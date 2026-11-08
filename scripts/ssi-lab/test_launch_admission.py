"""复核双端实机证据，并拒绝把缺失跟踪、半许可或工作区失败写成通过。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'check-{name}.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


checker = module('launch-admission')
evidence = json.loads((HERE.parents[1] / 'docs/evidence/ssi-launch-admission-20261108.json').read_text())


def row():
    return copy.deepcopy(evidence['mixed_runs'][0])


def rehash(record, name='trace'):
    record[name + '_sha256'] = hashlib.sha256(record[name].encode()).hexdigest()


def files(name):
    return evidence['execution_runs'][name]['files']


class LaunchAdmissionTest(unittest.TestCase):
    def test_all_four_mixed_pairs_refuse_before_any_guest_execution(self):
        results = checker.check_matrix(evidence)
        self.assertEqual(len(results), 4)
        for result in results:
            self.assertTrue(result['both_refused_before_guest'])
            self.assertFalse(result['full_ssi_accepted'])
            self.assertEqual(result['nodes'], [
                {'qemu_exec_calls': 0, 'kvm_calls': 0, 'sealed_inputs': 3, 'processes': 3}] * 2)

    def test_duplicate_or_missing_matrix_entry_is_rejected(self):
        for count in (3, 4):
            data = copy.deepcopy(evidence)
            data['mixed_runs'] = [row()] * count
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, '矩阵'):
                checker.check_matrix(data)

    def test_missing_native_lifecycle_cannot_be_counted_as_zero_execution(self):
        for token in ('all', 'execve(', 'vfork(', '+++ exited with', 'exit_group(', 'memfd_create(',
                      'F_ADD_SEALS', 'F_GET_SEALS'):
            data = row()
            record = data['records'][0]
            record['trace'] = '' if token == 'all' else '\n'.join(
                line for line in record['trace'].splitlines() if token not in line) + '\n'
            rehash(record)
            with self.subTest(token=token), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_unfinished_call_must_have_a_matching_completion(self):
        data = row()
        record = data['records'][0]
        record['trace'] = '\n'.join(line for line in record['trace'].splitlines()
                                    if '<... vfork resumed>' not in line) + '\n'
        rehash(record)
        with self.assertRaises(ValueError):
            checker.check_mixed(data)

    def test_kvm_calls_are_rejected_regardless_of_reported_zero(self):
        for ioctl in ('KVM_RUN', 'KVM_CREATE_VM', '0xae80', '0xAE01', '0x4020ae46',
                      '_IOC(_IOC_NONE, 0xae, 0x80, 0)'):
            data = row()
            record = data['records'][0]
            lines = record['trace'].splitlines()
            prefix = re.match(r'(\d+\s+\d+\.\d+\s+)', lines[-2])[1]
            lines.insert(-2, prefix + f'ioctl(8, {ioctl}, 0) = 0')
            record['trace'] = '\n'.join(lines) + '\n'
            record['kvm_calls'] = 0
            rehash(record)
            with self.subTest(ioctl=ioctl), self.assertRaisesRegex(ValueError, '触达 KVM'):
                checker.check_mixed(data)

    def test_qemu_exec_or_changed_worker_is_rejected(self):
        for old, new in (('/usr/bin/ps', '/lab/qemu-system-x86_64'),
                         ('import ctypes', 'import socket')):
            data = row()
            record = data['records'][0]
            self.assertIn(old, record['trace'])
            record['trace'] = record['trace'].replace(old, new)
            rehash(record)
            with self.subTest(new=new), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_wrong_version_current_worker_or_admission_is_rejected(self):
        changes = [lambda d: d.update(versions=[4, 5]),
                   lambda d: d['report'].update(worker_sha256='0' * 64),
                   lambda d: d['report'].update(commit_sent=[True, False]),
                   lambda d: d['report'].update(admission_passed=True),
                   lambda d: d['report']['nodes'][0].update(started={'pid': 1}),
                   lambda d: d.update(cli_exit=0)]
        for change in changes:
            data = row()
            change(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_missing_or_disagreeing_independent_records_are_rejected(self):
        changes = [lambda r: r.update(control=''),
                   lambda r: r['remote'].update(qemu_started=True),
                   lambda r: r['remote']['events'][0]['data'].update(token='changed'),
                   lambda r: r.update(remaining=['qemu-system-x86']),
                   lambda r: r.update(host_log=''),
                   lambda r: r.update(host_log='kernel: ktcp_receive error, ret -104')]
        for change in changes:
            data = row()
            record = data['records'][0]
            change(record)
            for name in ('control', 'host_log'):
                rehash(record, name)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_log_digest_change_is_rejected(self):
        data = row()
        data['records'][0]['trace'] += '\n'
        with self.assertRaisesRegex(ValueError, '日志摘要'):
            checker.check_mixed(data)

    def test_same_version_proof_executes_on_both_hosts(self):
        run = files('proof-1')
        report = json.loads(run['report.json'])
        self.assertEqual(evidence['execution_runs']['proof-1']['cli_exit'], 0)
        self.assertTrue(report['admission_passed'])
        self.assertEqual(report['errors'], [])
        with tempfile.TemporaryDirectory() as temporary:
            serial = Path(temporary) / 'serial.log'
            serial.write_text(run['node0-stdout.log'])
            result = subprocess.run([sys.executable, str(HERE / 'check-proof.py'), str(serial)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        for node in range(2):
            self.assertEqual(report['nodes'][node]['finished']['qemu_exit'], 0)
            samples = re.findall(r'CPU (\d+)/KVM\s+(\d+):(\d+):(\d+)', run[f'node{node}-vcpu.log'])
            active = {int(cpu) for cpu, hours, minutes, seconds in samples
                      if int(hours) * 3600 + int(minutes) * 60 + int(seconds) > 0}
            self.assertEqual(active, {node * 2, node * 2 + 1})
            self.assertEqual(json.loads(run[f'node{node}-remaining.json']), [])
            with self.assertRaisesRegex(ValueError, 'ktcp_receive'):
                checker.boot.check_errors(run[f'node{node}-host.log'])

    def test_workspace_keeps_original_clock_gate_and_rtc_shutdown_failures(self):
        run = files('workspace-1')
        result = json.loads(run['workspace.json'])
        chunks = re.findall(r'CLOCK_START.*?CLOCK_PASS[^\n]*', run['clock.log'], re.S)
        self.assertEqual(len(chunks), 3)
        for chunk in chunks:
            module('clock').validate(chunk, max_timer_ns=250_000_000)
        module('stress').validate(run['stress.log'])
        self.assertEqual(result['cli_exit'], 0)
        self.assertEqual(result['errors'], [])
        for name in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
            self.assertEqual(result['phases'][name]['exit'], 0)
        self.assertEqual(result['phases']['poweroff']['exit'], 255)
        self.assertTrue(result['sftp_matches'])
        self.assertEqual(result['sftp_sha256'], 'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83')
        transfer = evidence['execution_runs']['workspace-1']['binary_manifest']['sftp-return.bin']
        self.assertEqual(transfer, {'sha256': result['sftp_sha256'], 'bytes': 1024 * 1024})
        with self.assertRaisesRegex(ValueError, 'RTC interrupts'):
            checker.boot.validate(run['node0-stdout.log'])
        for node in range(2):
            with self.assertRaisesRegex(ValueError, 'ktcp_receive'):
                checker.boot.check_errors(run[f'node{node}-host.log'])

    def test_real_active_guest_faults_stop_and_release_locks(self):
        for mode in ('lease', 'disconnect', 'helper-kill', 'lock'):
            run = files(f'fault-{mode}-1')
            fault = json.loads(run['fault.json'])
            self.assertTrue(fault['guest_ready_before_injection'])
            self.assertEqual(fault['errors'], [])
            self.assertEqual(fault['cli_exit'], -9 if mode == 'disconnect' else 2)
            self.assertGreater(fault['observed_ns'], fault['injected_ns'])
            for node in range(2):
                self.assertEqual(fault[f'node{node}_remaining'], [])
                self.assertEqual(fault[f'node{node}_lock'], 'lock-free')
                if mode == 'helper-kill' and node == 0:
                    self.assertNotIn('node0-remote.json', run)
                    continue
                remote = json.loads(run[f'node{node}-remote.json'])
                self.assertTrue(remote['qemu_started'])
                self.assertEqual(remote['forced_cleanup'], ['SIGTERM'])
                self.assertTrue(remote['errors'])
                if mode in ('lease', 'disconnect'):
                    reason = 'controller lease expired' if mode == 'lease' else 'controller disconnected'
                    self.assertEqual(remote['errors'], [reason])
            if mode == 'disconnect':
                self.assertNotIn('report.json', run)

    def test_second_cli_is_refused_before_preparation(self):
        run = files('fault-lock-1')
        fault = json.loads(run['fault.json'])
        report = json.loads(files('fault-lock-1-contender')['report.json'])
        self.assertEqual(report, fault['contender_report'])
        self.assertEqual(fault['contender_exit'], 2)
        self.assertFalse(report['admission_passed'])
        self.assertEqual(report['commit_sent'], [False, False])
        for outcome in report['nodes']:
            self.assertIsNone(outcome['prepared'])
            self.assertIsNone(outcome['started'])
            self.assertFalse(outcome['finished']['qemu_started'])
            self.assertIn('Resource temporarily unavailable', outcome['finished']['errors'][0])

    def test_replacing_the_source_does_not_replace_the_running_executable(self):
        run = files('direct-replace-1')
        probe = json.loads(run['probe.json'])
        self.assertEqual(probe['errors'], [])
        self.assertEqual(probe['commit_sent'], [True, True])
        self.assertEqual(probe['ssh_exits'], [0, 0])
        self.assertEqual(probe['executed_sha256'], [checker.VERSIONS[5]] * 2)
        for node, replacement in enumerate(probe['replacements']):
            self.assertEqual(replacement['before'], checker.VERSIONS[5])
            self.assertEqual(replacement['after'], checker.VERSIONS[4])
            remote = json.loads(run[f'node{node}-remote.json'])
            self.assertTrue(remote['qemu_started'])
            self.assertEqual(remote['qemu_exit'], 0)
            self.assertEqual(remote['errors'], [])
            self.assertEqual(remote['forced_cleanup'], [])
            self.assertEqual(probe[f'node{node}_remaining'], [])
            self.assertEqual(probe[f'node{node}_lock'], 'lock-free')
        self.assertEqual(len(probe['replacements']), 2)
        self.assertIn('direct worker protocol', evidence['execution_runs']['direct-replace-1']['entrypoint'])
        with tempfile.TemporaryDirectory() as temporary:
            serial = Path(temporary) / 'serial.log'
            serial.write_text(run['node0-stdout.log'])
            result = subprocess.run([sys.executable, str(HERE / 'check-proof.py'), str(serial)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_half_commit_keeps_one_sided_execution_visible(self):
        run = files('direct-half-1')
        probe = json.loads(run['probe.json'])
        self.assertEqual(probe['errors'], [])
        self.assertEqual(probe['commit_sent'], [True, False])
        self.assertEqual(probe['ssh_exits'], [1, 1])
        for node in range(2):
            remote = json.loads(run[f'node{node}-remote.json'])
            self.assertEqual(remote['qemu_started'], node == 0)
            self.assertEqual(remote['qemu_exit'], -15 if node == 0 else None)
            self.assertEqual(remote['forced_cleanup'], ['SIGTERM'] if node == 0 else [])
            self.assertTrue(remote['errors'])
            self.assertEqual(probe[f'node{node}_remaining'], [])
            self.assertEqual(probe[f'node{node}_lock'], 'lock-free')
        self.assertIn('direct worker protocol', evidence['execution_runs']['direct-half-1']['entrypoint'])

    def test_published_artifact_hashes_and_restoration(self):
        for run in evidence['execution_runs'].values():
            for name, raw in run['files'].items():
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), run['manifest'][name]['published_sha256'])
        self.assertEqual(len(evidence['restoration']['nodes']), 2)
        for node in evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['old_boot_files_unchanged'])
            self.assertTrue(node['firewall_matches_original'])
            self.assertEqual(node['grub_environment'], '')
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            number = node['node']
            snapshots = evidence['restoration_manifest']
            before = snapshots[f'node{number}-firewall-stock.json']['published']
            after = snapshots[f'node{number}-firewall-restored.json']['published']
            self.assertEqual(json.loads(before), json.loads(after))
        raw = json.dumps(evidence)
        self.assertNotRegex(raw, r'/Users/|/home/ubuntu|192\.168\.\d+\.\d+|sshpool-ssi-0[12]')
        self.assertFalse(evidence['full_ssi_accepted'])
        self.assertFalse(evidence['ceph_deployed'])


if __name__ == '__main__':
    unittest.main()
