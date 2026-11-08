"""从真实跟踪复核启动拒绝，防止把旧节点运行或强制清理改写为通过。"""
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

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('startup', here / 'check-router-startup.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
evidence = json.loads((here.parents[1] / 'docs/evidence/ssi-router-startup-20261108.json').read_text())


def row(versions=(5, 4)):
    return copy.deepcopy(next(value for value in evidence['runs'] if value['run']['versions'] == list(versions)))


def rehash(record, name='ioctl'):
    record[name + '_sha256'] = hashlib.sha256(record[name].encode()).hexdigest()


class RouterStartupTest(unittest.TestCase):
    def test_capture_and_patch_match_recorded_inputs(self):
        self.assertEqual(hashlib.sha256((here / 'probe-router-startup.py').read_bytes()).hexdigest(), checker.CAPTURE)
        replay = evidence['patch_replay']
        self.assertTrue(replay['zero_fuzz'])
        self.assertTrue(replay['byte_identical'])
        self.assertEqual(hashlib.sha256((here / 'experiments/qemu-router-startup.patch').read_bytes()).hexdigest(),
                         replay['patch_sha256'])

    def test_new_master_refuses_both_legacy_versions_before_guest(self):
        for versions in ((5, 3), (5, 4)):
            with self.subTest(versions=versions):
                result = checker.require_both_before_guest(row(versions))
                self.assertEqual(result['kvm_run_calls'], [0, 0])
                self.assertFalse(result['full_ssi_accepted'])

    def test_old_master_execution_keeps_original_feature_partial(self):
        result = checker.check_mixed(row((3, 5)))
        self.assertGreater(result['kvm_run_calls'][0], 0)
        self.assertFalse(result['both_refused_before_guest'])
        with self.assertRaisesRegex(ValueError, '旧节点已经执行'):
            checker.require_both_before_guest(row((3, 5)))
        self.assertFalse(evidence['mixed_versions_before_guest_verified'])

    def test_real_old_master_timeout_is_rejected_even_with_exit_one(self):
        data = row((4, 5))
        old = data['records'][0]
        self.assertEqual(old['exit'], 1)
        self.assertEqual(old['forced_cleanup'], ['SIGTERM'])
        self.assertNotIn('exit_observed_ns', old)
        self.assertGreater(old['kvm_run_calls'], 0)
        with self.assertRaisesRegex(ValueError, '采集没有完整结束'):
            checker.check_mixed(data)

    def test_all_four_candidate_nodes_have_complete_native_failure_exits(self):
        self.assertEqual({tuple(value['run']['versions']) for value in evidence['runs']},
                         {(5, 3), (3, 5), (5, 4), (4, 5)})
        for data in evidence['runs']:
            node = data['run']['versions'].index(5)
            record = data['records'][node]
            checker.arguments(record)
            self.assertEqual(checker.native_trace(record), 0)
            self.assertEqual(record['forced_cleanup'], [])
            self.assertEqual(record['errors'], [])
            self.assertIn('SSI router startup protocol error:', record['stderr'])
            self.assertNotIn('SSI_ROUTER_READY', record['stderr'])

    def test_first_candidate_failure_is_preserved(self):
        results = [checker.check_mixed(data, checker.PREVIOUS) for data in evidence['previous_runs']]
        self.assertTrue(any(not result['both_refused_before_guest'] for result in results))

    def test_missing_native_trace_or_vm_creation_cannot_mean_zero_runs(self):
        for change in ('empty', 'vm', 'api', 'exec'):
            data = row()
            record = data['records'][0]
            if change == 'empty':
                record['ioctl'] = ''
            else:
                token = {'vm': 'KVM_CREATE_VM', 'api': 'KVM_GET_API_VERSION', 'exec': 'execve('}[change]
                record['ioctl'] = '\n'.join(line for line in record['ioctl'].splitlines() if token not in line) + '\n'
            rehash(record)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_missing_thread_creation_or_exit_cannot_be_complete(self):
        for token in ('clone3(', '+++ exited with'):
            data = row()
            record = data['records'][0]
            lines = record['ioctl'].splitlines()
            index = next(i for i, line in enumerate(lines) if token in line)
            del lines[index]
            record['ioctl'] = '\n'.join(lines) + '\n'
            rehash(record)
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, '线程创建或完整退出'):
                checker.check_mixed(data)

    def test_reported_zero_cannot_hide_native_kvm_run(self):
        data = row((3, 5))
        data['records'][0]['kvm_run_calls'] = 0
        with self.assertRaisesRegex(ValueError, '执行计数'):
            checker.check_mixed(data)

    def test_native_run_counts_unfinished_entry_but_not_resumed_line(self):
        record = row((3, 5))['records'][0]
        expected = record['kvm_run_calls']
        lines = record['ioctl'].splitlines()
        index = next(i for i, line in enumerate(lines) if 'KVM_RUN' in line and 'unfinished' not in line)
        line = lines[index]
        match = re.match(r'(\d+\s+\d+\.\d+\s+)ioctl\((\d+), KVM_RUN, (.*)', line)
        self.assertIsNotNone(match)
        lines[index:index + 1] = [match[1] + 'ioctl(' + match[2] + ', KVM_RUN <unfinished ...>',
                                 match[1] + '<... ioctl resumed>, ' + match[3]]
        record['ioctl'] = '\n'.join(lines) + '\n'
        self.assertEqual(checker.native_trace(record), expected)

    def test_raw_ioctl_number_cannot_hide_execution(self):
        for spelling in ('0xae80', '_IOC(_IOC_NONE, 0xae, 0x80, 0)'):
            record = row((3, 5))['records'][0]
            record['ioctl'] = record['ioctl'].replace('KVM_RUN', spelling)
            with self.subTest(spelling=spelling):
                self.assertEqual(checker.native_trace(record), record['kvm_run_calls'])

    def test_paused_launch_and_fake_exit_are_rejected(self):
        for field, value in [('qemu_arguments', row()['records'][0]['qemu_arguments'] + ['-S']),
                             ('exit', 0), ('forced_cleanup', ['SIGKILL']),
                             ('exit_observed_ns', 1)]:
            data = row()
            data['records'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.check_mixed(data)

    def test_changed_log_digest_is_rejected(self):
        data = row()
        data['records'][0]['stderr'] += 'changed'
        with self.assertRaisesRegex(ValueError, '日志摘要'):
            checker.check_mixed(data)

    def test_wrong_kernel_guard_precedes_paths_and_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'not-created'
            command = [sys.executable, str(here / 'probe-router-startup.py'), '--require-kernel', 'not-pf24',
                       '--qemu', '/nonexistent', '--require-sha256', 'invalid', '--firmware', '/nonexistent',
                       '--guest-kernel', '/nonexistent', '--guest-kernel-sha256', 'invalid',
                       '--initramfs', '/nonexistent', '--initramfs-sha256', 'invalid', '--node', '0',
                       '--peers', '192.0.2.10', '192.0.2.11', '--directory', str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('dedicated PF24 kernel required', result.stderr)
            self.assertFalse(output.exists())

    def test_workspace_gates_are_recomputed_and_first_failure_stays_visible(self):
        modules = {}
        for name in ('clock', 'stress', 'router-drain'):
            spec = importlib.util.spec_from_file_location(name, here / f'check-{name}.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules[name] = module
        rows = evidence['workspace_runs']
        self.assertEqual([value['label'] for value in rows],
                         ['rs-workspace-control-2', 'rs-workspace-pair-2',
                          'rs-workspace-baseline-3', 'rs-workspace-pair-3'])
        for data in rows:
            result = data['result']
            count = 1 if data['mode'] == 'control' else 2
            self.assertEqual(result['qemu_ssh_exits'], [0] * count)
            self.assertFalse(result['samples_errors'])
            self.assertFalse(any(result.get(key) for key in
                                 ('harness_error', 'management_timeout', 'host_log_timeout')))
            chunks = re.findall(r'CLOCK_START.*?CLOCK_PASS[^\n]*', data['clock_log'], re.S)
            self.assertEqual(len(chunks), 3)
            for chunk in chunks:
                modules['clock'].validate(chunk, max_timer_ns=250_000_000)
            modules['stress'].validate(data['stress_log'])
            self.assertFalse(data['full_ssi_accepted'])
            if data['label'] == 'rs-workspace-pair-2':
                self.assertFalse(result['sftp_matches'])
                self.assertEqual(result['phases']['sftp']['exit'], 255)
                self.assertIn('banner exchange', data['sftp_log'])
                with self.assertRaisesRegex(ValueError, 'RTC interrupts'):
                    checker.boot.validate(data['serial_log'])
            else:
                checker.boot.validate(data['serial_log'])
                self.assertTrue(result['sftp_matches'])
                self.assertEqual(result['sftp_sha256'], 'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83')
                for name in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                    self.assertEqual(result['phases'][name]['exit'], 0)
            if count == 2:
                self.assertEqual(modules['router-drain'].inspect(data)['outcome'], 'router_drained')
                for log in data['host_logs']:
                    with self.assertRaisesRegex(ValueError, 'ktcp_receive'):
                        checker.boot.check_errors(log)

    def test_candidate_releases_startup_only_after_both_handshakes(self):
        rows = [data for data in evidence['workspace_runs']
                if data['mode'] == 'pair' and data['result']['qemu_sha256'] == checker.CANDIDATE]
        self.assertEqual(len(rows), 2)
        for data in rows:
            for node, log in enumerate(data['qemu_stderr']):
                ready = f'SSI_ROUTER_READY node={node} peers=1 version=5'
                self.assertEqual(log.count(ready), 1)
                for kind in ('HELLO_RECEIVED', 'HELLO_ACK'):
                    marker = f'SSI_ROUTER_{kind} node={node} peer={1 - node} version=5'
                    self.assertEqual(log.count(marker), 1)
                    self.assertLess(log.index(marker), log.index(ready))
                self.assertLess(log.index(ready), log.index('SSI_CLOCK_COLD_START'))
                samples = re.findall(r'CPU (\d+)/KVM\s+(\d+):(\d+):(\d+)', data['vcpu_samples'][node])
                executed = {int(cpu) for cpu, hours, minutes, seconds in samples
                            if int(hours) * 3600 + int(minutes) * 60 + int(seconds) > 0}
                self.assertEqual(executed, {node * 2, node * 2 + 1})

    def test_lab_restoration_does_not_claim_full_ssi(self):
        self.assertFalse(evidence['full_ssi_accepted'])
        self.assertFalse(evidence['ceph_deployed'])
        self.assertFalse(evidence['cross_physical_verified'])
        nodes = evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertEqual(node['remaining_processes'], [])
            self.assertEqual(node['grub_environment'], '')
            for name in ('old_boot_files_unchanged', 'firewall_matches_original', 'identity_matches'):
                self.assertTrue(node[name])


if __name__ == '__main__':
    unittest.main()
