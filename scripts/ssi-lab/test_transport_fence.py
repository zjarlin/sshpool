"""重放两台 VM 的真实封闭实验，拒绝缺失证据和伪造成功。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('fence', HERE / 'check-transport-fence.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TransportFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-transport-fence-20261108.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes']}

    def reject(self, mode, mutate):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaises(ValueError):
            checker.inspect(record)

    def test_all_seven_cases_on_both_nodes(self):
        rows = self.evidence['probes']
        self.assertEqual(len(rows), 14)
        self.assertEqual({(row['run']['node'], row['record']['mode']) for row in rows},
                         {(node, mode) for node in (0, 1) for mode in checker.MODES})
        for row in rows:
            with self.subTest(node=row['run']['node'], mode=row['record']['mode']):
                self.assertEqual(checker.inspect(row['record']), row['analysis'])
                self.assertEqual(row['run']['exit'], 0)
                self.assertEqual(row['run']['capture_exit'], 0)
                self.assertEqual(row['firewall']['before'], row['firewall']['after'])
                self.assertTrue(row['firewall']['restored_exactly'])
                self.assertNotRegex(row['host_log'], r'WARNING:|BUG:|Oops:|Kernel panic|hung task')

    def test_runtime_and_source_provenance(self):
        for name, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        for row in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(row['text'].encode()).hexdigest(), row['sha256'])
        build = self.evidence['build']
        self.assertEqual(build['patch_sha256'], self.evidence['source_sha256'][
            'scripts/ssi-lab/experiments/kernel-dsm-transport-fence.patch'])
        self.assertTrue(build['patch_replay_matches_compiled_source'])
        self.assertTrue(build['config_only_localversion_changed'])
        self.assertNotRegex(self.evidence['build_log'], r'warning:|error:')
        for row in self.evidence['probes']:
            hashes = row['runtime_hashes']
            raw = (json.dumps(row['record'], indent=2) + '\n').encode()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['record_sha256'])
            self.assertEqual(hashes['vmlinuz-' + row['record']['kernel']], build['kernel'])
            self.assertEqual(hashes['probe-transport-fence.py'], row['record']['probe_sha256'])
            for name, digest in self.evidence['probe_sources'].items():
                self.assertEqual(hashes[name], digest)

    def test_both_race_orderings_were_observed(self):
        outcomes = [(row['analysis']['admitted_requests'], row['analysis']['denied_requests'])
                    for row in self.evidence['probes'] if row['record']['mode'] == 'race']
        self.assertEqual(set(outcomes), {(1, 0), (0, 1)})

    def test_lost_or_unpaired_native_trace_is_rejected(self):
        self.reject('cached', lambda r: r['trace_stats'].update(cpu0=r['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1', 1)))
        self.reject('cached', lambda r: r.update(trace=r['trace'].replace('tf_requested:', 'tf_missing:', 1)))
        self.reject('cached', lambda r: r.update(kprobe_profile=r['kprobe_profile'].replace('tf_return', 'tf_missing')))
        self.reject('cached', lambda r: r.update(trace=re.sub(r'(python3-)\d+( +\[\d+\].*tf_return:)', r'\g<1>999999\2', r['trace'], count=1)))

    def test_abi_and_native_calls_must_agree(self):
        self.reject('validation', lambda r: r['calls'][0].update(errno=0))
        self.reject('validation', lambda r: r['calls'][0].update(tid=999999))
        self.reject('validation', lambda r: r['calls'][0].update(input_hex=bytes(24).hex()))
        self.reject('validation', lambda r: r['statuses'][-1].update(generation=1))

    def test_cached_response_cannot_be_reported_consumed(self):
        def mutate(record):
            for row in record['statuses']:
                if row['name'] == 'cached':
                    row['cached'] = 0
                    row['hex'] = struct.pack('=IIIIiIQ', 2, 2, 0, 2, 0, 0, 0).hex()
            for row in record['calls']:
                if row['name'] == 'status_cached':
                    row['output_hex'] = struct.pack('=IIIIiIQ', 2, 2, 0, 2, 0, 0, 0).hex()
        self.reject('cached', mutate)
        self.reject('cached', lambda r: r.update(waiter_alive_while_cached=False))
        self.reject('cached', lambda r: r.update(partial_reader_pid=r['partial_reader_pid'] + 1))

    def test_waiter_cannot_return_before_response_release(self):
        def mutate(record):
            waiter = next(row for row in record['calls'] if row['name'] == 'waiter')
            lines = record['trace'].splitlines()
            target = next(i for i, line in enumerate(lines) if 'tracing_mark_write: release_responses' in line)
            source = next(i for i, line in enumerate(lines) if f'-{waiter["tid"]} ' in line and 'tf_return:' in line)
            timestamps = [re.search(r' (\d+\.\d+): ', line)[1] for line in lines if not line.startswith('#') and line.strip()]
            line = lines.pop(source)
            lines.insert(target, line)
            values = iter(timestamps)
            for i, line in enumerate(lines):
                if not line.startswith('#') and line.strip():
                    lines[i] = re.sub(r' \d+\.\d+: ', ' ' + next(values) + ': ', line, count=1)
            record['trace'] = '\n'.join(lines) + '\n'
        self.reject('reverse', mutate)
        self.reject('reverse', lambda r: r.update(waiter_alive_while_pending=False))

    def test_timeout_must_not_fence_or_hide_a_stuck_waiter(self):
        def mutate(record):
            row = next(row for row in record['calls'] if row['name'] == 'timeout')
            row['end_ns'] = row['start_ns'] + 1
        self.reject('timeout', mutate)
        def fenced(record):
            row = next(row for row in record['statuses'] if row['name'] == 'after_timeout')
            row.update(state=1, generation=checker.GENERATION)
            row['hex'] = struct.pack('=IIIIiIQ', 2, 2, 0, 2, 0, 1, checker.GENERATION).hex()
            next(call for call in record['calls'] if call['name'] == 'status_after_timeout')['output_hex'] = row['hex']
        self.reject('timeout', fenced)

    def test_known_fault_cannot_be_replaced_by_zero_count_success(self):
        self.reject('fault', lambda r: next(call for call in r['calls'] if call['name'] == 'waiter').update(errno=0))
        self.reject('fault', lambda r: r.update(trace=re.sub(r'(tf_failure: [^\n]*code=)-71', r'\g<1>-104', r['trace'], count=1)))
        self.reject('fault', lambda r: r.update(tasks_before_cleanup={'123': {}}))

    def test_late_request_requires_native_rejection(self):
        self.reject('late', lambda r: r.update(trace=re.sub(r'(tf_requested: [^\n]*code=)-108', r'\g<1>0', r['trace'], count=1)))
        self.reject('late', lambda r: r.update(requests=[]))
        self.reject('late', lambda r: next(call for call in r['calls'] if call['name'] == 'failed_status').update(errno=0))

    def test_raw_page_frames_and_transaction_identity_are_checked(self):
        self.reject('reverse', lambda r: r['responses'][-1].update(hex='00'))
        self.reject('reverse', lambda r: r['requests'].__setitem__(0, '00'))
        self.reject('cached', lambda r: r['injected'].__setitem__(0, '00'))
        self.reject('cached', lambda r: r.update(cached_txid=r['held_txid']))
        self.reject('reverse', lambda r: r['outgoing_requests'].__setitem__(1, r['outgoing_requests'][0]))

    def test_status_times_and_completion_cleanup_are_checked(self):
        self.reject('cached', lambda r: r['statuses'][-1].update(time_ns=1))
        self.reject('cached', lambda r: r.update(remaining_tasks={'123': {}}))
        self.reject('cached', lambda r: r.update(trace_cleanup_complete=False))
        self.reject('cached', lambda r: r.update(full_vm_shutdown_accepted=True))

    def test_probe_refuses_other_kernels_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(HERE / 'probe-transport-fence.py'),
                                     '--require-kernel', 'kernel-must-not-match', '--mode', 'validation',
                                     '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_nodes_restored_and_global_shutdown_still_unverified(self):
        self.assertFalse(self.evidence['whole_vm_shutdown_verified'])
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)
        for row in self.evidence['restoration']['nodes']:
            self.assertEqual(row['kernel'], '6.8.0-147-generic')
            self.assertTrue(row['identity_matches'])
            self.assertTrue(row['old_boot_files_unchanged'])
            self.assertTrue(row['firewall_matches_original'])
            self.assertEqual(row['remaining_processes'], [])
            self.assertEqual(row['grub_environment'], '')
            self.assertEqual(row['lib_target'], 'usr/lib')

    def test_full_guests_do_not_certify_unintegrated_shutdown(self):
        boot = checker.load('check-ssh-boot')
        clock = checker.load('check-clock')
        stress = checker.load('check-stress')
        router = checker.load('check-router-drain')
        self.assertEqual({row['mode'] for row in self.evidence['workspace_runs']}, {'control', 'pair'})
        for row in self.evidence['workspace_runs']:
            self.assertFalse(row['full_ssi_accepted'])
            self.assertFalse(row['fence_integrated_with_qemu'])
            self.assertTrue(row['operations_passed'])
            self.assertEqual(row['firewall']['before'], row['firewall']['after'])
            for name in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(row['result']['phases'][name]['exit'], 0)
            self.assertEqual(row['sftp']['bytes'], 1048576)
            self.assertEqual(row['sftp']['input_sha256'], row['sftp']['output_sha256'])
            files = row['files']
            stress.validate(files['stress.log'])
            trials = re.findall(r'CLOCK_START[^\n]*\n.*?CLOCK_PASS[^\n]*', files['clock.log'], re.S)
            self.assertEqual(len(trials), 3)
            failures = []
            for trial in trials:
                try:
                    clock.validate(trial, max_timer_ns=250000000)
                except ValueError as error:
                    failures.append(str(error))
            self.assertEqual(failures, row['clock_errors'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['vmlinuz-7.1.0-rc3-sshpool-gvm-pf25'], self.evidence['build']['kernel'])
                self.assertEqual(hashes['qemu-system-x86_64-router-startup-2'], row['result']['qemu_sha256'])
            if row['mode'] == 'control':
                self.assertEqual(row['result']['qemu_ssh_exits'], [0])
                continue
            replay = router.inspect({'mode': 'pair', 'result': row['result'],
                                     'qemu_stderr': [files[f'node{n}-qemu-stderr.log'] for n in (0, 1)],
                                     'host_logs': [files[f'node{n}-host.log'] for n in (0, 1)],
                                     'serial_log': files['node0-qemu.log']})
            self.assertEqual(replay, row['router_analysis'])
            self.assertFalse(replay['kernel_shutdown_accepted'])
            combined = files['node0-host.log'] + files['node1-host.log']
            self.assertRegex(combined, r'kvm-dsm:.*failed with -104')
            with self.assertRaises(ValueError):
                boot.check_errors(combined)


if __name__ == '__main__':
    unittest.main()
