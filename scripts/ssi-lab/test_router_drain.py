"""重放两端关闭屏障证据，拒绝仅凭退出码、单端确认或成功摘要通过。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

root = Path(__file__).resolve().parents[2]
directory = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker, boot, clock, stress, failure = [load(name) for name in
    ('check-router-drain', 'check-ssh-boot', 'check-clock', 'check-stress', 'check-failure-propagation')]


class RouterDrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-router-drain-20261106.json').read_text())
        cls.pair = next(row for row in cls.data['runs'] if row['mode'] == 'pair')
        cls.early = next(row for row in cls.data['runs'] if row['mode'] == 'early')

    def test_real_runs_keep_operations_router_and_kernel_shutdown_separate(self):
        modes = [row['mode'] for row in self.data['runs']]
        self.assertEqual(modes, ['control', 'pair', 'pair', 'invalid', 'early'])
        for row in self.data['runs']:
            self.assertTrue(row['operations_passed'])
            self.assertFalse(row['full_ssi_accepted'])
            boot.validate(row['serial_log'])
            stress.validate(row['stress_log'])
            trials = ['CLOCK_START' + part for part in row['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            self.assertTrue(row['result']['sftp_matches'])
            if row['mode'] == 'control':
                self.assertEqual(row['result']['qemu_ssh_exits'], [0])
                self.assertNotIn('SSI_DRAIN_', row['qemu_stderr'][0])
                boot.check_errors(row['host_logs'][0])
            else:
                self.assertEqual(checker.inspect(row), row['analysis'])
                self.assertFalse(row['analysis']['kernel_shutdown_accepted'])
                self.assertFalse(row['analysis']['persistent_io_accepted'])
                self.assertTrue(any(row['validation']['hosts']))

    def test_source_provenance_and_runtime_match(self):
        for path, digest in self.data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        build = self.data['build']
        self.assertTrue(build['patch_replay_matches_compiled_source'])
        self.assertEqual(build['patch_sha256'], self.data['source_sha256']['scripts/ssi-lab/experiments/qemu-router-drain.patch'])
        self.assertNotIn('warning:', self.data['build_log'])
        self.assertNotIn('error:', self.data['build_log'])
        self.assertFalse(self.data['rejected_build']['executed'])
        self.assertIn('undefined reference', self.data['rejected_build']['log'])
        for row in self.data['runs']:
            for runtime in row['runtime_hashes']:
                self.assertEqual(runtime['kernel'], self.data['kernel_sha256'])
                self.assertEqual(runtime['qemu'], build['binary'])

    def test_baseline_zero_exits_are_not_drain_evidence(self):
        old = json.loads((root / self.data['baseline_evidence']).read_text())
        row = deepcopy(next(row for row in old['workspace_runs'] if row['mode'] == 'pair' and row['qemu_variant'] == 'failure-exit'))
        self.assertEqual(row['result']['qemu_ssh_exits'], [0, 0])
        row['qemu_stderr'] = [failure.expand_log(item) for item in row['qemu_stderr']]
        with self.assertRaises(ValueError):
            checker.inspect(row)

    def test_peer_nonce_and_cpu_stop_must_match_raw_records(self):
        for old, new in [('stopped=4', 'stopped=3'), ('peer=1', 'peer=0'), ('node=0', 'node=1')]:
            bad = deepcopy(self.pair)
            bad['qemu_stderr'][0] = bad['qemu_stderr'][0].replace(old, new)
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.pair)
        bad['qemu_stderr'][0] = re.sub(r'(SSI_DRAIN_ACK_SENT.*nonce=)\d+', r'\g<1>17', bad['qemu_stderr'][0])
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_missing_duplicate_or_out_of_order_ack_cannot_pass(self):
        for kind in ('missing', 'duplicate', 'early'):
            bad = deepcopy(self.pair)
            rows = bad['qemu_stderr'][0].splitlines()
            ack = next(row for row in rows if row.startswith('SSI_DRAIN_ACK_SENT'))
            if kind == 'missing':
                rows.remove(ack)
            elif kind == 'duplicate':
                rows.append(ack)
            else:
                rows.remove(ack)
                rows.insert(0, ack)
            bad['qemu_stderr'][0] = '\n'.join(rows)
            with self.assertRaises(ValueError):
                checker.inspect(bad)

    def test_late_traffic_crash_and_management_failure_stay_visible(self):
        for text in ('SSI router generated traffic after local drain', 'SSI router received traffic after drain marker',
                     'SSI router EOF before acknowledged drain', 'SSI drain acknowledgement send failed',
                     'SSI shutdown notification failed', 'Segmentation fault', 'terminating on signal 15'):
            bad = deepcopy(self.pair)
            bad['qemu_stderr'][0] += '\n' + text
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.pair)
        bad['result']['management_timeout'] = True
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_early_marker_must_wait_without_reply_and_then_reach_deadline(self):
        for key, value in [('early_state', {'bytes': 24}), ('elapsed_ns', 1000), ('frame_hex', '00' * 26)]:
            bad = deepcopy(self.early)
            injection = json.loads(bad['injection_log'])
            injection[key] = value
            bad['injection_log'] = json.dumps(injection)
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.early)
        bad['qemu_stderr'][0] += '\nSSI_DRAIN_ACK_SENT node=0 peer=1 nonce=41789\n'
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_restoration_and_remaining_storage_work_are_explicit(self):
        self.assertEqual(len(self.data['restoration']['nodes']), 2)
        for node in self.data['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        self.assertEqual(self.data['storage_check']['lima_status'], 'Stopped')
        for node in self.data['storage_check']['nodes']:
            self.assertFalse(node['ceph_installed'])
            self.assertFalse(node['docker_installed'])
        for gate in ('normal DSM shutdown', 'DSM in-flight drain', 'Ceph', 'Docker', 'PostgreSQL', 'Redis', 'failover'):
            self.assertIn(gate, self.data['not_accepted'])


if __name__ == '__main__':
    unittest.main()
