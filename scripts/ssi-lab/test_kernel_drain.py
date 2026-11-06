"""从保存的真实内核事件重算屏障顺序，并故意篡改关键证据验证拒绝路径。"""
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


checker, boot, clock, stress, router = [load(name) for name in
    ('check-kernel-drain', 'check-ssh-boot', 'check-clock', 'check-stress', 'check-router-drain')]


class KernelDrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-kernel-drain-20261106.json').read_text())
        cls.active = next(row for row in cls.data['probes'] if row['record']['mode'] == 'active')
        cls.lock = next(row for row in cls.data['probes'] if row['record']['mode'] == 'lock')

    def inspect(self, row):
        return checker.inspect(row['record'], row['host_log'])

    def test_real_probes_keep_stream_and_vm_shutdown_separate(self):
        self.assertEqual(len(self.data['probes']), 20)
        self.assertEqual({row['record']['mode'] for row in self.data['probes']},
                         {'idle', 'active', 'lock', 'timeout', 'fault', 'version', 'generation', 'duplicate', 'late', 'partial', 'prefix'})
        for row in self.data['probes']:
            self.assertEqual(self.inspect(row), row['analysis'])
            self.assertFalse(row['analysis']['full_vm_shutdown_accepted'])
            self.assertTrue(row['firewall_restored_exactly'])
            self.assertEqual(row['run']['exit'], 0)

    def test_capture_sources_runtime_and_patch_replay(self):
        for path, digest in self.data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        self.assertTrue(self.data['build']['patch_replay_matches_compiled_source'])
        self.assertTrue(self.data['build']['config_only_localversion_changed'])
        self.assertNotIn('warning:', self.data['build_log'])
        self.assertNotIn('error:', self.data['build_log'])
        self.assertEqual(self.data['build']['patch_sha256'], self.data['source_sha256']['scripts/ssi-lab/experiments/kernel-dsm-inbound-drain.patch'])
        fix = self.data['fault_order_build']
        self.assertTrue(fix['patch_replay_matches_compiled_source'])
        self.assertTrue(fix['config_only_localversion_changed'])
        self.assertNotIn('warning:', self.data['fault_order_build_log'])
        self.assertNotIn('error:', self.data['fault_order_build_log'])
        self.assertEqual(fix['patch_sha256'], self.data['source_sha256']['scripts/ssi-lab/experiments/kernel-dsm-drain-fault-order.patch'])
        for captured in self.data['capture_source_versions']:
            self.assertEqual(hashlib.sha256(captured['text'].encode()).hexdigest(), captured['sha256'])
        self.assertEqual({row['sha256'] for row in self.data['capture_source_versions']},
                         {row['probe-kernel-drain.py'] for row in self.data['capture_versions']})
        versions = self.data['capture_versions']
        for row in self.data['probes']:
            build = self.data['fault_order_build'] if row['record']['kernel'].endswith('pf19') else self.data['build']
            self.assertEqual(row['runtime_hashes']['vmlinuz-' + row['record']['kernel']], build['kernel'])
            actual = {name: value for name, value in row['runtime_hashes'].items() if not name.startswith('vmlinuz-')}
            self.assertIn(actual, versions)

    def test_changed_page_or_ack_bytes_fail(self):
        for index, offset in [(0, 70), (-1, 15), (-1, 18), (-1, 22), (-1, 30), (-1, 38)]:
            bad = deepcopy(self.active)
            row = bad['record']['responses'][index]
            raw = bytearray.fromhex(row['hex'])
            raw[offset] ^= 1
            row['hex'] = raw.hex()
            with self.assertRaises(ValueError):
                self.inspect(bad)

    def test_drain_generation_and_injected_frame_must_match(self):
        bad = deepcopy(self.active)
        bad['record']['generation'] += 1
        with self.assertRaises(ValueError):
            self.inspect(bad)
        bad = deepcopy(self.active)
        bad['record']['requests'][-1] = bad['record']['requests'][0]
        with self.assertRaises(ValueError):
            self.inspect(bad)

    def test_counter_and_release_evidence_cannot_be_replaced_by_summary(self):
        for old, new in [('active=7', 'active=0'), ('DSM_DRAIN_ACK', 'DSM_DRAIN_MISSING')]:
            bad = deepcopy(self.active)
            bad['host_log'] = bad['host_log'].replace(old, new)
            with self.assertRaises(ValueError):
                self.inspect(bad)
        bad = deepcopy(self.active)
        # 系统其他 SRCU 的释放不能替代 DSM 处理器自身的释放。
        bad['record']['trace'] = re.sub(r'(kd_srcu_done: \()ivy_kvm_dsm_handle_req\+', r'\1other_subsystem+', bad['record']['trace'])
        with self.assertRaisesRegex(ValueError, 'SRCU'):
            self.inspect(bad)

    def test_lock_wait_must_span_remote_response(self):
        bad = deepcopy(self.lock)
        bad['record']['write_result']['errno'] = 5
        with self.assertRaises(ValueError):
            self.inspect(bad)
        bad = deepcopy(self.lock)
        bad['record']['silence']['readable'] = True
        with self.assertRaises(ValueError):
            self.inspect(bad)

    def test_loss_truncation_and_missing_probe_are_rejected(self):
        for kind in ('loss', 'truncated', 'profile'):
            bad = deepcopy(self.active)
            data = bad['record']
            if kind == 'loss':
                key = next(iter(data['trace_stats']))
                data['trace_stats'][key] = data['trace_stats'][key].replace('overrun: 0', 'overrun: 1', 1)
            elif kind == 'truncated':
                data['trace'] = '\n'.join(line for line in data['trace'].splitlines() if 'kd_unlocked:' not in line)
            else:
                data['kprobe_profile'] = '\n'.join(line for line in data['kprobe_profile'].splitlines() if 'kd_unlocked' not in line)
            with self.assertRaises(ValueError):
                self.inspect(bad)

    def test_first_error_and_pre_cleanup_failure_are_required(self):
        for mode in ('timeout', 'fault', 'version', 'generation', 'late', 'duplicate', 'prefix'):
            row = next(row for row in self.data['probes'] if row['record']['mode'] == mode)
            bad = deepcopy(row)
            bad['record']['management_errno'] = 0
            with self.assertRaises(ValueError):
                self.inspect(bad)
            bad = deepcopy(row)
            bad['record']['tasks_before_cleanup'] = {'1': 'still running'}
            with self.assertRaises(ValueError):
                self.inspect(bad)
        bad = deepcopy(next(row for row in self.data['probes'] if row['record']['mode'] == 'timeout'))
        bad['record']['trace'] = bad['record']['trace'].replace('code=-110', 'code=-71')
        with self.assertRaises(ValueError):
            self.inspect(bad)

    def test_fault_prefix_is_latched_before_buffered_marker(self):
        row = next(row for row in self.data['probes'] if row['record']['mode'] == 'prefix')
        bad = deepcopy(row)
        lines = bad['host_log'].splitlines()
        first = next(i for i, line in enumerate(lines) if 'failed with -71;' in line)
        begin = next(i for i, line in enumerate(lines) if 'DSM_DRAIN_BEGIN' in line)
        lines[first], lines[begin] = lines[begin], lines[first]
        bad['host_log'] = '\n'.join(lines)
        with self.assertRaisesRegex(ValueError, '故障先锁存'):
            self.inspect(bad)

    def test_rejected_attempts_remain_visible(self):
        raced, refused = self.data['rejected_attempts']
        with self.assertRaises(ValueError):
            self.inspect(raced)
        self.assertIn('就绪', raced['analysis_error'])
        self.assertEqual(refused['run']['exit'], 2)
        self.assertIn('TCP', refused['stderr'])
        self.assertIsNone(refused['record'])

    def test_workspace_regression_retains_kernel_close_errors(self):
        self.assertEqual([row['mode'] for row in self.data['workspace_runs']], ['control', 'pair', 'control', 'pair'])
        for row in self.data['workspace_runs']:
            latest_pair = row['label'] == 'kd-pf19-workspace-pair-1'
            self.assertEqual(row['operations_passed'], not latest_pair)
            self.assertFalse(row['full_ssi_accepted'])
            if latest_pair:
                self.assertIn('Long readout interval, skipping watchdog check', row['validation']['boot'])
                with self.assertRaisesRegex(ValueError, 'Long readout interval'):
                    boot.validate(row['serial_log'])
            else:
                boot.validate(row['serial_log'])
            stress.validate(row['stress_log'])
            trials = ['CLOCK_START' + part for part in row['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            self.assertTrue(row['result']['sftp_matches'])
            if row['mode'] == 'pair':
                self.assertEqual(router.inspect(row), row['analysis'])
                self.assertTrue(any(row['validation']['hosts']))
                self.assertTrue(any('ret -104' in text for text in row['host_logs']))
            else:
                boot.check_errors(row['host_logs'][0])

    def test_restoration_and_remaining_work(self):
        for node in self.data['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        self.assertEqual(self.data['storage_check']['lima_status'], 'Stopped')
        for name in ('whole-VM admission', 'reverse request chains', 'normal DSM shutdown', 'Ceph', 'Docker', 'PostgreSQL', 'Redis', 'failover'):
            self.assertIn(name, self.data['not_accepted'])


if __name__ == '__main__':
    unittest.main()
