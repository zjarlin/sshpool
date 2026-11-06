"""重放故障传播证据，防止把清理导致的返回、摘要成功或缺失跟踪误验收。"""
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


checker = load('check-failure-propagation')
boot, clock, stress = [load(name) for name in ('check-ssh-boot', 'check-clock', 'check-stress')]


class FailurePropagationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-failure-propagation-20261106.json').read_text())
        cls.success = next(item['record'] for item in cls.data['probes'] if item['label'] == 'failure-pf17-malformed-node0-2')
        cls.baseline = next(item['record'] for item in cls.data['probes'] if item['label'] == 'failure-pf16-malformed-node0-1')

    def test_real_comparisons_preserve_baseline_waiting_and_candidate_failure(self):
        counts = {}
        self.assertEqual(len(self.data['probes']), 16)
        for item in self.data['probes']:
            report = checker.inspect(item['record'])
            self.assertEqual(report, item['analysis'])
            expected = 'request_completed' if item['record']['mode'] == 'complete' else (
                'request_still_waiting' if item['run']['kernel'].endswith('pf16') else 'failure_propagated')
            self.assertEqual(report['outcome'], expected)
            counts[expected] = counts.get(expected, 0) + 1
            self.assertTrue(item['firewall_restored_exactly'])
            self.assertFalse(report['normal_shutdown_accepted'])
        self.assertEqual(counts, {'request_completed': 4, 'request_still_waiting': 6, 'failure_propagated': 6})

    def test_source_build_and_runtime_hashes_match(self):
        for path, digest in self.data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        for name, digest in self.data['capture_hashes'].items():
            public_name = 'probe-failure-propagation.py' if name == 'probe-failure.py' else name
            self.assertEqual(hashlib.sha256((directory / public_name).read_bytes()).hexdigest(), digest)
        build = self.data['build']
        self.assertTrue(build['patch_replay_matches_compiled_source'])
        self.assertTrue(build['config_only_localversion_changed'])
        self.assertEqual(build['patch_sha256'], self.data['source_sha256']['scripts/ssi-lab/experiments/kernel-dsm-failure-propagation.patch'])
        qemu = self.data['qemu_build']
        self.assertTrue(qemu['patch_replay_matches_compiled_source'])
        self.assertEqual(qemu['patch_sha256'], self.data['source_sha256']['scripts/ssi-lab/experiments/qemu-dsm-failure-exit.patch'])
        self.assertNotIn('warning:', self.data['qemu_build_log'])
        self.assertNotIn('error:', self.data['qemu_build_log'])
        for item in self.data['probes']:
            kernel = item['run']['kernel']
            expected = build['kernel'] if kernel.endswith('pf17') else self.data['baseline_kernel_sha256']
            self.assertEqual(item['runtime_hashes']['vmlinuz-' + kernel], expected)
            for name, digest in self.data['capture_hashes'].items():
                self.assertEqual(item['runtime_hashes'][name], digest)

    def test_cleanup_error_cannot_be_relabelled_as_timely_failure(self):
        bad = deepcopy(self.baseline)
        bad.update(write_pending_after_fault=False, tasks_after_fault={}, registers_after=5, run_errno=5, vm_ioctl_errno=5)
        with self.assertRaises(ValueError):
            checker.inspect(bad)
        bad = deepcopy(self.success)
        bad['write_result']['finished_ns'] = next(row['time_ns'] for row in bad['events'] if row['phase'] == 'cleanup_begin') + 1
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_vm_and_vcpu_must_refuse_failed_instance(self):
        for key in ('registers_after', 'run_errno', 'vm_ioctl_errno'):
            bad = deepcopy(self.success)
            bad[key] = 0
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.success)
        bad['write_result']['errno'] = 104
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_request_content_and_fault_type_are_verified(self):
        for key in ('fault_frame_hex', 'missing_request_hex', 'outgoing_request_hex'):
            bad = deepcopy(self.success)
            raw = bytearray.fromhex(bad[key])
            raw[14] ^= 1
            bad[key] = raw.hex()
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.success)
        bad['second_after_fault'] = {'state': 'waiting'}
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_loss_counts_and_thread_lifecycle_cannot_be_omitted(self):
        for kind in ('overrun', 'missing_cpu', 'probe_miss', 'missing_exit', 'reused_pid'):
            bad = deepcopy(self.success)
            if kind == 'overrun':
                cpu = next(iter(bad['trace_stats']))
                bad['trace_stats'][cpu] = bad['trace_stats'][cpu].replace('overrun: 0', 'overrun: 1', 1)
            elif kind == 'missing_cpu':
                bad['trace_stats'] = {}
            elif kind == 'probe_miss':
                lines = bad['kprobe_profile'].splitlines()
                lines[0] = re.sub(r'0\s*$', '1', lines[0])
                bad['kprobe_profile'] = '\n'.join(lines)
            elif kind == 'missing_exit':
                bad['trace'] = '\n'.join(row for row in bad['trace'].splitlines() if 'failure_root:' not in row)
            else:
                pid = next(iter(bad['initial_tasks']))
                bad['all_tasks'][pid]['name'] = 'different-task'
            with self.assertRaises(ValueError):
                checker.inspect(bad)

    def test_first_error_and_normal_page_contents_are_preserved(self):
        bad = deepcopy(self.success)
        bad['trace'] = re.sub(r'(failure_root:.*code=)-71', r'\g<1>0', bad['trace'])
        with self.assertRaises(ValueError):
            checker.inspect(bad)
        control = next(item['record'] for item in self.data['probes'] if item['record']['mode'] == 'complete')
        bad = deepcopy(control)
        bad['written_page_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            checker.inspect(bad)
        bad = deepcopy(control)
        bad['initial_response']['hex'] = '00' * 4110
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_rejected_attempt_and_cleanup_failure_remain_visible(self):
        self.assertEqual(len(self.data['rejected_attempts']), 1)
        rejected = self.data['rejected_attempts'][0]
        self.assertEqual(rejected['label'], 'failure-pf17-malformed-node0-1')
        self.assertTrue(rejected['analysis_error'])
        self.assertTrue(rejected['record']['errors'])
        self.assertNotIn('fault_begin', [item['phase'] for item in rejected['record']['events']])
        for key, value in [('errors', ['failed']), ('vm_closed', False), ('trace_cleanup_complete', False), ('remaining_tasks', {'1': {}})]:
            bad = deepcopy(self.success)
            bad[key] = value
            with self.assertRaises(ValueError):
                checker.inspect(bad)

    def test_workspace_and_real_peer_failure_keep_their_distinct_gates(self):
        by_mode = {(item['qemu_variant'], item['mode']): item for item in self.data['workspace_runs']}
        self.assertEqual(set(by_mode), {(variant, mode) for variant in ('baseline', 'failure-exit') for mode in ('control', 'pair', 'fault')})
        for (variant, mode), item in by_mode.items():
            for hashes in item['runtime_hashes']:
                self.assertEqual(hashes['kernel'], self.data['build']['kernel'])
                expected = self.data['qemu_build']['binary'] if variant == 'failure-exit' else '9578a44f54a770283af1979c897d40aef74d936f473712e8fa41131d808f2541'
                self.assertEqual(hashes['qemu'], expected)
            self.assertFalse(item['full_ssi_accepted'])
            # 双节点与注入结果从原始日志复核，不能只信汇总状态。
            rejected_boot = variant == 'baseline' and mode == 'fault'
            self.assertEqual(item['operations_passed'], not rejected_boot)
            self.assertTrue(item['result']['sftp_matches'])
            if rejected_boot:
                self.assertIn('hpet: Lost 3 RTC interrupts', item['serial_log'])
                with self.assertRaisesRegex(ValueError, 'RTC interrupts'):
                    boot.validate(item['serial_log'])
            else:
                boot.validate(item['serial_log'])
            stress.validate(item['stress_log'])
            trials = ['CLOCK_START' + part for part in item['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            for node, encoded in enumerate(item['qemu_stderr']):
                checker.expand_log(encoded)
                raw = self.data['raw_artifacts'][f"{item['label']}-node{node}-qemu-stderr.log"]
                self.assertEqual(encoded['raw_sha256'], raw['sha256'])
                self.assertEqual(encoded['raw_bytes'], raw['bytes'])
                # 本批 stderr 无需脱敏替换，展开结果应逐字节等于原始文件。
                self.assertEqual(encoded['decoded_sha256'], raw['sha256'])
                self.assertEqual(encoded['decoded_utf8_bytes'], raw['bytes'])
            if mode == 'control':
                self.assertEqual(item['result']['qemu_ssh_exits'], [0])
                for text in item['host_logs']:
                    boot.check_errors(text)
            else:
                self.assertTrue(any(item['validation']['host']))
            if mode == 'fault':
                report = checker.inspect_workspace_fault(item)
                self.assertEqual(report, item['fault_analysis'])
                self.assertTrue(report['failure_reached_qemu'])
                self.assertEqual(report['controlled_failure_exit'], variant == 'failure-exit')
                self.assertEqual(report['crash_detected'], variant == 'baseline')
                self.assertFalse(report['normal_shutdown_accepted'])

    def test_exit_code_and_summary_cannot_hide_the_recorded_qemu_crash(self):
        bad = deepcopy(next(item for item in self.data['workspace_runs'] if item['mode'] == 'fault' and item['qemu_variant'] == 'baseline'))
        bad['result']['qemu_ssh_exits'] = [1, 1]
        bad['fault_analysis']['controlled_failure_exit'] = True
        report = checker.inspect_workspace_fault(bad)
        self.assertTrue(report['crash_detected'])
        self.assertFalse(report['controlled_failure_exit'])
        self.assertTrue(all(count > 50000 for count in report['synchronization_errors']))

    def test_injection_and_management_failures_cannot_pass_as_controlled_exit(self):
        candidate = next(item for item in self.data['workspace_runs'] if item['mode'] == 'fault' and item['qemu_variant'] == 'failure-exit')
        for key in ('management_timeout', 'host_log_timeout', 'harness_error', 'samples_errors'):
            bad = deepcopy(candidate)
            bad['result'][key] = True
            with self.assertRaises(ValueError):
                checker.inspect_workspace_fault(bad)
        bad = deepcopy(candidate)
        bad['result']['phases']['failure-poweroff'] = {'exit': 255}
        with self.assertRaises(ValueError):
            checker.inspect_workspace_fault(bad)
        bad = deepcopy(candidate)
        injected = json.loads(bad['injection_log'])
        injected['frame_hex'] = '00' * 4110
        bad['injection_log'] = json.dumps(injected)
        with self.assertRaises(ValueError):
            checker.inspect_workspace_fault(bad)
        bad = deepcopy(candidate)
        bad['result']['qemu_ssh_exits'] = [1, 137]
        self.assertFalse(checker.inspect_workspace_fault(bad)['controlled_failure_exit'])

    def test_repeated_error_logs_are_lossless_and_reject_tampering(self):
        row = next(item for item in self.data['workspace_runs'] if item['mode'] == 'fault' and item['qemu_variant'] == 'baseline')
        encoded = row['qemu_stderr'][0]
        decoded = checker.expand_log(encoded)
        self.assertGreater(len(decoded), 6000000)
        for kind in ('count', 'line', 'length', 'hash'):
            bad = deepcopy(encoded)
            if kind == 'count':
                bad['runs'][0][1] += 1
            elif kind == 'line':
                bad['runs'][0][0] = 'hidden error\n'
            elif kind == 'length':
                bad['decoded_utf8_bytes'] += 1
            else:
                bad['decoded_sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                checker.expand_log(bad)

    def test_restoration_and_unfinished_ssi_requirements_are_explicit(self):
        self.assertEqual(len(self.data['restoration']['nodes']), 2)
        for node in self.data['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        self.assertEqual(self.data['lab_storage_check']['lima_status'], 'Stopped')
        for node in self.data['lab_storage_check']['nodes']:
            self.assertFalse(node['ceph_installed'])
            self.assertFalse(node['ceph_units'])
            self.assertFalse(node['docker_installed'])
        for item in ('normal DSM shutdown', 'Ceph', 'Docker', 'PostgreSQL', 'Redis', 'sub2api', 'physical capacity aggregation', 'failover'):
            self.assertIn(item, self.data['not_accepted'])


if __name__ == '__main__':
    unittest.main()
