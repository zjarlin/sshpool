"""重放真实固定页证据，并验证缺失记录、虚假成功和采集丢失不能被接受。"""
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


checker, clock, boot, stress = [load(name) for name in ('check-copyset-retry', 'check-clock', 'check-ssh-boot', 'check-stress')]


class CopysetRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-copyset-retry-20261106.json').read_text())
        cls.success = next(item['record'] for item in cls.data['probes'] if item['label'] == 'copyset-pf16-pin-node0-1')
        cls.failure = next(item['record'] for item in cls.data['probes'] if item['label'] == 'copyset-pf15-pin-node0-3')

    def test_same_requests_separate_baseline_failure_from_candidate_response(self):
        self.assertEqual(len(self.data['probes']), 8)
        frames = set()
        for item in self.data['probes']:
            report = checker.inspect(item['record'])
            self.assertEqual(report, item['analysis'])
            expected_failure = item['run']['pin'] and item['run']['kernel'].endswith('pf15')
            self.assertEqual(report['outcome'], 'request_rejected_after_unpin' if expected_failure else 'page_returned')
            self.assertEqual(item['run']['exit'], int(expected_failure))
            self.assertEqual(report['handler_codes_during_read'], [-22] if expected_failure else [])
            if item['run']['pin']:
                self.assertGreaterEqual(report['retry_unlocks_before_unpin'], 2)
            frames.add(item['record']['request_hex'])
            self.assertTrue(item['firewall_restored_exactly'])
        self.assertEqual(len(frames), 1)

    def test_compiled_patch_capture_and_runtime_hashes_match(self):
        data = self.data
        for path, expected in data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for name, expected in data['capture_versions']['accepted'].items():
            public_name = 'probe-copyset-retry.py' if name == 'probe-copyset.py' else name
            self.assertEqual(hashlib.sha256((directory / public_name).read_bytes()).hexdigest(), expected)
        self.assertEqual(data['build']['patch_sha256'], data['source_sha256']['scripts/ssi-lab/experiments/kernel-dsm-copyset-retry.patch'])
        self.assertTrue(data['build']['patch_replay_matches_compiled_source'])
        self.assertTrue(data['build']['config_only_localversion_changed'])
        for item in data['probes']:
            kernel = item['run']['kernel']
            expected = data['baseline_kernel_sha256'] if kernel.endswith('pf15') else data['build']['kernel']
            self.assertEqual(item['runtime_hashes']['vmlinuz-' + kernel], expected)
            for name, digest in data['capture_versions']['accepted'].items():
                self.assertEqual(item['runtime_hashes'][name], digest)
        for node in data['runtime_boot_checks']:
            self.assertTrue(node['identity_matches'])
            self.assertEqual(node['kernel'], '7.1.0-rc3-sshpool-gvm-pf16')
            self.assertEqual(node['pause_exiting'], 'Y')

    def test_transport_reset_after_read_is_preserved_without_failing_the_completed_read(self):
        item = next(item for item in self.data['probes'] if item['label'] == 'copyset-pf16-control-node0-1')
        report = checker.inspect(item['record'])
        self.assertEqual(report['handler_codes_during_read'], [])
        self.assertIn(-104, report['handler_codes_after_read'])
        self.assertEqual(report['outcome'], 'page_returned')
        self.assertIn('normal DSM shutdown', self.data['not_accepted'])

    def test_success_flag_does_not_override_bad_page_copyset_or_transaction(self):
        for field, value in [('copyset', 0), ('version', 7), ('txid', 43), ('sha256', '0' * 64), ('length', 14)]:
            bad = deepcopy(self.success)
            bad['response'][field] = value
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        bad = deepcopy(self.failure)
        bad['response'] = self.success['response']
        bad.pop('response_error')
        with self.assertRaises(ValueError):
            checker.inspect(bad)

    def test_lost_trace_events_and_probe_misses_are_rejected(self):
        for kind in ('overrun', 'missing_cpu_stats', 'probe_miss', 'missing_line'):
            bad = deepcopy(self.success)
            if kind == 'overrun':
                cpu = next(iter(bad['trace_stats']))
                bad['trace_stats'][cpu] = bad['trace_stats'][cpu].replace('overrun: 0', 'overrun: 1', 1)
            elif kind == 'missing_cpu_stats':
                bad['trace_stats'] = {}
            elif kind == 'probe_miss':
                rows = bad['kprobe_profile'].splitlines()
                rows[0] = re.sub(r'0\s*$', '1', rows[0])
                bad['kprobe_profile'] = '\n'.join(rows)
            else:
                bad['trace'] = '\n'.join(line for line in bad['trace'].splitlines() if 'copy_locked:' not in line)
            with self.assertRaises(ValueError):
                checker.inspect(bad)

    def test_wrong_page_and_early_response_are_rejected(self):
        for key, value in [('vfn', self.success['vfn'] + 1), ('response_before_unpin', True), ('observed_retry_unlocks', 1)]:
            bad = deepcopy(self.success)
            bad[key] = value
            with self.assertRaises(ValueError):
                checker.inspect(bad)

    def test_errors_and_incomplete_cleanup_remain_failures(self):
        for key, value in [('errors', ['collection failed']), ('vm_closed', False),
                           ('trace_cleanup_complete', False), ('remaining_tasks', {'7': {}})]:
            bad = deepcopy(self.success)
            bad[key] = value
            with self.assertRaises(ValueError):
                checker.inspect(bad)
        self.assertEqual(len(self.data['rejected_attempts']), 3)
        for item in self.data['rejected_attempts']:
            self.assertTrue(item['analysis_error'])
            self.assertTrue(item['trace_cleanup_complete'])
            self.assertTrue(item['vm_closed'])
            self.assertFalse(item['remaining_tasks'])

    def test_workspace_regressions_keep_clock_gate_and_shutdown_errors(self):
        self.assertEqual(len(self.data['workspace_runs']), 2)
        for item in self.data['workspace_runs']:
            for hashes in item['runtime_hashes']:
                self.assertEqual(hashes['kernel'], self.data['build']['kernel'])
                self.assertEqual(hashes['qemu'], '9578a44f54a770283af1979c897d40aef74d936f473712e8fa41131d808f2541')
            trials = ['CLOCK_START' + part for part in item['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            stress.validate(item['stress_log'])
            self.assertTrue(item['result']['sftp_matches'])
            self.assertEqual(item['result']['qemu_ssh_exits'], [0, 0])
            self.assertIn('Power down', item['serial_log'])
            self.assertFalse(item['full_workspace_passed'])
            for text in item['host_logs']:
                self.assertNotIn('ivy.c:', text)
                with self.assertRaisesRegex(ValueError, 'ktcp_receive'):
                    boot.check_errors(text)

    def test_labs_restored_and_business_storage_not_accepted(self):
        for node in self.data['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        self.assertEqual(len(self.data['restoration']['nodes']), 2)
        for node in self.data['lab_storage_check']['nodes']:
            self.assertFalse(node['ceph_installed'])
            self.assertFalse(node['ceph_units'])
            self.assertFalse(node['docker_installed'])
        self.assertEqual(self.data['lab_storage_check']['lima_status'], 'Stopped')
        for name in ('Ceph', 'Docker', 'PostgreSQL', 'Redis', 'sub2api', 'failover'):
            self.assertIn(name, self.data['not_accepted'])


if __name__ == '__main__':
    unittest.main()
