"""核查宿主定时器实测摘要及失败边界，不把摘录当作全量跟踪重放。"""
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


clock, boot, stress = [load(name) for name in ('check-clock', 'check-ssh-boot', 'check-stress')]


class HostTimerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-host-timers-20261106.json').read_text())

    def test_built_source_and_observed_runtime_are_linked(self):
        data = self.data
        for path, expected in data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for name, expected in data['capture_source_versions']['candidate'].items():
            self.assertEqual(hashlib.sha256((directory / name).read_bytes()).hexdigest(), expected)
        self.assertTrue(data['build']['config_only_localversion_changed'])
        self.assertTrue(data['build']['patch_replay_matches_compiled_source'])
        self.assertEqual(len(data['runtime_boot_checks']), 2)
        for node in data['runtime_boot_checks']:
            self.assertEqual(node['kernel'], '7.1.0-rc3-sshpool-gvm-pf15')
            self.assertEqual(node['pause_exiting'], 'Y')
            self.assertTrue(node['identity_matches'])
        unchanged = set()
        for run in data['runs']:
            expected = data['baseline_kernel_sha256'] if run['label'].startswith('pf14-') else data['build']['kernel']
            for hashes in run['runtime_hashes']:
                self.assertEqual(hashes['kernel'], expected)
                self.assertEqual(hashes['qemu'], run['result']['qemu_sha256'])
                unchanged.add(tuple(hashes[key] for key in ('qemu', 'guest', 'initramfs', 'runner')))
        self.assertEqual(len(unchanged), 1)

    def test_trace_counts_and_rearm_endpoints_are_consistent(self):
        self.assertEqual(len(self.data['traces']), 4)
        for trace in self.data['traces']:
            self.assertIsNone(trace['analysis_error'])
            self.assertTrue(trace['trace_cleanup_complete'])
            summary = trace['summary']
            self.assertEqual(trace['header_counts'], [[str(summary['events'])] * 2])
            self.assertEqual(sum(summary['event_counts'].values()), summary['events'])
            for stats in trace['trace_stats'].values():
                for name in ('overrun', 'commit overrun', 'dropped events'):
                    self.assertEqual(re.findall('^' + name + r': (\d+)$', stats, re.MULTILINE), ['0'])
            for cpu, data in summary['cpus'].items():
                longest = data['longest_rearms'][0]
                self.assertEqual(longest['after_irq_delay_ns'], data['after_irq_delay']['max_ns'])
                for window in data['longest_rearms']:
                    self.assertEqual(window['after_irq_delay_ns'], window['rearm']['ns'] - window['irq_exit']['ns'])
                    self.assertEqual(int(cpu), window['cpu'])
                    self.assertTrue(all(event['cpu'] == int(cpu) for event in window['window_events']))
                    self.assertEqual(sum(window['window_event_counts'].values()),
                                     len(window['window_events']) + window['window_omitted_events'])
                self.assertIsNotNone(longest['program'])
                self.assertIsNotNone(longest['lapic_programming_entry'])
        for node in (0, 1):
            before, after = [next(item for item in self.data['traces']
                                 if item['node'] == node and item['label'].startswith(prefix))
                             for prefix in ('pf14-', 'pf15-')]
            for cpu in before['summary']['cpus']:
                self.assertLess(after['summary']['cpus'][cpu]['after_irq_delay']['max_ns'],
                                before['summary']['cpus'][cpu]['after_irq_delay']['max_ns'])

    def test_unprofiled_clock_pass_does_not_override_workspace_failures(self):
        runs = [run for run in self.data['runs'] if '-unprofiled-' in run['label']]
        self.assertEqual(len(runs), 3)
        for run in runs:
            trials = ['CLOCK_START' + part for part in run['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            self.assertEqual(run['validation']['clock'], [None] * 3)
            stress.validate(run['stress_log'])
            self.assertTrue(run['result']['sftp_matches'])
            self.assertIn('Power down', run['serial_log'])
            if run['result']['mode'] == 'control':
                boot.validate(run['serial_log'])
                boot.check_errors(run['host_logs'][0])
                self.assertTrue(run['full_workspace_passed'])
            else:
                with self.assertRaises(ValueError):
                    boot.validate(run['serial_log'])
                self.assertFalse(run['full_workspace_passed'])
                self.assertTrue(any(run['validation']['host']))
            self.assertEqual(run['result']['qemu_ssh_exits'], [0] * len(run['host_logs']))

    def test_disk_failure_and_partial_capture_remain_failures(self):
        failed = self.data['incomplete_run']
        self.assertFalse(failed['full_workspace_passed'])
        self.assertIn('No space left on device', failed['stderr'])
        self.assertIn('harness_error', failed['result'])
        self.assertIsNotNone(failed['traces'][0]['analysis_error'])
        self.assertNotIn('summary', failed['traces'][0])
        self.assertIsNone(failed['traces'][1]['analysis_error'])
        archived = {item['sha256'] for item in self.data['archived_trace_copies']
                    if item['remote_duplicate_removed']}
        for trace in self.data['traces'] + failed['traces']:
            self.assertIn(trace['raw_sha256'], archived)

    def test_lab_is_restored_without_storage_acceptance_claim(self):
        nodes = self.data['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        for node in self.data['lab_storage_check']['nodes']:
            self.assertFalse(node['ceph_installed'])
            self.assertFalse(node['ceph_units'])
            self.assertGreater(node['disk_free_bytes'], 1024 ** 3)
        self.assertEqual(self.data['lab_storage_check']['lima_status'], 'Stopped')


if __name__ == '__main__':
    unittest.main()
