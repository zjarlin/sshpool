"""核查公开摘录、真实 PAUSE 退出、原验收门槛和实验恢复，摘要不冒充完整跟踪。"""
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


residency, clock, boot, stress, resources = [load(name) for name in
    ('check-vcpu-residency', 'check-clock', 'check-ssh-boot', 'check-stress', 'check-esxi-resources')]


class ResidencyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-vcpu-residency-20261106.json').read_text())

    def test_sources_match_and_cpu_limits_are_not_reintroduced(self):
        data = self.evidence
        for path, expected in data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for path, expected in data['trace_source_versions'].items():
            self.assertEqual(hashlib.sha256((directory / path).read_bytes()).hexdigest(), expected)
        for key in ('esxi_baseline', 'esxi_active', 'esxi_final'):
            self.assertEqual(resources.assess(data[key]), [])
            self.assertEqual(data[key]['distinct_physical_hosts'], 1)
        for key in ('pf12_build', 'pf13_build', 'pf14_build'):
            self.assertTrue(data[key]['config_only_localversion_changed'])

    def test_long_kvm_intervals_match_saved_endpoints_without_loss(self):
        for run in self.evidence['runs']:
            for trace in run['traces']:
                if trace['analysis_error'] is not None:
                    self.assertTrue(any(int(b) < int(w) for b, w in trace['header_counts']))
                    continue
                self.assertIn('[global]', trace['trace_clock'])
                self.assertTrue(trace['trace_cleanup_complete'])
                for stats in trace['trace_stats'].values():
                    for key in ('overrun', 'commit overrun', 'dropped events'):
                        self.assertEqual(re.findall('^' + key + r': (\d+)$', stats, re.MULTILINE), ['0'])
                summary = trace['summary']
                self.assertEqual(sum(summary['event_counts'].values()), summary['events'])
                endpoints = []
                for line in trace['raw_endpoint_excerpt']:
                    match = residency.latency.EVENT.fullmatch(line)
                    self.assertIsNotNone(match)
                    _, pid, cpu, stamp, name, detail = match.groups()
                    seconds, fraction = stamp.split('.')
                    endpoints.append((int(pid), int(cpu), int(seconds) * 1000000000 + int(fraction.ljust(9, '0')), name, detail))
                for interval in summary['longest_kvm_intervals'][:5]:
                    self.assertEqual(interval['end']['ns'] - interval['start']['ns'], interval['duration_ns'])
                    for key in ('start', 'end'):
                        event = interval[key]
                        self.assertIn(tuple(event[field] for field in ('pid', 'cpu', 'ns', 'name', 'detail')), endpoints)

    def test_declared_activation_requires_real_pause_exits(self):
        active = 0
        for run in self.evidence['runs']:
            for trace in run['traces']:
                if trace['analysis_error'] is not None:
                    continue
                pauses = trace['summary']['exit_reasons'].get('PAUSE_INSTRUCTION', 0)
                if run['pause_active']:
                    self.assertGreater(pauses, 0)
                    active += 1
                else:
                    self.assertEqual(pauses, 0)
        self.assertGreaterEqual(active, 2)

    def test_comparison_uses_same_kernel_and_same_clock_workload(self):
        runs = {run['label']: run for run in self.evidence['runs']}
        enabled = runs['pf14-pause-short-pair-1']
        disabled = runs['pf14-off-short-pair-2']
        self.assertEqual(enabled['clock_trials'], disabled['clock_trials'])
        self.assertEqual(enabled['clock_trials'], 1)
        self.assertEqual(enabled['result']['qemu_sha256'], disabled['result']['qemu_sha256'])
        for before, after in zip(disabled['traces'], enabled['traces']):
            self.assertEqual(before['kernel'], after['kernel'])
            self.assertEqual(before['kernel'], '7.1.0-rc3-sshpool-gvm-pf14')
            self.assertEqual(before['node'], after['node'])
            self.assertIsNone(before['analysis_error'])
            self.assertIsNone(after['analysis_error'])
            self.assertLess(after['summary']['kvm_intervals']['max_ns'], before['summary']['kvm_intervals']['max_ns'])
        for name, nodes in self.evidence['runtime_switch_checks'].items():
            self.assertEqual(len(nodes), 2)
            for node in nodes:
                self.assertTrue(node['identity_matches'])
                self.assertEqual(node['pause_exiting'], 'N' if name == 'pf14-off-boot' else 'Y')

    def test_clock_memory_and_workspace_results_are_recomputed(self):
        for run in self.evidence['runs']:
            trials = ['CLOCK_START' + part for part in run['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), run['clock_trials'])
            self.assertEqual(len(trials), len(run['validation']['clock']))
            for trial, error in zip(trials, run['validation']['clock']):
                if error is None:
                    clock.validate(trial, 250000000)
                else:
                    with self.assertRaises(ValueError):
                        clock.validate(trial, 250000000)
            if run['pause_user_log'] is not None:
                self.assertEqual(run['result']['phases']['pause-user']['exit'], 0)
                self.assertEqual(run['pause_user_log'].splitlines(),
                                 [f'PAUSE_CPU cpu={cpu} cpl=3 iterations=64 checksum=2080' for cpu in range(4)])
            stress.validate(run['stress_log'])
            self.assertTrue(run['result']['sftp_matches'])
            self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
            self.assertFalse(run['full_workspace_passed'])
            if run['validation']['boot'] is None:
                boot.validate(run['serial_log'])
            else:
                with self.assertRaises(ValueError):
                    boot.validate(run['serial_log'])
            for log, error in zip(run['host_logs'], run['validation']['host']):
                if error is None:
                    boot.check_errors(log)
                else:
                    with self.assertRaises(ValueError):
                        boot.check_errors(log)

    def test_labs_return_to_stock_without_residual_work(self):
        restored = self.evidence['restoration']['nodes']
        self.assertEqual(len(restored), 2)
        for node in restored:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'] and node['firewall_matches_original'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            for key in ('trace_events', 'trace_instances', 'grub_environment'):
                self.assertEqual(node[key], '')

    def test_failed_unprofiled_upload_is_retained_as_incomplete(self):
        failures = self.evidence['incomplete_workloads']
        self.assertEqual(len(failures), 1)
        failure = failures[0]
        self.assertIn('Connection timed out during banner exchange', failure['upload_log'])
        self.assertEqual(failure['result']['phases']['clock-upload']['exit'], 255)
        self.assertNotIn('clock', failure['result']['phases'])
        self.assertFalse(failure['full_workspace_passed'])


if __name__ == '__main__':
    unittest.main()
