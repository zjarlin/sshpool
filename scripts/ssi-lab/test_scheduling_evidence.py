"""复核公开的资源变化、调度端点摘录和工作区门槛，不冒充私有全量跟踪重放。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

directory = Path(__file__).resolve().parent
root = directory.parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


resources, scheduling, clock, boot, stress = [load(name) for name in
    ('check-esxi-resources', 'check-dsm-scheduling', 'check-clock', 'check-ssh-boot', 'check-stress')]


class SchedulingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-scheduling-20261106.json').read_text())

    def test_only_cpu_limit_changed_and_after_samples_have_no_throttling(self):
        evidence = self.evidence
        self.assertEqual(len(evidence['resource_change']['nodes']), 2)
        for node in evidence['resource_change']['nodes']:
            expected = copy.deepcopy(node['before'])
            self.assertEqual(expected['cpu']['limit'], 2000)
            expected['cpu']['limit'] = -1
            self.assertEqual(node['after'], expected)
        for node in evidence['esxi_before']['nodes']:
            rows = node['performance'][0]['values']
            limits = next(row['values'] for row in rows if row['counter'] == 'cpu.maxlimited.summation')
            self.assertGreater(max(limits), 0)
        self.assertEqual(resources.assess(evidence['esxi_after']), [])
        self.assertEqual(resources.assess(evidence['esxi_full_comparison']), [])
        self.assertEqual(resources.assess(evidence['esxi_final']), [])
        self.assertEqual([node['cpu']['limit'] for node in evidence['esxi_final']['nodes']], [-1, -1])
        self.assertEqual(evidence['esxi_after']['distinct_physical_hosts'], 1)

    def test_endpoint_excerpts_match_reported_ready_waits(self):
        checked = 0
        for run in self.evidence['runs']:
            for node in run.get('scheduling', []):
                if node['analysis_error']:
                    self.assertTrue(any(int(b) < int(w) for b, w in node['header_counts']))
                    continue
                witness = node['longest_ready_witness']
                if node['preempt_mode'] is not None:
                    self.assertIn('(' + run['preemption'] + ')', node['preempt_mode'])
                    self.assertIn('[global]', node['trace_clock'])
                wait = witness['wait']
                self.assertEqual(wait['end_ns'] - wait['begin_ns'], wait['duration_ns'])
                starts, ends = [], []
                for line in witness['raw_excerpt']:
                    match = scheduling.latency.EVENT.fullmatch(line)
                    self.assertIsNotNone(match)
                    _, _, _, stamp, name, detail = match.groups()
                    seconds, fraction = stamp.split('.')
                    ns = int(seconds) * 1000000000 + int(fraction.ljust(9, '0'))
                    event = {'detail': detail}
                    if name == 'sched_wakeup' and scheduling.latency.field(event, 'pid') == wait['pid']:
                        starts.append(ns)
                    if name == 'sched_switch':
                        if scheduling.latency.field(event, 'prev_pid') == wait['pid'] and 'prev_state=R' in detail:
                            starts.append(ns)
                        if scheduling.latency.field(event, 'next_pid') == wait['pid']:
                            ends.append(ns)
                self.assertIn(wait['begin_ns'], starts)
                self.assertIn(wait['end_ns'], ends)
                for call in node['summary']['longest_responses']:
                    self.assertEqual(sum(call['scheduling_ns'].values()), call['duration_ns'])
                checked += 1
        self.assertEqual(checked, 6)

    def test_guest_probes_do_not_hide_full_workspace_failures(self):
        for run in self.evidence['runs']:
            trials = ['CLOCK_START' + part for part in run['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            self.assertEqual(len(run['validation']['clock']), 3)
            for trial, expected in zip(trials, run['validation']['clock']):
                if expected is None:
                    clock.validate(trial, 250000000)
                else:
                    with self.assertRaises(ValueError):
                        clock.validate(trial, 250000000)
            stress.validate(run['stress_log'])
            self.assertTrue(run['result']['sftp_matches'])
            self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
            self.assertFalse(run['full_workspace_passed'])
            if run['validation']['boot'] is not None:
                with self.assertRaises(ValueError):
                    boot.validate(run['serial_log'])
            for log, error in zip(run['host_logs'], run['validation']['host']):
                if error is not None:
                    with self.assertRaises(ValueError):
                        boot.check_errors(log)
        failure = self.evidence['failed_export']
        self.assertIn('exited 255', failure['result']['harness_error'])
        self.assertTrue(any('Out of memory:' in line for host in failure['host_logs'] for line in host['oom_excerpt']))

    def test_sources_and_lab_restoration(self):
        for path, expected in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        latest = self.evidence['capture_tool_versions']['64MiB-stream']['trace-dsm-scheduling.py']
        self.assertEqual(latest, self.evidence['source_sha256']['scripts/ssi-lab/trace-dsm-scheduling.py'])
        for node in self.evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'] and node['firewall_matches_original'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            for key in ('trace_events', 'trace_instances', 'grub_environment'):
                self.assertEqual(node[key], '')
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)


if __name__ == '__main__':
    unittest.main()
