"""验证活动探针边界、坏记录拒绝和真实实验摘录；摘录不冒充全量回放。"""
from collections import Counter
from copy import deepcopy
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('clock_stalls', HERE / 'check-clock-stalls.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture(events=None):
    if events is None:
        events = [('cs_acquired', '1.000000', '(direct_page_fault+0x1/0x2 <- kvm_dsm_vcpu_acquire_page) code=7'),
                  ('tracing_mark_write', '1.000100', 'capture_begin'),
                  ('cs_acquire', '1.000200', '(kvm_dsm_vcpu_acquire_page+0x4/0x60) vcpu=0x123 gfn=0x456 write=1'),
                  ('cs_acquired', '1.000300', '(direct_page_fault+0x1/0x2 <- kvm_dsm_vcpu_acquire_page) code=7'),
                  ('cs_acquire', '1.000400', '(kvm_dsm_vcpu_acquire_page+0x4/0x60) vcpu=0x123 gfn=0x457 write=0'),
                  ('tracing_mark_write', '1.000500', 'capture_end')]
    counts = Counter(row[0] for row in events)
    trace = f'# entries-in-buffer/entries-written: {len(events)}/{len(events)}\n'
    trace += ''.join(f'       CPU 0/KVM-42 [000] ..... {time}: {name}: {detail}\n' for name, time, detail in events)
    identity = {'comm': 'qemu-system-x86', 'start_ticks': 123}
    tasks = {'42': {'comm': 'CPU 0/KVM', 'start_ticks': 124}}
    return {'kernel': '7.1.0-rc3-sshpool-gvm-pf28', 'node': 0, 'errors': [], 'trace_cleanup_complete': True,
            'qemu_present_after': True, 'trace_clock': '[global]',
            'profile_boundary_policy': 'disabled-returns-may-complete',
            'qemu_identity_before': identity, 'qemu_identity_after': deepcopy(identity),
            'qemu_tasks_before': tasks, 'qemu_tasks_after': deepcopy(tasks), 'trace': trace,
            'trace_stats': {'cpu0': f'entries: {len(events)}\noverrun: 0\ncommit overrun: 0\ndropped events: 0\n'},
            'kprobe_profile': '\n'.join(f'{name} {counts[name]} 0' for _, name, _ in checker.probe.PROBES),
            'events': [{'phase': 'capture_begin', 'time_ns': 10}, {'phase': 'capture_end', 'time_ns': 20}]}


class ClockStallsTests(unittest.TestCase):
    def reject(self, change, reason):
        record = fixture()
        change(record)
        with self.assertRaisesRegex(ValueError, reason):
            checker.inspect(record)

    def test_boundary_calls_do_not_enter_latency_distribution(self):
        result = checker.inspect(fixture())
        call = result['functions']['cs_acquire']
        self.assertEqual(call['measurement'], {'count': 1, 'median_ns': 100000, 'p95_ns': 100000, 'max_ns': 100000})
        self.assertEqual(len(call['prefix_returns']), 1)
        self.assertEqual(len(call['suffix_entries']), 1)
        self.assertEqual(result['functions']['cs_update']['measurement'], {'count': 0})
        self.assertFalse(result['stall_cause_established'])
        self.assertFalse(result['full_ssi_accepted'])

    def test_disabled_return_can_complete_but_cannot_exceed_pending_suffix(self):
        record = fixture()
        record['kprobe_profile'] = record['kprobe_profile'].replace('cs_acquired 2 0', 'cs_acquired 3 0')
        self.assertEqual(checker.inspect(record)['functions']['cs_acquire']['disabled_return_hits'], 1)
        record['kprobe_profile'] = record['kprobe_profile'].replace('cs_acquired 3 0', 'cs_acquired 4 0')
        with self.assertRaisesRegex(ValueError, '返回计数差'):
            checker.inspect(record)

    def test_entry_count_is_always_exact(self):
        self.reject(lambda r: r.update(kprobe_profile=r['kprobe_profile'].replace('cs_acquire 2 0', 'cs_acquire 3 0')),
                    '入口探针计数')

    def test_missed_probes_and_buffer_loss_are_rejected(self):
        self.reject(lambda r: r.update(kprobe_profile=r['kprobe_profile'].replace('cs_acquire 2 0', 'cs_acquire 2 1')),
                    '漏采')
        for field in ('overrun', 'commit overrun', 'dropped events'):
            with self.subTest(field=field):
                self.reject(lambda r: r['trace_stats'].update(cpu0=r['trace_stats']['cpu0'].replace(field + ': 0', field + ': 1')),
                            '跟踪丢失')

    def test_pid_reuse_and_foreign_thread_are_rejected(self):
        self.reject(lambda r: r['qemu_tasks_after']['42'].update(start_ticks=125), '身份改变')
        self.reject(lambda r: r.update(trace=r['trace'].replace('CPU 0/KVM-42', 'CPU 1/KVM-43')), '目标 vCPU')
        self.reject(lambda r: r['qemu_identity_after'].update(start_ticks=126), 'QEMU 身份改变')

    def test_invalid_timestamps_fields_markers_and_counts_are_rejected(self):
        changes = [('1.000300:', '0.000300:', '时间倒退'), ('write=1', 'write=2', '入口字段'),
                   ('vcpu=0x123 gfn=0x457', 'vcpu=0x124 gfn=0x457', '指针改变'),
                   ('capture_end', 'capture_begin', '窗口标记'), ('6/6', '6/7', '头部计数')]
        for old, new, reason in changes:
            with self.subTest(reason=reason):
                self.reject(lambda r: r.update(trace=r['trace'].replace(old, new)), reason)

    def test_interior_orphan_and_duplicate_entry_are_not_boundaries(self):
        rows, _, _, _ = checker.parse(fixture())
        interior = deepcopy(rows[3])
        with self.assertRaisesRegex(ValueError, '窗口内部返回'):
            checker.pair_calls(rows[:4] + [interior] + rows[4:], 'cs_acquire', 'cs_acquired')
        with self.assertRaisesRegex(ValueError, '重复入口'):
            checker.pair_calls(rows[:3] + [deepcopy(rows[2])] + rows[3:], 'cs_acquire', 'cs_acquired')

    def test_zero_recorded_returns_cannot_become_successful_calls(self):
        rows, _, _, _ = checker.parse(fixture())
        rows = [r for r in rows if r['name'] == 'cs_acquire'][:1]
        complete, prefix, suffix = checker.pair_calls(rows, 'cs_acquire', 'cs_acquired')
        self.assertEqual(complete, [])
        self.assertEqual(prefix, [])
        self.assertEqual(len(suffix), 1)


class ClockStallsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-clock-stalls-20261108.json').read_text())

    def test_source_and_raw_evidence_boundaries_are_explicit(self):
        for name, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)
        self.assertFalse(self.evidence['full_trace_embedded'])
        self.assertFalse(self.evidence['stall_cause_established'])
        self.assertFalse(self.evidence['full_ssi_accepted'])
        executed = self.evidence['executed_probe_source']
        self.assertEqual(ast.dump(ast.parse(executed)), ast.dump(ast.parse((HERE / 'trace-clock-stalls.py').read_text())))
        for node in self.evidence['clock_traces']:
            self.assertEqual(hashlib.sha256(executed.encode()).hexdigest(), node['probe_sha256'])
            analysis = node['analysis']
            self.assertFalse(analysis['stall_cause_established'])
            self.assertEqual(analysis['functions']['cs_update']['measurement'], {'count': 0})
            for function in analysis['functions'].values():
                for call in function['longest']:
                    self.assertEqual(call['end']['ns'] - call['start']['ns'], call['duration_ns'])

    def test_workloads_and_close_do_not_hide_warnings(self):
        close = checker.load('check-qemu-close')
        clock = checker.load('check-clock')
        stress = checker.load('check-stress')
        for run in self.evidence['runs']:
            self.assertEqual(close.inspect(run), run['close_analysis'])
            self.assertIn('hogged CPU', run['serial_log'])
            self.assertIn('reboot: Power down', run['serial_log'])
            for name in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(run['result']['phases'][name]['exit'], 0)
            trials = re.findall(r'CLOCK_START[^\n]*\n.*?CLOCK_PASS[^\n]*', run['clock_log'], re.S)
            self.assertEqual(len(trials), 3)
            failures = []
            for trial in trials:
                try:
                    clock.validate(trial, 250_000_000)
                except ValueError as error:
                    failures.append(str(error))
            self.assertEqual(failures, run['clock_validation']['errors'])
            self.assertEqual(run['clock_validation']['passed'], not failures)
            stress.validate(run['stress_log'])
            self.assertTrue(run['result']['sftp_matches'])
            self.assertEqual(run['firewall']['before'], run['firewall']['after'])
        self.assertIn('skipping watchdog check', self.evidence['runs'][1]['serial_log'])
        self.assertTrue(any(run['clock_validation']['errors'] for run in self.evidence['runs']))

    def test_restoration_is_complete_on_both_nodes(self):
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual([node['node'] for node in nodes], [0, 1])
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged',
                        'firewall_matches_original', 'stock_grub_default'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])

    @unittest.skipUnless(os.environ.get('SSHPOOL_CLOCK_STALL_TRACE_DIR'), '全量私有跟踪未提供；公开端点不是全量回放')
    def test_full_private_traces_replay_with_exact_hashes(self):
        directory = Path(os.environ['SSHPOOL_CLOCK_STALL_TRACE_DIR'])
        for node in self.evidence['clock_traces']:
            raw = (directory / node['file']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), node['raw_sha256'])
            self.assertEqual(checker.inspect(json.loads(raw)), node['analysis'])


if __name__ == '__main__':
    unittest.main()
