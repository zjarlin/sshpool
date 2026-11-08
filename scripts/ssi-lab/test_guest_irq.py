"""重放真实函数与分段记录，拒绝采集漏洞，并保留超时失败。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('irq', HERE / 'check-guest-irq.py')
irq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(irq)
rewrite_trace = irq.guest.load('test_guest_timers').rewrite_trace


class GuestIrqTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-guest-irq-20261108.json').read_text())
        cls.runs = {run['label']: run for run in cls.evidence['runs']}
        cls.control = cls.runs['control-d']
        cls.files = irq.guest.read_archive(ROOT / 'docs/evidence' / cls.control['archive']['file'])
        cls.log = cls.control['files']['clock']
        cls.call = cls.control['analysis']['functions'][irq.SYMBOLS[0]]['longest'][0]

    def reject(self, change, pattern='.'):
        files = deepcopy(self.files)
        change(files)
        with self.assertRaisesRegex(ValueError, pattern):
            irq.inspect(files, self.log)

    def change_row(self, files, index, change):
        rewrite_trace(files, lambda lines: [change(line) if at == index else line for at, line in enumerate(lines)])

    def change_hits(self, files, name, delta):
        files['profile-after'] = re.sub(r'(^\s*' + name + r'\s+)(\d+)',
                                        lambda match: match[1] + str(int(match[2]) + delta),
                                        files['profile-after'], flags=re.M)

    def test_all_captures_replay_with_independent_latency_gate(self):
        for label, run in self.runs.items():
            with self.subTest(label=label):
                archive = ROOT / 'docs/evidence' / run['archive']['file']
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), run['archive']['sha256'])
                self.assertEqual(archive.stat().st_size, run['archive']['bytes'])
                result = irq.inspect(irq.guest.read_archive(archive), run['files']['clock'])
                self.assertEqual(result, run['analysis'])
                timers = result['timer_analysis']
                self.assertEqual(len(timers['timers']), 24)
                self.assertEqual(timers['timer_gate_ns'], 250_000_000)
                self.assertEqual(timers['timer_gate_passed'],
                                 all(timer['elapsed_ns'] <= 250_000_000 for timer in timers['timers']))
                self.assertFalse(result['full_ssi_accepted'])
                self.assertFalse(result['stall_cause_established'])
        self.assertFalse(self.runs['pair-b']['analysis']['timer_analysis']['timer_gate_passed'])
        self.assertFalse(self.runs['pair-c']['analysis']['timer_analysis']['timer_gate_passed'])

    def test_long_function_is_not_the_longest_application_wait(self):
        result = self.runs['pair-c']['analysis']
        call = result['functions'][irq.SYMBOLS[0]]['longest'][0]
        self.assertEqual(call['duration_ns'], 467_787_000)
        self.assertEqual(len(call['attempts']), 1)
        self.assertEqual(call['attempts'][0]['to_even_ns'], 467_776_000)
        self.assertEqual(call['attempts'][0]['clock_read_ns'], 5_000)
        timer = max(result['timer_analysis']['timers'], key=lambda row: row['elapsed_ns'])
        self.assertEqual(timer['elapsed_ns'], 553_933_098)
        self.assertEqual(timer['irq']['duration_ns'], 16_012_000)
        self.assertNotIn(call['start']['index'], [item['start']['index'] for item in timer['irq_functions']])

    def test_real_retry_waits_for_the_next_even_sequence(self):
        call = self.runs['pair-e']['analysis']['functions'][irq.SYMBOLS[0]]['longest'][0]
        self.assertEqual(call['duration_ns'], 523_303_000)
        self.assertEqual(len(call['attempts']), 2)
        first, second = call['attempts']
        self.assertTrue(first['retried'])
        self.assertEqual(irq.sequence_value(first['check'], 'after'), 39159)
        self.assertEqual(second['to_even_ns'], 520_256_000)
        self.assertEqual(irq.sequence_value(second['even'], 'seq'), 39160)
        self.assertFalse(second['retried'])

    def test_counters_must_cover_all_probes_and_start_at_zero(self):
        self.reject(lambda files: files.update({'profile-after': files['profile-after'] + files['profile-after']}), '重复')
        self.reject(lambda files: files.update({'profile-after': '\n'.join(files['profile-after'].splitlines()[1:])}), '不完整')
        self.reject(lambda files: files.update({'profile-before': re.sub(r'\b0\b', '1', files['profile-before'], count=1)}), '初始')
        self.reject(lambda files: files.update({'profile-after': re.sub(r'0\s*$', '1', files['profile-after'])}), '漏采')

    def test_entry_and_stage_hits_must_match_exactly(self):
        for name in ('tick_sched_do_timer_enter', *irq.STAGES):
            with self.subTest(name=name):
                self.reject(lambda files: self.change_hits(files, name, 1), '命中与事件')

    def test_return_hit_excess_requires_suffix_calls(self):
        self.reject(lambda files: self.change_hits(files, 'tick_sched_handle_exit', 100), '边界解释')
        self.reject(lambda files: self.change_hits(files, 'tick_sched_handle_exit', -100), '边界解释')

    def test_stop_fence_and_restoration_are_mandatory(self):
        for key in ('kprobes-before', 'kprobes-disabled', 'kprobes-restored'):
            self.reject(lambda files: files.pop(key), '同步或恢复')
            self.reject(lambda files: files.update({key: 'unexpected'}), '同步或恢复')

    def test_exact_probe_definitions_and_symbol_addresses_are_required(self):
        self.reject(lambda files: files.update(probes=files['probes'].replace('+56 ', '+57 ')), '定义')
        self.reject(lambda files: files.update(kallsyms=files['kallsyms'].replace(
                    'ffffffff81213bc0 T ktime_get_update_offsets_now', 'ffffffff81213bc1 T ktime_get_update_offsets_now')), '地址')
        self.reject(lambda files: files.update({'filter-ktime_seq_even': 'seq == 2'}), '隐藏')

    def test_details_cannot_name_another_function_or_instruction(self):
        index = self.call['attempts'][0]['even']['index']
        self.reject(lambda files: self.change_row(files, index, lambda line: line.replace('+0x38/', '+0x39/')), '地址')
        index = self.call['start']['index']
        self.reject(lambda files: self.change_row(files, index, lambda line: line.replace(
                    '(ktime_get_update_offsets_now+', '(ktime_get+')), '地址')

    def test_missing_stage_is_rejected_even_with_recomputed_counts(self):
        index = self.call['attempts'][0]['clock']['index']
        def change(files):
            rewrite_trace(files, lambda lines: [line for at, line in enumerate(lines) if at != index])
            self.change_hits(files, 'ktime_clock_done', -1)
        self.reject(change, '分段缺失')

    def test_stage_order_cannot_be_repaired_by_matching_counts(self):
        even = self.call['attempts'][0]['even']['index']
        clock = self.call['attempts'][0]['clock']['index']
        def change(files):
            def swap(lines):
                even_detail = lines[even].split('ktime_seq_even:', 1)[1]
                clock_detail = lines[clock].split('ktime_clock_done:', 1)[1]
                lines[even] = lines[even].split('ktime_seq_even:', 1)[0] + 'ktime_clock_done:' + clock_detail
                lines[clock] = lines[clock].split('ktime_clock_done:', 1)[0] + 'ktime_seq_even:' + even_detail
                return lines
            rewrite_trace(files, swap)
        self.reject(change, '分段顺序')

    def test_odd_sequence_and_unexplained_retry_are_rejected(self):
        even = self.call['attempts'][0]['even']['index']
        self.reject(lambda files: self.change_row(files, even, lambda line: re.sub(r'seq=\d+', 'seq=1', line)), '偶数')
        check = self.call['attempts'][-1]['check']['index']
        self.reject(lambda files: self.change_row(files, check, lambda line: re.sub(r'after=\d+', 'after=1', line)), '控制流')

    def test_stage_cannot_belong_to_a_different_thread(self):
        index = self.call['attempts'][0]['clock']['index']
        self.reject(lambda files: self.change_row(files, index, lambda line: re.sub(r'-(\d+)(\s+\[)', r'-9999\2', line)), '线程')

    def test_internal_missing_entry_is_not_a_capture_boundary(self):
        index = self.call['start']['index']
        def change(files):
            rewrite_trace(files, lambda lines: [line for at, line in enumerate(lines) if at != index])
            self.change_hits(files, 'ktime_get_update_offsets_now_enter', -1)
        self.reject(change, '内部返回|孤立返回')

    def test_buffer_loss_is_not_covered_by_probe_counts(self):
        self.reject(lambda files: files.update({'stats-cpu0': files['stats-cpu0'].replace('overrun: 0', 'overrun: 1')}), '丢失')

    def test_failed_legacy_capture_remains_rejected(self):
        run = self.evidence['rejected_instrumentation']
        self.assertFalse(run['accepted_for_attribution'])
        self.assertEqual(run['recorded_probe_counts']['tick_sched_do_timer_enter'], 17429)
        profile = irq.profile(run['profile_after'], irq.FUNCTION_EVENTS)
        self.assertEqual(profile['tick_sched_do_timer_enter'], 17431)
        files = irq.guest.read_archive(ROOT / 'docs/evidence' / run['archive']['file'])
        with self.assertRaisesRegex(ValueError, '同步或恢复'):
            irq.inspect(files, run['files']['clock'])

    def test_cli_outputs_analysis_but_fails_the_250ms_gate(self):
        run = self.runs['pair-c']
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'clock.log'
            log.write_text(run['files']['clock'])
            result = subprocess.run([sys.executable, str(HERE / 'check-guest-irq.py'),
                                      str(ROOT / 'docs/evidence' / run['archive']['file']), str(log)],
                                     capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout), run['analysis'])

    def test_real_workspace_results_and_original_boots_are_preserved(self):
        stress = irq.guest.load('check-stress')
        close = irq.guest.load('check-qemu-close')
        for run in self.runs.values():
            result = run['result']
            for phase in ('identity', 'clock-upload', 'guest-trace-start', 'clock', 'guest-trace-stop', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(result['phases'][phase]['exit'], 0)
            self.assertFalse(any(result.get(key) for key in ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')))
            self.assertEqual(result['qemu_ssh_exits'], [0, 0] if result['mode'] == 'pair' else [0])
            self.assertTrue(result['sftp_matches'])
            self.assertEqual(run['firewall']['before'], run['firewall']['after'])
            stress.validate(run['files']['stress'])
            self.assertIn('reboot: Power down', run['serial_log'])
            if result['mode'] == 'pair':
                generation = close.inspect_barrier(run['qemu_stderr'], 'QUIESCE')
                close.inspect_barrier(run['qemu_stderr'], 'DRAIN')
                for log in run['qemu_stderr']:
                    self.assertIn(f'SSI_KERNEL_CLOSE_RESULT generation={generation} ret=0', log)
                    self.assertIn('SSI_DEVICE_CLOSE_COMPLETE', log)
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)
        for node in self.evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged', 'firewall_matches_original', 'stock_grub_default'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])

    def test_live_collector_matches_shipped_source(self):
        source = self.evidence['collector_sources']['d']
        raw = (HERE / 'trace-guest-timers.sh').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), source['sha256'])
        self.assertEqual(raw.decode(), source['source'])
        subprocess.run(['sh', '-n', str(HERE / 'trace-guest-timers.sh')], check=True, capture_output=True)
        self.assertFalse(self.evidence['runtime_fix_proven'])
        self.assertEqual(self.evidence['physical_hosts'], 1)

    def test_failed_ssh_session_is_not_a_completed_workspace(self):
        failed = self.evidence['incomplete_workspace']
        result = failed['result']
        self.assertEqual(result['phases']['guest-trace-start']['exit'], 255)
        self.assertIn('guest trace start failed', result['harness_error'])
        self.assertNotIn('clock', result['phases'])
        self.assertEqual(result['qemu_ssh_exits'], [0, 0])
        self.assertEqual(failed['firewall']['before'], failed['firewall']['after'])
        self.assertFalse(failed['full_ssi_accepted'])


if __name__ == '__main__':
    unittest.main()
