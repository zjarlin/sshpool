"""重放真实客体定时器记录，并拒绝漏采、错误归属和不同时间域的伪关联。"""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('guest', HERE / 'check-guest-timers.py')
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


def rewrite_trace(files, transform):
    """重算容器计数，让负例确实覆盖生命周期检查而非只被总数拦截。"""
    lines = files['trace'].splitlines()
    headers = [line for line in lines if line.startswith('#')]
    rows = [line for line in lines if line.strip() and not line.startswith('#')]
    rows = transform(rows)
    files['trace'] = re.sub(r'entries-in-buffer/entries-written: \d+/\d+',
                           f'entries-in-buffer/entries-written: {len(rows)}/{len(rows)}',
                           '\n'.join(headers + rows) + '\n')
    for cpu in range(4):
        count = sum(f'[{cpu:03d}]' in line for line in rows)
        key = f'stats-cpu{cpu}'
        files[key] = re.sub(r'^entries: \d+$', f'entries: {count}', files[key], flags=re.M)


class GuestTimerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-guest-timers-20261108.json').read_text())
        cls.pair, cls.control = cls.evidence['runs']
        cls.files = guest.read_archive(ROOT / 'docs/evidence' / cls.pair['archive']['file'])
        cls.log = cls.pair['files']['clock']
        cls.slow = max(cls.pair['timer_analysis']['timers'], key=lambda row: row['elapsed_ns'])

    def reject(self, transform, pattern='.'):
        files = deepcopy(self.files)
        transform(files)
        with self.assertRaisesRegex(ValueError, pattern):
            guest.inspect(files, self.log)

    def change_target(self, files, event, change):
        pointer = self.slow['pointer']
        def transform(lines):
            return [change(line) if event + ':' in line and 'hrtimer=' + pointer in line else line for line in lines]
        rewrite_trace(files, transform)

    def test_full_public_archives_replay(self):
        for run in self.evidence['runs']:
            archive = ROOT / 'docs/evidence' / run['archive']['file']
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), run['archive']['sha256'])
            self.assertEqual(archive.stat().st_size, run['archive']['bytes'])
            analysis = guest.inspect(guest.read_archive(archive), run['files']['clock'])
            self.assertEqual(analysis, run['timer_analysis'])
            self.assertEqual(len(analysis['timers']), 24)
            self.assertTrue(analysis['timer_gate_passed'])
            self.assertFalse(analysis['stall_cause_established'])
            self.assertFalse(analysis['full_ssi_accepted'])

    def test_reused_pointer_is_a_new_generation(self):
        timers = self.control['timer_analysis']['timers']
        self.assertEqual(len(timers), 24)
        self.assertEqual(len({timer['pointer'] for timer in timers}), 23)
        self.assertEqual(len({timer['generation_index'] for timer in timers}), 24)

    def test_slow_irq_and_monotonic_components_are_separate(self):
        timer = self.slow
        self.assertEqual(timer['elapsed_ns'], 215_760_933)
        self.assertEqual(timer['irq']['duration_ns'], 192_625_000)
        self.assertEqual(timer['irq_entry_to_first_callback_ns'], 114_478_000)
        self.assertEqual(timer['wakeup_to_switch_ns'], 86_519_000)
        self.assertEqual(timer['wakeup_to_irq_exit_ns'], 74_210_000)
        self.assertEqual(max(row['duration_ns'] for row in timer['post_wakeup_ticks']), 68_289_000)
        self.assertEqual(sum(timer[key] for key in ('before_to_arm_reference_ns', 'requested_ns',
                         'base_now_minus_softexpires_ns', 'base_now_to_after_ns')), timer['elapsed_ns'])
        self.assertNotEqual(timer['endpoints']['expire']['ns'],
                            int(guest.field(timer['endpoints']['expire'], 'now')))

    def test_lost_events_and_cpu_counts_are_rejected(self):
        self.reject(lambda files: files.update({'stats-cpu0': files['stats-cpu0'].replace('overrun: 0', 'overrun: 1')}), '丢失')
        self.reject(lambda files: files.update({'stats-cpu0': files['stats-cpu0'].replace('entries: 18914', 'entries: 18913')}), '计数')
        self.reject(lambda files: files.pop('stats-cpu3'), '四 CPU')
        self.reject(lambda files: files.update(trace=files['trace'].replace('84908/84908', '84908/84909')), '计数')

    def test_incompatible_capture_metadata_is_rejected(self):
        for key, value in [('cleanup', 'incomplete'), ('trace_clock', '[mono]'), ('clocksource', 'tsc'),
                           ('tainted', '1'), ('version', 'Linux version wrong'), ('cmdline', 'panic=10')]:
            with self.subTest(key=key):
                self.reject(lambda files: files.update({key: value}))
        self.reject(lambda files: files.update({'filter-hrtimer_cancel': 'pid == 190'}), '隐藏')
        self.reject(lambda files: files.update({'format-hrtimer_start': 'name: unknown\n'}), '格式')

    def test_target_clock_cpu_and_owner_are_required(self):
        for old, new in [('CLOCK_MONOTONIC', 'CLOCK_REALTIME'), ('mode=REL', 'mode=ABS'),
                         ('ssi-clock-190', 'ssi-clock-191'), ('[000]', '[001]')]:
            with self.subTest(new=new):
                self.reject(lambda files: self.change_target(files, 'hrtimer_init', lambda line: line.replace(old, new)), '身份|时钟域')

    def test_cancel_and_rearm_cannot_be_called_a_completed_timer(self):
        self.reject(lambda files: self.change_target(files, 'hrtimer_expire_entry',
                    lambda line: line.replace('hrtimer_expire_entry:', 'hrtimer_cancel:')), '取消')
        self.reject(lambda files: self.change_target(files, 'hrtimer_start',
                    lambda line: line.replace('was_armed=0', 'was_armed=1')), '模式')

    def test_target_generation_cannot_omit_init_or_return(self):
        for event in ('hrtimer_init', 'hrtimer_expire_entry', 'hrtimer_expire_exit'):
            with self.subTest(event=event):
                self.reject(lambda files: rewrite_trace(files, lambda lines:
                            [line for line in lines if not (event + ':' in line and 'hrtimer=' + self.slow['pointer'] in line)]))

    def test_target_callback_cannot_move_cpu(self):
        self.reject(lambda files: self.change_target(files, 'hrtimer_expire_entry',
                    lambda line: line.replace('[000]', '[002]')), '迁移')

    def test_monotonic_base_sample_must_fit_app_bounds(self):
        for value in (1, self.slow['after_ns'] + 1):
            self.reject(lambda files: self.change_target(files, 'hrtimer_expire_entry',
                        lambda line: re.sub(r'now=\d+', f'now={value}', line)), '边界不相容')

    def test_missing_wakeup_cannot_use_a_later_switch(self):
        at = self.slow['endpoints']['wakeup']['index']
        self.reject(lambda files: rewrite_trace(files, lambda lines: [line for index, line in enumerate(lines) if index != at]), '唤醒')
        at = self.slow['endpoints']['resume']['index']
        self.reject(lambda files: rewrite_trace(files, lambda lines: [line for index, line in enumerate(lines) if index != at]), '额外调度|重新运行')

    def test_missing_irq_exit_is_not_patched_with_another_exit(self):
        at = self.slow['irq']['end']['index']
        self.reject(lambda files: rewrite_trace(files, lambda lines: [line for index, line in enumerate(lines) if index != at]), '区间|中断')

    def test_markers_and_internal_unmatched_returns_are_rejected(self):
        self.reject(lambda files: files.update(trace=files['trace'].replace('guest_timer_end', 'unexpected')), '窗口')
        rows, _ = guest.parse(self.files)
        calls, _ = guest.pair_nested(rows, 'local_timer_entry', 'local_timer_exit', lambda row: guest.field(row, 'vector'))
        at = next(call['start']['index'] for call in calls if call['start']['index'] > 1000)
        self.reject(lambda files: rewrite_trace(files, lambda lines: [line for index, line in enumerate(lines) if index != at]), '内部返回')

    def test_app_duplicates_wrong_pid_and_bad_interval_are_rejected(self):
        line = next(line for line in self.log.splitlines() if line.startswith('TIMER_INTERVAL'))
        changes = [self.log.replace(line, line + '\n' + line, 1),
                   self.log.replace(line, line.replace('pid=189', 'pid=1000'), 1),
                   self.log.replace(line, re.sub(r'after_ns=\d+', 'after_ns=1', line), 1),
                   self.log + '\nCLOCK_ERROR operation=extra\n']
        for log in changes:
            with self.subTest(change=log[-80:]), self.assertRaises(ValueError):
                guest.inspect(self.files, log)

    def test_irq_prefix_suffix_and_nesting_have_no_fabricated_durations(self):
        def row(index, name, vector='236'):
            return {'cpu': 0, 'pid': 0, 'index': index, 'ns': index * 1000,
                    'name': name, 'detail': 'vector=' + vector}
        rows = [row(0, 'leave'), row(1, 'entry'), row(2, 'entry', '237'),
                row(3, 'leave', '237'), row(4, 'leave'), row(5, 'entry')]
        calls, boundaries = guest.pair_nested(rows, 'entry', 'leave', lambda item: guest.field(item, 'vector'))
        self.assertEqual([call['duration_ns'] for call in calls], [1000, 3000])
        self.assertEqual(boundaries, {'prefix': [rows[0]], 'suffix': [rows[5]]})
        with self.assertRaises(ValueError):
            guest.pair_nested(rows + [row(6, 'leave', '237')], 'entry', 'leave', lambda item: guest.field(item, 'vector'))

    def test_clock_pass_does_not_override_the_original_timer_gate(self):
        last = self.pair['timer_analysis']['timers'][-1]
        before, old_after = last['before_ns'], last['after_ns']
        elapsed = 300_000_000
        log = self.log.replace(f'before_ns={before} after_ns={old_after}',
                               f'before_ns={before} after_ns={before + elapsed}')
        old = f'CLOCK_TIMER cpu={last["cpu"]} requested_ns=20000000 elapsed_ns={last["elapsed_ns"]}'
        log = log.replace(old, f'CLOCK_TIMER cpu={last["cpu"]} requested_ns=20000000 elapsed_ns={elapsed}')
        result = guest.inspect(self.files, log)
        self.assertFalse(result['timer_gate_passed'])
        self.assertEqual(result['timer_gate_ns'], 250_000_000)
        self.assertFalse(result['full_ssi_accepted'])

    def test_restore_keeps_both_stock_boots_and_cleans_experiment_state(self):
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)
        for node in self.evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged',
                        'firewall_matches_original', 'stock_grub_default'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])
            self.assertEqual(node['grub_environment'], '')

    def test_archive_never_extracts_links_paths_or_duplicates(self):
        for names in (['../outside'], ['trace', 'trace'], ['trace-link']):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / 'unsafe.tar.gz'
                with tarfile.open(archive, 'w:gz') as out:
                    for name in names:
                        info = tarfile.TarInfo(name)
                        info.size = 1
                        if name == 'trace-link':
                            info.type = tarfile.SYMTYPE
                            info.linkname = '/etc/passwd'
                            info.size = 0
                        out.addfile(info, io.BytesIO(b'x'))
                with self.assertRaises(ValueError):
                    guest.read_archive(archive)

    def test_operations_close_warnings_and_failed_instrumentation_stay_visible(self):
        close, stress = guest.load('check-qemu-close'), guest.load('check-stress')
        runs = [*self.evidence['runs'], self.evidence['earlier_without_intervals'], self.evidence['rejected_instrumentation']]
        for run in runs:
            result = run['result']
            for phase in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(result['phases'][phase]['exit'], 0)
            self.assertEqual(result['qemu_ssh_exits'], [0, 0] if result['mode'] == 'pair' else [0])
            self.assertTrue(result['sftp_matches'])
            self.assertEqual(run['firewall']['before'], run['firewall']['after'])
            stress.validate(run['files']['stress'])
            gate = run['clock_gate']
            self.assertEqual(gate['limit_ns'], 250_000_000)
            trials = re.findall(r'CLOCK_START[^\n]*\n.*?CLOCK_PASS[^\n]*', run['files']['clock'], re.S)
            self.assertEqual(len(trials), len(gate['trials']))
            for trial, expected in zip(trials, gate['trials']):
                if expected['passed']:
                    guest.clock.validate(trial, gate['limit_ns'])
                else:
                    with self.assertRaisesRegex(ValueError, '超过'):
                        guest.clock.validate(trial, gate['limit_ns'])
            self.assertEqual(gate['passed'], all(row['passed'] for row in gate['trials']))
            self.assertIn('reboot: Power down', run['serial_log'])
            if result['mode'] == 'pair':
                self.assertEqual(close.inspect(run), run['close_analysis'])
                self.assertIn('hogged CPU', run['serial_log'])
            self.assertFalse(run['full_ssi_accepted'])
        self.assertIn('skipping watchdog check', self.pair['serial_log'])
        self.assertNotRegex(self.control['serial_log'], r'hogged CPU|skipping watchdog check')
        rejected = self.evidence['rejected_instrumentation']
        self.assertFalse(rejected['accepted_for_attribution'])
        self.assertFalse(rejected['clock_gate']['passed'])
        self.assertEqual(rejected['clock_gate']['maximum_elapsed_ns'], 390_604_637)
        self.assertTrue(any(int(line.split()[2]) > 0 for line in rejected['profile_after'].splitlines()))
        prior = json.loads((ROOT / self.evidence['prior_445ms_failure_preserved_at']).read_text())
        self.assertFalse(prior['full_ssi_accepted'])

    def test_probe_build_and_capture_syntax(self):
        self.assertEqual(hashlib.sha256((HERE / 'guest-clock.c').read_bytes()).hexdigest(),
                         self.evidence['probe_build']['source_sha256'])
        subprocess.run(['sh', '-n', str(HERE / 'trace-guest-timers.sh')], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
