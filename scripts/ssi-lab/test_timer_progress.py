"""验证定时器空档的归因边界，不能用合成退出记录冒充硬件修复。"""
import importlib.util
import hashlib
import json
from pathlib import Path
import unittest

from test_vcpu_residency import capture

spec = importlib.util.spec_from_file_location('progress', Path(__file__).with_name('check-timer-progress.py'))
progress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(progress)


class TimerProgressTests(unittest.TestCase):
    def test_saved_summary_links_to_the_original_complete_traces(self):
        root = Path(__file__).resolve().parents[2]
        directory = root / 'docs/evidence'
        data = json.loads((directory / 'ssi-timer-progress-20261106.json').read_text())
        original = json.loads((directory / 'ssi-vcpu-residency-20261106.json').read_text())
        self.assertEqual(data['source_sha256'], hashlib.sha256(Path(progress.__file__).read_bytes()).hexdigest())
        self.assertEqual(len(data['runs']), 4)
        self.assertEqual(len({(run['label'], run['node']) for run in data['runs']}), 4)
        for run in data['runs']:
            before = next(item for item in original['runs'] if item['label'] == run['label'])
            trace = next(item for item in before['traces'] if item['node'] == run['node'])
            self.assertIsNone(trace['analysis_error'])
            self.assertEqual(run['raw_sha256'], trace['raw_sha256'])
            self.assertEqual(run['events'], trace['summary']['events'])
            self.assertEqual({window['cpu'] for window in run['timer_windows']}, set(run['cpus']))
            for window in run['timer_windows']:
                self.assertEqual(window['duration_ns'], window['timer_end']['ns'] - window['timer_start']['ns'])
                self.assertEqual(window['duration_ns'], trace['summary']['timer_intervals'][str(window['cpu'])]['max_ns'])
                self.assertEqual(window['interior_events'], sum(window['event_counts'].values()))
                self.assertEqual(window['event_counts'].get('kvm_exit', 0), sum(window['exit_reasons'].values()))
                self.assertEqual(window['max_observed_event_gap_ns'], window['max_gap_end']['ns'] - window['max_gap_start']['ns'])
                for key in ('max_gap_start', 'max_gap_end', 'first_interior_event', 'last_interior_event'):
                    event = window[key]
                    if event is not None:
                        self.assertEqual(event['cpu'], window['cpu'])
                        self.assertLessEqual(window['timer_start']['ns'], event['ns'])
                        self.assertLessEqual(event['ns'], window['timer_end']['ns'])

    def test_short_exits_do_not_erase_timer_silence(self):
        data = capture([
            (1, 0, 'local_timer_entry', 'vector=236'),
            (2, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
            (3, 0, 'kvm_exit', 'vcpu 0 reason PAUSE_INSTRUCTION'),
            (4, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
            (5, 0, 'kvm_exit', 'vcpu 0 reason PAUSE_INSTRUCTION'),
            (6, 0, 'local_timer_entry', 'vector=236'),
        ])
        window = progress.inspect(data)['timer_windows'][0]
        self.assertEqual(window['duration_ns'], 5000000000)
        self.assertEqual(window['max_observed_event_gap_ns'], 1000000000)
        self.assertEqual(window['interior_events'], 4)
        self.assertEqual(window['exit_reasons'], {'PAUSE_INSTRUCTION': 2})
        self.assertNotIn('sched_switch', window['event_counts'])

    def test_other_cpu_activity_cannot_fill_a_silent_cpu(self):
        data = capture([
            (1, 0, 'local_timer_entry', 'vector=236'),
            (2, 1, 'local_timer_entry', 'vector=236'),
            (3, 1, 'irq_handler_entry', 'irq=59 name=network'),
            (4, 1, 'local_timer_entry', 'vector=236'),
            (6, 0, 'local_timer_entry', 'vector=236'),
        ])
        windows = progress.inspect(data)['timer_windows']
        self.assertEqual(len(windows), 2)
        self.assertEqual(windows[0]['interior_events'], 0)
        self.assertIsNone(windows[0]['first_interior_event'])
        self.assertEqual(windows[0]['max_observed_event_gap_ns'], 5000000000)
        self.assertEqual(windows[1]['event_counts'], {'irq_handler_entry': 1})

    def test_scheduler_and_irq_events_remain_visible(self):
        data = capture([
            (1, 0, 'local_timer_entry', 'vector=236'),
            (2, 0, 'local_timer_exit', 'vector=236'),
            (3, 0, 'sched_switch', 'prev_pid=10 next_pid=20 prev_state=S'),
            (3, 0, 'irq_handler_entry', 'irq=59 name=network'),
            (4, 0, 'local_timer_entry', 'vector=236'),
            (5, 0, 'local_timer_entry', 'vector=236'),
        ])
        windows = progress.inspect(data, limit=1)['timer_windows']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['event_counts'], {'local_timer_exit': 1, 'sched_switch': 1, 'irq_handler_entry': 1})
        self.assertEqual(windows[0]['exit_reasons'], {})
        self.assertEqual(windows[0]['max_gap_end']['ns'] - windows[0]['max_gap_start']['ns'], 1000000000)

    def test_open_boundaries_are_not_invented(self):
        data = capture([(1, 0, 'irq_handler_exit', 'irq=59 ret=handled'),
                        (2, 0, 'local_timer_entry', 'vector=236'),
                        (5, 0, 'irq_handler_entry', 'irq=59 name=network')])
        self.assertEqual(progress.inspect(data)['timer_windows'], [])

    def test_incomplete_or_inconsistent_evidence_is_rejected(self):
        data = capture([(1, 0, 'local_timer_entry', 'vector=236'),
                        (2, 0, 'local_timer_entry', 'vector=236')])
        data['trace_stats']['cpu0'] = 'overrun: 1\ncommit overrun: 0\ndropped events: 0\n'
        with self.assertRaisesRegex(ValueError, '丢失'):
            progress.inspect(data)
        data = capture([(1, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
                        (2, 0, 'kvm_entry', 'vcpu 0, rip 0x1')])
        with self.assertRaisesRegex(ValueError, '重复入口'):
            progress.inspect(data)
        with self.assertRaisesRegex(ValueError, '数量'):
            progress.inspect(data, limit=0)


if __name__ == '__main__':
    unittest.main()
