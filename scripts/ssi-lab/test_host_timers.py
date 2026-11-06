"""核查定时器重装分析的边界、时钟域和拒绝条件，不以合成数据替代运行证据。"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_vcpu_residency import capture

spec = importlib.util.spec_from_file_location('host_timers', Path(__file__).with_name('check-host-timers.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

trace_spec = importlib.util.spec_from_file_location('host_timer_trace', Path(__file__).with_name('trace-host-timers.py'))
tracer = importlib.util.module_from_spec(trace_spec)
trace_spec.loader.exec_module(tracer)


def recorded(rows):
    result = capture(rows)
    result['kprobe_profile'] = '\n'.join(f'{name} 100 0' for name in sorted(checker.PROBES))
    return result


def example():
    return recorded([
        (1, 0, 'local_timer_entry', 'vector=236'),
        (2, 0, 'local_timer_exit', 'vector=236'),
        (4, 0, 'ht_deferred', '(__hrtimer_rearm_deferred+0x4/0x160)'),
        (5, 0, 'hrtimer_rearm', 'next_event=12345 deferred=1'),
        (6, 0, 'ht_program', 'dev=0x123 expires=12345 force=1'),
        (7, 0, 'ht_lapic', 'delta=15 dev=0x123'),
        (8, 0, 'local_timer_entry', 'vector=236'),
        (9, 0, 'local_timer_exit', 'vector=236'),
    ])


class HostTimersTests(unittest.TestCase):
    def test_low_disk_space_is_rejected_before_capture_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist.json'
            with patch.object(tracer.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024 * 1024)):
                with self.assertRaisesRegex(ValueError, '空间不足'):
                    tracer.check_output_space(output, 2)
            self.assertFalse(output.exists())
            with patch.object(tracer.shutil, 'disk_usage', return_value=SimpleNamespace(free=2 * 1024**3)):
                report = tracer.check_output_space(output, 2)
            self.assertGreater(report['available_free_bytes'], report['required_free_bytes'])

    def test_delay_uses_trace_timestamps_and_matches_program_device(self):
        report = checker.inspect(example())['cpus']['0']
        self.assertEqual(report['complete_interrupts'], 2)
        self.assertEqual(report['after_irq_delay']['count'], 1)
        self.assertEqual(report['after_irq_delay']['max_ns'], 3000000000)
        longest = report['longest_rearms'][0]
        self.assertEqual(longest['program']['ns'], 6000000000)
        self.assertEqual(longest['lapic_programming_entry']['ns'], 7000000000)
        self.assertEqual(longest['window_omitted_events'], 0)
        self.assertEqual(len(longest['window_events']), 6)

    def test_wrong_device_or_expiry_is_not_paired(self):
        for old, new in [('delta=15 dev=0x123', 'delta=15 dev=0x456'),
                         ('expires=12345', 'expires=67890')]:
            result = example()
            result['trace'] = result['trace'].replace(old, new)
            longest = checker.inspect(result)['cpus']['0']['longest_rearms'][0]
            self.assertIsNone(longest['program'])
            self.assertIsNone(longest['lapic_programming_entry'])

    def test_rearm_during_interrupt_is_not_post_exit_delay(self):
        result = recorded([
            (1, 0, 'local_timer_entry', 'vector=236'),
            (2, 0, 'hrtimer_rearm', 'next_event=42 deferred=0'),
            (3, 0, 'local_timer_exit', 'vector=236'),
            (8, 0, 'hrtimer_rearm', 'next_event=88 deferred=1'),
        ])
        report = checker.inspect(result)['cpus']['0']
        self.assertEqual(report['after_irq_delay']['count'], 0)
        self.assertEqual(report['unpaired_rearm'], {'rearmed_inside_interrupt': 1})

    def test_new_interrupt_and_other_cpu_do_not_supply_missing_rearm(self):
        result = recorded([
            (1, 0, 'local_timer_entry', 'vector=236'),
            (2, 0, 'local_timer_exit', 'vector=236'),
            (3, 1, 'hrtimer_rearm', 'next_event=42 deferred=1'),
            (4, 0, 'local_timer_entry', 'vector=236'),
            (5, 0, 'local_timer_exit', 'vector=236'),
            (6, 0, 'hrtimer_rearm', 'next_event=88 deferred=1'),
        ])
        report = checker.inspect(result)['cpus']['0']
        self.assertEqual(report['after_irq_delay']['count'], 1)
        self.assertEqual(report['after_irq_delay']['max_ns'], 1000000000)
        self.assertEqual(report['unpaired_rearm'], {'no_rearm_before_next_interrupt_or_boundary': 1})

    def test_boundary_interrupts_are_censored_and_internal_gaps_fail(self):
        result = recorded([(1, 0, 'local_timer_exit', 'vector=236'),
                           (3, 0, 'local_timer_entry', 'vector=236')])
        self.assertEqual(checker.inspect(result)['cpus']['0']['boundary_interrupts'], 2)
        for name in ('local_timer_entry', 'local_timer_exit'):
            result = recorded([(1, 0, name, 'vector=236'), (2, 0, name, 'vector=236')])
            with self.assertRaises(ValueError):
                checker.inspect(result)

    def test_probe_omission_and_trace_loss_are_rejected(self):
        for profile in ('ht_program 100 1\nht_lapic 100 0\nht_deferred 100 0',
                        'ht_program 100 0\nht_lapic 100 0',
                        'ht_program 0 0\nht_lapic 100 0\nht_deferred 100 0'):
            result = example()
            result['kprobe_profile'] = profile
            with self.assertRaises(ValueError):
                checker.inspect(result)
        result = example()
        result['trace_stats']['cpu0'] = 'overrun: 1\ncommit overrun: 0\ndropped events: 0\n'
        with self.assertRaisesRegex(ValueError, '丢失'):
            checker.inspect(result)

    def test_capture_refuses_wrong_kernel_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('trace-host-timers.py')),
                                     '--attach-pid', '1', '--node', '0', '--require-kernel', 'kernel-must-not-match',
                                     '--output', str(output)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
