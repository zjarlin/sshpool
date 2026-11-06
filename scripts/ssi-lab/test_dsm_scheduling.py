"""拒绝丢失、身份错配与倒退记录，并验证等待分解不会外推未知的窗口边界。"""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('scheduling', Path(__file__).with_name('check-dsm-scheduling.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
spec = importlib.util.spec_from_file_location('capture_scheduling', Path(__file__).with_name('trace-dsm-scheduling.py'))
tracer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tracer)


def capture(rows):
    # 合成记录只验证分析器的语义，不作为硬件实验通过的证据。
    task = {'comm': 'dsm-conn/0:1', 'stat': '10 (dsm-conn/0:1) S ' + '0 ' * 18 + '42 0'}
    events = [f' dsm-conn/0:1-10 [000] ..... {stamp}.000000: {name}: {detail}'
              for stamp, name, detail in rows]
    return {'exit': 0, 'errors': [], 'trace_cleanup_complete': True,
            'tasks_before': {'10': copy.deepcopy(task)}, 'tasks_after': {'10': copy.deepcopy(task)},
            'trace': f'# entries-in-buffer/entries-written: {len(rows)}/{len(rows)}\n' + '\n'.join(events),
            'trace_stats': {'cpu0': 'overrun: 0\ncommit overrun: 0\ndropped events: 0\n'},
            'kprobe_profile': '\n'.join(f'{name} 100 0' for name in sorted(set(checker.PAIRS) | set(checker.PAIRS.values()))),
            'trace_clock': 'local [global] counter', 'capture_started_ns': 1, 'capture_stopped_ns': 10000000000,
            'heartbeats': [{'monotonic_ns': 100}, {'monotonic_ns': 200}]}


def example():
    return capture([(1, 'sc_tcp', 'length=4096'),
                    (2, 'sched_switch', 'prev_pid=10 next_pid=20 prev_state=D'),
                    (4, 'sched_wakeup', 'pid=10 target_cpu=0'),
                    (5, 'sched_migrate_task', 'pid=10 orig_cpu=0 dest_cpu=1'),
                    (6, 'sched_switch', 'prev_pid=20 next_pid=10 prev_state=R'),
                    (7, 'sc_tcp_done', 'code=4096')])


class SchedulingTests(unittest.TestCase):
    def test_wrong_kernel_refuses_before_opening_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('trace-dsm-scheduling.py')),
                                     '--attach-pid', '1', '--node', '0', '--require-kernel', 'kernel-must-not-match',
                                     '--output', str(output)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_large_trace_export_is_bounded_and_preserves_escaping(self):
        class BoundedReader(io.StringIO):
            def read(self, size=-1):
                if not 0 < size <= 65536:
                    raise AssertionError('不允许无界读取整个跟踪文件')
                return super().read(size)
        content = 'x' * 65535 + '\n"\\\x00调度🧪' + 'y' * 150000
        output = io.StringIO()
        tracer.write_json_text(output, BoundedReader(content))
        self.assertEqual(json.loads(output.getvalue()), content)

    def test_sleep_ready_scheduled_and_unknown_are_distinct(self):
        report, calls, _ = checker.inspect(example())
        self.assertEqual(calls[0]['duration_ns'], 6000000000)
        self.assertEqual(report['longest_calls'][0]['scheduling_ns'],
                         {'unknown': 1000000000, 'sleep:D': 2000000000,
                          'runnable': 2000000000, 'scheduled': 1000000000})
        self.assertEqual(report['runnable_waits']['max_ns'], 2000000000)

    def test_boundary_calls_are_censored_but_internal_missing_entries_fail(self):
        data = capture([(1, 'sc_tcp_done', 'code=0'), (2, 'sc_tcp', 'length=8')])
        report, calls, _ = checker.inspect(data)
        self.assertEqual(report['boundary_censored_calls'], 2)
        self.assertEqual(calls, [])
        data['trace'] = data['trace'].replace('sc_tcp: length=8', 'sc_tcp_done: code=0')
        with self.assertRaisesRegex(ValueError, '窗口内部'):
            checker.inspect(data)

    def test_repeated_entry_cannot_hide_missing_return(self):
        data = capture([(1, 'sc_tcp', 'length=8'), (2, 'sc_tcp', 'length=8')])
        with self.assertRaisesRegex(ValueError, '入口重复'):
            checker.inspect(data)

    def test_no_extrapolation_before_or_after_saved_events(self):
        _, _, states = checker.inspect(example())
        self.assertEqual(checker.partition(states[10], 0, 9000000000),
                         {'unknown': 4000000000, 'sleep:D': 2000000000,
                          'runnable': 2000000000, 'scheduled': 1000000000})

    def test_duplicate_wakeups_do_not_shorten_ready_wait(self):
        data = capture([(1, 'sched_wakeup', 'pid=10'), (2, 'sched_wakeup', 'pid=10'),
                        (4, 'sched_switch', 'prev_pid=20 next_pid=10 prev_state=R'),
                        (5, 'sc_access', 'access=1')])
        report, _, _ = checker.inspect(data)
        self.assertEqual(report['runnable_waits']['max_ns'], 3000000000)

    def test_losses_and_missing_headers_are_rejected(self):
        for key in ('overrun', 'commit overrun', 'dropped events'):
            data = example()
            data['trace_stats']['cpu0'] = data['trace_stats']['cpu0'].replace(key + ': 0', key + ': 1')
            with self.assertRaisesRegex(ValueError, '丢失'):
                checker.inspect(data)
        for transform in (lambda s: s.replace('6/6', '6/7'), lambda s: s.split('\n', 1)[1]):
            data = example()
            data['trace'] = transform(data['trace'])
            with self.assertRaisesRegex(ValueError, '计数'):
                checker.inspect(data)

    def test_pid_reuse_and_foreign_tasks_fail(self):
        data = example()
        data['tasks_after']['10']['stat'] = data['tasks_after']['10']['stat'].replace('42 0', '43 0')
        with self.assertRaisesRegex(ValueError, '复用'):
            checker.inspect(data)
        data = example()
        data['trace'] = data['trace'].replace('pid=10 target_cpu', 'pid=99 target_cpu')
        with self.assertRaisesRegex(ValueError, '唤醒事件'):
            checker.inspect(data)

    def test_clocks_and_capture_boundaries_fail_closed(self):
        for key, value in [('trace_clock', '[local] global'), ('capture_stopped_ns', 150)]:
            data = example()
            data[key] = value
            with self.assertRaises(ValueError):
                checker.inspect(data)
        data = example()
        data['trace'] = data['trace'].replace('7.000000', '3.000000')
        with self.assertRaisesRegex(ValueError, '倒退'):
            checker.inspect(data)

    def test_probe_misses_and_disappearing_tasks_fail(self):
        data = example()
        data['kprobe_profile'] = data['kprobe_profile'].replace('100 0', '100 1', 1)
        with self.assertRaisesRegex(ValueError, '遗漏'):
            checker.inspect(data)
        data = example()
        data['tasks_after'].clear()
        with self.assertRaisesRegex(ValueError, '线程集合'):
            checker.inspect(data)


if __name__ == '__main__':
    unittest.main()
