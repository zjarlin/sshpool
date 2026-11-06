"""验证 KVM 区间和计时观测的拒绝条件；合成事件不代表真实硬件通过。"""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('check-vcpu-residency.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def capture(rows):
    task = {'comm': 'CPU 0/KVM', 'stat': '10 (CPU 0/KVM) S ' + '0 ' * 18 + '42 0'}
    lines = [f' CPU 0/KVM-10 [{cpu:03}] d.... {stamp}.000000: {name}: {detail}'
             for stamp, cpu, name, detail in rows]
    return {'exit': 0, 'errors': [], 'trace_cleanup_complete': True,
            'tasks_before': {'10': copy.deepcopy(task)}, 'tasks_after': {'10': copy.deepcopy(task)},
            'trace': f'# entries-in-buffer/entries-written: {len(rows)}/{len(rows)}\n' + '\n'.join(lines),
            'trace_stats': {f'cpu{cpu}': 'overrun: 0\ncommit overrun: 0\ndropped events: 0\n' for cpu in (0, 1)},
            'trace_clock': 'local [global] counter', 'capture_started_ns': 1, 'capture_stopped_ns': 10000000000,
            'heartbeats': [{'monotonic_ns': 100, 'raw_ns': 50}, {'monotonic_ns': 200, 'raw_ns': 150}]}


def example():
    return capture([(1, 0, 'local_timer_entry', 'vector=236'),
                    (2, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
                    (3, 0, 'kvm_wait_lapic_expire', 'vcpu 0: delta 2 (late)'),
                    (4, 1, 'sched_wakeup', 'pid=20 target_cpu=000'),
                    (5, 0, 'kvm_exit', 'vcpu 0 reason EXTERNAL_INTERRUPT rip 0x2'),
                    (6, 0, 'local_timer_entry', 'vector=236')])


class ResidencyTests(unittest.TestCase):
    def test_wrong_kernel_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('trace-vcpu-residency.py')),
                                     '--attach-pid', '1', '--node', '0', '--require-kernel', 'kernel-must-not-match',
                                     '--output', str(output)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_kvm_and_timer_intervals_are_not_confused(self):
        report, _ = checker.inspect(example())
        self.assertEqual(report['kvm_intervals']['max_ns'], 3000000000)
        self.assertEqual(report['timer_intervals']['0']['max_ns'], 5000000000)
        longest = report['longest_kvm_intervals'][0]
        self.assertEqual(len(longest['lapic_events']), 1)
        self.assertEqual(len(longest['targeted_wakeups']), 1)
        self.assertEqual(longest['cpu_events'], [])

    def test_boundary_calls_are_censored_and_internal_missing_calls_fail(self):
        data = capture([(1, 0, 'kvm_exit', 'vcpu 0 reason HLT'),
                        (2, 0, 'kvm_entry', 'vcpu 0, rip 0x1')])
        report, _ = checker.inspect(data)
        self.assertEqual(report['boundary_censored_runs'], 2)
        self.assertEqual(report['kvm_intervals']['count'], 0)
        data['trace'] = data['trace'].replace('kvm_entry: vcpu 0, rip 0x1', 'kvm_exit: vcpu 0 reason HLT')
        with self.assertRaisesRegex(ValueError, '窗口内部'):
            checker.inspect(data)

    def test_duplicate_entries_fail(self):
        data = capture([(1, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
                        (2, 0, 'kvm_entry', 'vcpu 0, rip 0x2')])
        with self.assertRaisesRegex(ValueError, '重复入口'):
            checker.inspect(data)

    def test_cpu_or_vcpu_mismatch_fails(self):
        for cpu, vcpu, expected in [(1, 0, 'CPU 迁移'), (0, 1, 'vCPU 编号')]:
            data = capture([(1, 0, 'kvm_entry', 'vcpu 0, rip 0x1'),
                            (2, cpu, 'kvm_exit', f'vcpu {vcpu} reason HLT')])
            with self.assertRaisesRegex(ValueError, expected):
                checker.inspect(data)

    def test_losses_and_missing_header_fail(self):
        for key in ('overrun', 'commit overrun', 'dropped events'):
            data = example()
            data['trace_stats']['cpu0'] = data['trace_stats']['cpu0'].replace(key + ': 0', key + ': 1')
            with self.assertRaisesRegex(ValueError, '丢失'):
                checker.inspect(data)
        for transform in (lambda text: text.replace('6/6', '6/7'), lambda text: text.split('\n', 1)[1]):
            data = example()
            data['trace'] = transform(data['trace'])
            with self.assertRaisesRegex(ValueError, '计数'):
                checker.inspect(data)

    def test_padded_cpu_numbers_and_untracked_switches(self):
        data = capture([(1, 1, 'kvm_entry', 'vcpu 0, rip 0x1'),
                        (2, 0, 'sched_wakeup', 'pid=20 target_cpu=001'),
                        (3, 0, 'sched_switch', 'prev_pid=40 next_pid=50 prev_state=S'),
                        (4, 1, 'kvm_exit', 'vcpu 0 reason HLT')])
        report, _ = checker.inspect(data)
        self.assertEqual(len(report['longest_kvm_intervals'][0]['targeted_wakeups']), 1)
        self.assertEqual(report['runnable_waits']['count'], 0)

    def test_missing_cpu_counters_fail(self):
        data = example()
        del data['trace_stats']['cpu1']
        with self.assertRaisesRegex(ValueError, '计数不完整'):
            checker.inspect(data)

    def test_runnable_waits_do_not_extend_to_unknown_boundary(self):
        data = capture([(1, 0, 'sched_wakeup', 'pid=10 target_cpu=000'),
                        (2, 0, 'sched_wakeup', 'pid=10 target_cpu=000'),
                        (4, 0, 'sched_switch', 'prev_pid=20 next_pid=10 prev_state=S'),
                        (5, 0, 'sched_switch', 'prev_pid=10 next_pid=20 prev_state=R'),
                        (6, 1, 'local_timer_entry', 'vector=236')])
        report, _ = checker.inspect(data)
        self.assertEqual(report['runnable_waits']['count'], 1)
        self.assertEqual(report['runnable_waits']['max_ns'], 3000000000)

    def test_pid_reuse_or_foreign_kvm_event_fails(self):
        data = example()
        data['tasks_after']['10']['stat'] = data['tasks_after']['10']['stat'].replace('42 0', '43 0')
        with self.assertRaisesRegex(ValueError, '复用'):
            checker.inspect(data)
        data = example()
        data['trace'] = data['trace'].replace('KVM-10', 'KVM-99')
        with self.assertRaisesRegex(ValueError, '目标 vCPU'):
            checker.inspect(data)

    def test_clocks_and_capture_boundaries_fail_closed(self):
        for key, value in [('trace_clock', '[local] global'), ('capture_stopped_ns', 150)]:
            data = example()
            data[key] = value
            with self.assertRaises(ValueError):
                checker.inspect(data)
        data = example()
        data['trace'] = data['trace'].replace('6.000000', '3.000000')
        with self.assertRaisesRegex(ValueError, '倒退'):
            checker.inspect(data)
        for clock in ('monotonic_ns', 'raw_ns'):
            data = example()
            data['heartbeats'][1][clock] = data['heartbeats'][0][clock]
            with self.assertRaisesRegex(ValueError, '倒退'):
                checker.inspect(data)

    def test_incomplete_capture_and_disappearing_task_fail(self):
        for key, value in [('exit', 1), ('errors', ['failure']), ('trace_cleanup_complete', False)]:
            data = example()
            data[key] = value
            with self.assertRaisesRegex(ValueError, '未完成'):
                checker.inspect(data)
        data = example()
        data['tasks_after'].clear()
        with self.assertRaisesRegex(ValueError, '线程集合'):
            checker.inspect(data)


if __name__ == '__main__':
    unittest.main()
