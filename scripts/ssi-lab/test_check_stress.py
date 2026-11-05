"""用真实单节点日志验证检查器，再破坏记录检查误报防护。"""
import importlib.util
from pathlib import Path
import unittest

directory = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('check_stress', directory / 'check-stress.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
control = (directory.parents[1] / 'docs/evidence/ssi-stress-control-20261105.txt').read_text()


class CheckStressTest(unittest.TestCase):
    def test_accepts_real_complete_control(self):
        checker.validate(control)

    def test_accepts_real_two_node_record(self):
        log = (directory.parents[1] / 'docs/evidence/ssi-stress-20261105.txt').read_text()
        checker.validate(log)

    def test_accepts_known_printk_insert_without_losing_fields(self):
        diagnostic = '[  228.094020] workqueue: pm_runtime_work hogged CPU for >10000us 4 times, consider switching to WQ_UNBOUND\n'
        interleaved = control.replace('STRESS_ROUND allocation=1', 'STRESS_ROUND all' + diagnostic + 'ocation=1', 1)
        checker.validate(interleaved)
        with self.assertRaises(ValueError):
            checker.validate(interleaved.replace('ocation=1', 'ocation=', 1))

    def test_rejects_incomplete_or_conflicting_evidence(self):
        lines = control.splitlines(True)
        round_line = next(line for line in lines if line.startswith('STRESS_ROUND'))
        pass_line = next(line for line in lines if line.startswith('STRESS_PASS'))
        invalid_logs = {
            '缺轮次': control.replace(round_line, '', 1),
            '重复轮次': control.replace(round_line, round_line * 2, 1),
            '错误计数': control.replace('counter=512', 'counter=511', 1),
            '跨 PID': control.replace('pid=1 tid=', 'pid=2 tid=', 1),
            '错误亲和性': control.replace('observed_cpu=2', 'observed_cpu=0', 1),
            '缺远端 CPU': control.replace('requested_cpu=3', 'requested_cpu=1', 1),
            '半次分配': '\n'.join(line for line in control.splitlines() if 'allocation=1' not in line),
            '双次通过': control + pass_line,
            '中途错误': control + 'STRESS_ERROR corruption\n',
            '非零退出': control.replace('STRESS_EXIT status=0', 'STRESS_EXIT status=1'),
            '无退出': control.replace('STRESS_EXIT status=0', ''),
        }
        for reason, log in invalid_logs.items():
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                checker.validate(log)


if __name__ == '__main__':
    unittest.main()
