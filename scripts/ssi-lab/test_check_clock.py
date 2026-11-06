"""用真实客体记录校验时钟证据，并拒绝缺样本、倒退和提前到期。"""
import importlib.util
from pathlib import Path
import re
import unittest

directory = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('check_clock', directory / 'check-clock.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
control = (directory.parents[1] / 'docs/evidence/ssi-clock-control-20261105.txt').read_text()


class CheckClockTest(unittest.TestCase):
    def test_pause_rounds_keep_prior_samples_and_require_all_waits(self):
        interactive = control
        for round_number in range(1, 8):
            marker = f'CLOCK_SAMPLE round={round_number} cpu=0 '
            interactive = interactive.replace(marker, f'CLOCK_WAIT round={round_number}\n' + marker)
        checker.validate(interactive, max_timer_ns=250_000_000, pause_rounds=True)
        with self.assertRaises(ValueError):
            checker.validate(interactive)
        invalid = (
            interactive.replace('CLOCK_WAIT round=3\n', ''),
            interactive.replace('CLOCK_WAIT round=3', 'CLOCK_WAIT round=4'),
            re.sub(r'(CLOCK_SAMPLE round=1 cpu=0 tsc=)\d+', r'\g<1>1', interactive),
        )
        for log in invalid:
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.validate(log, pause_rounds=True)

    def test_accepts_real_single_node_control(self):
        checker.validate(control)

    def test_timer_budget_distinguishes_real_control_and_delayed_pair(self):
        checker.validate(control, max_timer_ns=250_000_000)
        evidence = directory.parents[1] / 'docs/evidence/ssi-pvclock-workspace-20261106.txt'
        with self.assertRaisesRegex(ValueError, '超过'):
            checker.validate(evidence.read_text(), max_timer_ns=250_000_000)

    def test_rejects_impossible_timer_budget(self):
        with self.assertRaises(ValueError):
            checker.validate(control, max_timer_ns=19_000_000)

    def test_accepts_bounded_candidate_samples_without_claiming_boot_pass(self):
        evidence = directory.parents[1] / 'docs/evidence/ssi-clock-offset-20261105.txt'
        checker.validate(evidence.read_text())

    def test_rejects_recorded_cross_node_backstep(self):
        evidence = directory.parents[1] / 'docs/evidence/ssi-clock-baseline-20261105.txt'
        with self.assertRaises(ValueError):
            checker.validate(evidence.read_text())

    def test_rejects_incomplete_combined_or_wrong_cpu_records(self):
        sample = next(line for line in control.splitlines(True) if line.startswith('CLOCK_SAMPLE'))
        invalid = (
            control.replace(sample, '', 1),
            control + control,
            control.replace('round=0 cpu=2', 'round=0 cpu=0', 1),
            control.replace('online_cpus=4', 'online_cpus=2', 1),
            control.replace('CLOCK_PASS', 'CLOCK_ERROR', 1),
        )
        for log in invalid:
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.validate(log)

    def test_rejects_each_counter_going_backwards(self):
        for field in ('tsc', 'mono', 'raw', 'boot'):
            log = re.sub(r'(CLOCK_SAMPLE round=0 cpu=2[^\n]*\b' + field + r'=)\d+',
                         r'\g<1>1', control, count=1)
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.validate(log)

    def test_rejects_early_or_misassigned_timer(self):
        early = re.sub(r'(CLOCK_TIMER cpu=0 requested_ns=20000000 elapsed_ns=)\d+',
                       r'\g<1>19999999', control, count=1)
        wrong_cpu = control.replace('CLOCK_TIMER cpu=0', 'CLOCK_TIMER cpu=2', 1)
        for log in (early, wrong_cpu):
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.validate(log)


if __name__ == '__main__':
    unittest.main()
