"""日历合法不能替代正确时间，失败样本不能被成功标记覆盖。"""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rtc_check', Path(__file__).with_name('check-rtc.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def example():
    base = int(datetime(2026, 11, 6, 6, 0, 0, tzinfo=timezone.utc).timestamp()) * 1000000000
    reference = {'mode': 'pair', 'started_realtime_ns': base,
                 'finished_realtime_ns': base + 10 * 1000000000,
                 'host_clock_samples': [
                     {'node': node, 'controller_before_ns': base + 1000000000,
                      'controller_after_ns': base + 2000000000,
                      'host_realtime_ns': base + 1500000000} for node in (0, 1)]}
    lines = ['RTCPROBE_START cpus=4 rounds=8']
    for round_number in range(8):
        for cpu in (0, 2, 1, 3):
            lines.append(f'RTCPROBE_READ round={round_number} cpu={cpu} observed_cpu={cpu} status=0 errno=0 '
                         f'year=2026 month=11 day=6 hour=6 minute=0 second={round_number}')
    lines += ['RTCPROBE_RESULT reads=32 failures=0', 'RTCPROBE_EXIT status=0']
    return '\n'.join(lines), reference


class RtcTests(unittest.TestCase):
    def test_complete_record_agrees_with_independent_host_window(self):
        log, reference = example()
        report = checker.inspect(log, reference)
        self.assertEqual(report['reads'], 32)
        self.assertEqual(report['failures'], 0)

    def test_successful_ioctl_with_legal_wrong_date_is_rejected(self):
        log, reference = example()
        lines = log.splitlines()
        for index in range(1, 33):
            if 'cpu=2 ' in lines[index] or 'cpu=3 ' in lines[index]:
                lines[index] = lines[index].replace('year=2026 month=11 day=6 hour=6 minute=0',
                                                   'year=2004 month=4 day=4 hour=4 minute=4')
        report = checker.inspect('\n'.join(lines), reference)
        self.assertEqual(report['calendar_failures'], 0)
        self.assertEqual(report['reference_failures'], 16)
        self.assertEqual(report['failures_by_cpu'], {'2': 8, '3': 8})
        self.assertEqual(report['failures'], 16)

    def test_ioctl_failure_is_counted_once_even_with_invalid_calendar(self):
        log, reference = example()
        log = log.replace('status=0 errno=0 year=2026 month=11 day=6',
                          'status=-1 errno=22 year=1900 month=1 day=0', 1)
        log = log.replace('reads=32 failures=0', 'reads=32 failures=1').replace('RTCPROBE_EXIT status=0',
                                                                               'RTCPROBE_EXIT status=1')
        report = checker.inspect(log, reference)
        self.assertEqual((report['failures'], report['calendar_failures'], report['reference_failures']), (1, 1, 0))

    def test_valid_field_ranges_do_not_hide_impossible_calendar_date(self):
        log, reference = example()
        log = log.replace('month=11 day=6', 'month=2 day=31', 1)
        report = checker.inspect(log, reference)
        self.assertEqual(report['probe_range_failures'], 0)
        self.assertEqual(report['calendar_failures'], 1)
        self.assertEqual(report['failures'], 1)

    def test_missing_repeated_or_mislabelled_samples_are_rejected(self):
        log, reference = example()
        lines = log.splitlines()
        bad_logs = ['\n'.join(lines[:2] + lines[3:]),
                    '\n'.join(lines[:2] + [lines[1]] + lines[3:]),
                    log.replace('cpu=2 observed_cpu=2', 'cpu=2 observed_cpu=0', 1),
                    log.replace('status=0 errno=0', 'status=0 errno=5', 1),
                    log.replace('reads=32 failures=0', 'reads=32 failures=1')]
        for bad in bad_logs:
            with self.assertRaises(ValueError):
                checker.inspect(bad, reference)

    def test_bad_reference_cannot_make_an_incorrect_rtc_pass(self):
        log, reference = example()
        for change in ('missing_node', 'duplicate_node', 'clock_skew', 'time_reversed', 'excessive_window'):
            bad = deepcopy(reference)
            if change == 'missing_node':
                bad['host_clock_samples'].pop()
            elif change == 'duplicate_node':
                bad['host_clock_samples'][1]['node'] = 0
            elif change == 'clock_skew':
                bad['host_clock_samples'][0]['host_realtime_ns'] += 20 * 1000000000
            elif change == 'time_reversed':
                bad['finished_realtime_ns'] = bad['started_realtime_ns'] - 1
            else:
                bad['finished_realtime_ns'] += 1000 * 1000000000
            with self.assertRaises(ValueError):
                checker.inspect(log, bad)


if __name__ == '__main__':
    unittest.main()
