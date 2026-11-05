"""损坏或混合生命周期的性能记录不能产生误导性汇总。"""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('summary', Path(__file__).with_name('summarize-profile.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def recording():
    records = [{'op': 'start', 'kernel': 'test', 'schedstats': '0'}]
    for timestamp, cpu in [(1_000_000_000, 5_000_000_000), (11_000_000_000, 7_000_000_000)]:
        records.append({'op': 'sample', 'monotonic_ns': timestamp, 'disappeared': [],
                        'tasks': [{'tid': 10, 'start_ticks': 20, 'comm': 'dsm-conn/0:0',
                                   'runtime_ns': cpu, 'stack': []}]})
    records.append({'op': 'complete', 'samples': 2})
    return records


class ProfileTests(unittest.TestCase):
    def test_real_profiles_are_complete_and_show_receiver_cost(self):
        evidence = Path(__file__).resolve().parents[2] / 'docs/evidence'
        for version in ('pf6', 'pf7'):
            for node in range(2):
                path = evidence / f'ssi-{version}-node{node}-profile-20261106.jsonl.gz'
                records = [json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
                result = summary.summarize(records)
                self.assertEqual(result['groups']['dsm']['matched_threads'], 8)
                cost = result['groups']['dsm']['cpu_equivalents']
                if version == 'pf6':
                    self.assertGreater(cost, 0.8)
                else:
                    self.assertLess(cost, 0.1)
                self.assertGreater(result['stack_observations']['vcpu_samples_in_ktcp_receive'], 0)

    def test_cpu_time_is_delta_not_lifetime(self):
        result = summary.summarize(recording())
        self.assertEqual(result['groups']['dsm']['cpu_seconds'], 2)
        self.assertEqual(result['groups']['dsm']['cpu_equivalents'], 0.2)

    def test_reused_tid_is_not_same_thread(self):
        records = recording()
        records[2]['tasks'][0]['start_ticks'] = 30
        result = summary.summarize(records)
        self.assertEqual(result['groups']['dsm']['matched_threads'], 0)

    def test_incomplete_capture_is_rejected(self):
        with self.assertRaises(ValueError):
            summary.summarize(recording()[:-1])

    def test_error_marker_is_rejected(self):
        records = recording()
        records.insert(2, {'op': 'error', 'message': 'process disappeared'})
        with self.assertRaises(ValueError):
            summary.summarize(records)

    def test_corrupt_timing_and_duplicates_are_rejected(self):
        for field, value in [('monotonic_ns', 1), ('runtime_ns', 1), ('duplicate', None)]:
            records = recording()
            if field == 'runtime_ns':
                records[2]['tasks'][0][field] = value
            elif field == 'duplicate':
                records[2]['tasks'].append(copy.deepcopy(records[2]['tasks'][0]))
            else:
                records[2][field] = value
            with self.assertRaises(ValueError):
                summary.summarize(records)


if __name__ == '__main__':
    unittest.main()
