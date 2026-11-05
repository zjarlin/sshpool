"""重算真实内核探针记录，并拒绝旧快照、撕裂版本和同页数据损坏。"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

directory = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('probe_pvclock', directory / 'probe-pvclock.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
evidence = directory.parents[1] / 'docs/evidence/ssi-pvclock-probes-20261106.json'
runs = json.loads(evidence.read_text())['runs']


def evaluate(exchange):
    return probe.check_exchange(exchange['before'], exchange['previous'],
                                exchange['latest'], exchange['observed'],
                                exchange['cpu'], exchange['reader_node'])


class PvclockEvidenceTest(unittest.TestCase):
    def test_recomputes_real_pf5_failure_and_pf6_success(self):
        for run in runs:
            expected = run['run'] != 'pvclock-pf5-pair-1'
            self.assertEqual(len(run['exchanges']), 8)
            self.assertEqual(run['result']['errors'], [])
            self.assertEqual(run['closed_nodes'], [1, 0] if 'pair' in run['run'] else [0])
            for exchange in run['exchanges']:
                with self.subTest(run=run['run'], round=exchange['round'], cpu=exchange['cpu']):
                    self.assertEqual(evaluate(exchange)['pass'], expected)

    def test_rejects_stale_snapshot_even_with_a_new_local_clock(self):
        exchange = copy.deepcopy(runs[-1]['exchanges'][0])
        exchange['observed'] = copy.deepcopy(exchange['previous'])
        self.assertFalse(evaluate(exchange)['pass'])

    def test_rejects_torn_version_and_zero_time(self):
        for field, value in [('version', 7), ('time', 0), ('multiplier', 0)]:
            exchange = copy.deepcopy(runs[-1]['exchanges'][0])
            for side in ('latest', 'observed'):
                exchange[side]['records'][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(evaluate(exchange)['pass'])

    def test_rejects_damage_to_another_record_or_marker(self):
        exchange = copy.deepcopy(runs[-1]['exchanges'][0])
        for side in ('latest', 'observed'):
            exchange[side]['records'][1]['flags'] ^= 1
        self.assertFalse(evaluate(exchange)['pass'])
        exchange = copy.deepcopy(runs[-1]['exchanges'][0])
        for side in ('latest', 'observed'):
            exchange[side]['marker'] = 99
        self.assertFalse(evaluate(exchange)['pass'])


if __name__ == '__main__':
    unittest.main()
