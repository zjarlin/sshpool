"""资源检查器不能遗漏父资源池、历史限速、缺样或把根资源总量当作人为限额。"""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('resources', Path(__file__).with_name('check-esxi-resources.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def report():
    return {'nodes': [{'moid': 'test-node', 'memory_mb': 1024,
                       'cpu': {'limit': -1}, 'memory': {'limit': 1024},
                       'resource_pools': [{'moid': 'root', 'is_root': True,
                                           'cpu': {'limit': 70000}, 'memory': {'limit': 120000}}],
                       'performance': [{'intervals': [{'timestamp': '2026-11-06T01:00:00+00:00', 'interval': 20},
                                                      {'timestamp': '2026-11-06T01:00:20+00:00', 'interval': 20}],
                                        'values': [{'counter': name, 'instance': '', 'values': [0, 0]}
                                                   for name in sorted(checker.COUNTERS)]}]}]}


class EsxiResourceTests(unittest.TestCase):
    def test_root_capacity_and_configured_memory_are_not_extra_caps(self):
        self.assertEqual(checker.assess(report()), [])

    def test_vm_cpu_and_lower_memory_caps_block(self):
        for kind, limit in [('cpu', 2000), ('memory', 512)]:
            data = report()
            data['nodes'][0][kind]['limit'] = limit
            self.assertTrue(checker.assess(data))

    def test_child_pool_cap_blocks(self):
        data = report()
        data['nodes'][0]['resource_pools'][0]['is_root'] = False
        self.assertEqual(len(checker.assess(data)), 2)

    def test_old_throttling_is_still_reported_after_cap_removal(self):
        data = report()
        for row in data['nodes'][0]['performance'][0]['values']:
            if row['counter'] == 'cpu.maxlimited.summation':
                row['values'][0] = 14486
        self.assertIn('采样窗口包含 CPU 限速', checker.assess(data)[0])

    def test_missing_or_unknown_measurements_do_not_pass(self):
        for values in ([], [-1, 0], [0]):
            data = report()
            data['nodes'][0]['performance'][0]['values'][0]['values'] = values
            self.assertTrue(checker.assess(data))
        data = report()
        data['nodes'][0]['performance'][0]['values'].pop()
        self.assertTrue(checker.assess(data))
        data = report()
        data['nodes'][0]['performance'].clear()
        self.assertTrue(checker.assess(data))
        self.assertTrue(checker.assess({'nodes': []}))

    def test_reordered_intervals_and_duplicate_counters_fail(self):
        data = report()
        data['nodes'][0]['performance'][0]['intervals'].reverse()
        self.assertTrue(checker.assess(data))
        data = report()
        values = data['nodes'][0]['performance'][0]['values']
        values.append(values[0])
        self.assertTrue(checker.assess(data))


if __name__ == '__main__':
    unittest.main()
