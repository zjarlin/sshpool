"""重放双节点真实设备证据，拒绝伪造零引用、隐藏错误和将部分生命周期当成通过。"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pins', Path(__file__).with_name('check-virtio-dsm-pins.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class VirtioDsmPinsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-virtio-dsm-pins-20261107.json').read_text())
        cls.row = next(row for row in cls.evidence['runs'] if row['run']['variant'] == 'candidate'
                       and row['run']['error'] == 5)

    def reject(self, mutate, source=None):
        row = deepcopy(self.row if source is None else source)
        mutate(row)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            checker.check(row)

    def test_six_completed_experiments_and_four_failures(self):
        runs = self.evidence['runs']
        self.assertEqual(len(runs), 6)
        self.assertEqual(len(self.evidence['rejected_runs']), 4)
        for row in runs:
            self.assertEqual(checker.check(row), row['checked'])
            self.assertFalse(row['checked']['full_ssi_accepted'])
            self.assertFalse(row['checked']['storage_replicated'])
        reverse = next(row for row in runs if row['run']['error'] == 28)
        self.assertEqual(reverse['run']['physical_nodes'], [1, 0])
        for row in self.evidence['rejected_runs']:
            with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
                checker.check(row)

    def test_baseline_leak_remains_visible_after_device_disappears(self):
        row = next(row for row in self.evidence['runs'] if row['run']['variant'] == 'baseline'
                   and row['run']['error'] == 5)
        result = checker.check(row)
        self.assertTrue(result['native_pin_leak_reproduced'])
        self.assertFalse(result['native_pins_released'])
        self.reject(lambda r: r['run'].update(variant='candidate'), row)

    def test_forged_counts_must_match_original_queries(self):
        self.reject(lambda r: r['records'][0]['snapshots'][-1]['pins'][0].update(read_refs=1))
        self.reject(lambda r: r['records'][0]['snapshots'][1]['queue'].update(inuse=0))
        self.reject(lambda r: r['records'][0]['snapshots'][-1].update(qmp_start=1))
        self.reject(lambda r: r['records'][0]['qmp'].pop(2))

    def test_consistent_false_zero_cannot_hide_a_missing_pending_request(self):
        def mutate(row):
            record = row['records'][0]
            for snapshot in record['snapshots']:
                for pin in snapshot['pins']:
                    pin.update(read_refs=0, write_refs=0)
            for entry in record['qmp']:
                if entry['request']['execute'] == 'human-monitor-command':
                    for reply in entry['responses']:
                        if 'return' in reply:
                            pin = json.loads(reply['return'])
                            pin.update(read_refs=0, write_refs=0)
                            reply['return'] = json.dumps(pin)
        self.reject(mutate)

    def test_native_query_failures_are_not_zero_references(self):
        for field, value in [('ret', -22), ('version', 0), ('error', -5), ('active_ops', 1), ('reserved', 1)]:
            def mutate(row):
                record = row['records'][0]
                snapshot = record['snapshots'][-1]
                for pin in snapshot['pins']:
                    pin[field] = value
                for entry in record['qmp'][snapshot['qmp_end'] - 2:snapshot['qmp_end']]:
                    for reply in entry['responses']:
                        if 'return' in reply:
                            pin = json.loads(reply['return'])
                            pin[field] = value
                            reply['return'] = json.dumps(pin)
            with self.subTest(field=field):
                self.reject(mutate)

    def test_cancelled_write_is_not_durable_or_replicated(self):
        self.reject(lambda r: r['records'][0].update(payload_matches=True, payload_zero=False))
        self.reject(lambda r: r['records'][0].update(disk_sha256=checker.DISK_SHA[True]))
        self.reject(lambda r: r['records'][1].update(payload_matches=True))
        self.reject(lambda r: r['records'][0].update(qemu_exit=0))
        self.reject(lambda r: r['records'][1].update(qemu_exit=0))

    def test_actual_guest_driver_error_and_request_trace_required(self):
        def erase_event(row):
            for entry in row['records'][0]['qmp']:
                entry['responses'] = [r for r in entry['responses'] if r.get('event') != 'BLOCK_IO_ERROR']
        self.reject(erase_event)
        for before, after in [('virtio_blk_handle_write', 'hmp_write'), ('ret -5', 'ret 0'),
                              ("retains I/O status 'failed'", 'hidden')]:
            self.reject(lambda r: r['records'][0].update(stderr=r['records'][0]['stderr'].replace(before, after)))
        self.reject(lambda r: r['records'][0].update(serial=r['records'][0]['serial'].replace('SSI_BLOCK_WRITE_BEGIN', '')))

    def test_timeouts_and_partial_reset_remain_rejected(self):
        self.reject(lambda r: r['records'][1].update(forced_cleanup=True))
        self.reject(lambda r: r['run'].update(errors=['timeout']))
        self.reject(lambda r: r['run'].update(capture_exits=[0, 1]))
        self.reject(lambda r: r['run'].update(node1_remaining='qemu-system-x86'))
        reset = next(row for row in self.evidence['rejected_runs'] if row['run']['action'] == 'reset')
        self.assertEqual(reset['records'][0]['snapshots'][-1]['pins'][0]['read_refs'], 0)
        self.assertTrue(reset['records'][1]['forced_cleanup'])
        self.assertTrue(reset['records'][1]['errors'])

    def test_unexpected_runtime_disk_or_resume_is_rejected(self):
        self.reject(lambda r: r['records'][0].update(qemu_sha256='unknown'))
        self.reject(lambda r: r['records'][0]['command'].extend(['-drive', 'file=business.img']))
        self.reject(lambda r: r['records'][0]['command'].append('-S'))
        self.reject(lambda r: r['run'].update(pause_cycles=1))
        self.reject(lambda r: r['run'].update(action='resume'))

    def test_normal_candidate_regressions_and_restoration_are_recorded(self):
        normal = self.evidence['normal_candidate']
        self.assertTrue(normal['diagnostic_hmp_removed'])
        self.assertTrue(normal['warning_free'])
        runs = self.evidence['workspace_runs']
        self.assertEqual([row['mode'] for row in runs], ['control', 'pair'])
        for row in runs:
            self.assertEqual(row['result']['qemu_sha256'], normal['sha256'])
            self.assertTrue(row['operations_passed'])
            self.assertLessEqual(row['max_timer_ns'], 250000000)
            self.assertFalse(row['full_ssi_accepted'])
        self.assertTrue(all('ktcp_receive' in error for error in runs[1]['validation']['hosts']))
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['old_boot_files_unchanged'])
            self.assertTrue(node['firewall_matches_original'])
            self.assertTrue(node['identity_matches'])
            self.assertFalse(node['remaining_processes'])
            self.assertFalse(node['trace_events'])
            self.assertFalse(node['trace_instances'])


if __name__ == '__main__':
    unittest.main()
