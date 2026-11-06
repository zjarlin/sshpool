"""重放复位路由的真实对照，拒绝遗漏复位、强制清理、故障伪零和无证据的关闭。"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('reset', Path(__file__).with_name('check-reset-router.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ResetRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-reset-router-20261107.json').read_text())
        cls.row = next(row for row in cls.evidence['runs'] if row['run']['variant'] == 'candidate'
                       and row['run']['error'] == 28)

    def reject(self, mutate, source=None):
        row = deepcopy(self.row if source is None else source)
        mutate(row)
        with self.assertRaises((ValueError, KeyError, IndexError, TypeError)):
            checker.check(row)

    def test_recorded_matrix_and_accepted_scope(self):
        self.assertEqual(len(self.evidence['runs']), 5)
        observed = set()
        for row in self.evidence['runs']:
            result = checker.check(row)
            self.assertEqual(result, row['checked'])
            self.assertFalse(result['full_ssi_accepted'])
            self.assertFalse(result['native_pins_observed'])
            self.assertFalse(result['reset_resume_verified'])
            run = row['run']
            observed.add((run['variant'], run['error'], run['reset_count'], run['crash']))
        self.assertEqual(observed, {('baseline', 5, 1, False), ('candidate', 5, 1, False),
                                   ('candidate', 28, 3, False), ('candidate', 0, 3, False),
                                   ('candidate', 0, 3, True)})

    def test_baseline_cleanup_is_a_defect_reproduction(self):
        row = next(row for row in self.evidence['runs'] if row['run']['variant'] == 'baseline')
        result = checker.check(row)
        self.assertTrue(result['baseline_timeout_reproduced'])
        self.assertFalse(result['reset_shutdown_verified'])
        self.assertTrue(result['nodes'][1]['forced_cleanup'])
        self.assertEqual(len(result['nodes'][1]['lost_task_ids']), 1)
        self.reject(lambda r: r['records'][1].update(forced_cleanup=False), row)
        self.reject(lambda r: r['records'][1].update(errors=[]), row)
        self.reject(lambda r: r['run'].update(variant='candidate'), row)

    def test_native_reset_events_are_required_on_both_nodes(self):
        for node in (0, 1):
            def remove(row):
                for entry in row['records'][node]['qmp']:
                    entry['responses'] = [r for r in entry['responses'] if r.get('event') != 'RESET']
            self.reject(remove)
        self.reject(lambda r: r['run'].update(reset_count=1))

    def test_peer_resets_must_be_forwarded(self):
        def mutate(row):
            for entry in row['records'][1]['qmp']:
                for reply in entry['responses']:
                    if reply.get('event') == 'RESET':
                        reply['data'] = {'guest': False, 'reason': 'host-qmp-system-reset'}
        self.reject(mutate)

    def test_snapshot_cannot_outpace_reset_completion(self):
        self.reject(lambda r: r['records'][1]['snapshots'][-2].update(qmp_end=10))
        self.reject(lambda r: r['records'][1]['snapshots'].pop(3))
        self.reject(lambda r: r['records'][1]['snapshots'][-1]['queue'].update(inuse=1))
        self.reject(lambda r: r['records'][1]['snapshots'][-1].update(pins=[{'read_refs': 0}]))

    def test_errors_and_data_loss_are_not_cleared_by_reset(self):
        self.reject(lambda r: r['records'][0].update(qemu_exit=0))
        self.reject(lambda r: r['records'][1].update(qemu_exit=0))
        self.reject(lambda r: r['records'][0].update(payload_matches=True))
        self.reject(lambda r: r['records'][0].update(disk_sha256=checker.pins.DISK_SHA[True]))
        self.reject(lambda r: r['records'][0].update(stderr=r['records'][0]['stderr'].replace('ret -28', 'ret 0')))
        self.reject(lambda r: r['records'][0]['command'].extend(['-drive', 'file=business.img']))

    def test_forced_cleanup_and_missing_deadline_are_rejected_for_candidate(self):
        self.reject(lambda r: r['records'][1].update(forced_cleanup=True))
        self.reject(lambda r: r['records'][1].update(errors=['timeout']))
        self.reject(lambda r: r['records'][1].pop('exit_observed_ns'))
        self.reject(lambda r: r['records'][1].update(exit_observed_ns=r['records'][1]['actions'][-1]['time_ns'] + 40000000000))
        self.reject(lambda r: r['run'].update(node1_remaining='qemu-system-x86'))

    def test_peer_thread_disappearance_is_not_accepted(self):
        def remove(row):
            for snapshot in row['records'][1]['snapshots']:
                if snapshot['phase'].startswith('after_reset_') or snapshot['phase'] == 'before_quit':
                    snapshot['threads'].pop()
        self.reject(remove)

    def test_crash_requires_owned_process_fault_record_and_peer_eof(self):
        row = next(row for row in self.evidence['runs'] if row['run']['crash'])
        self.assertEqual(row['run']['physical_nodes'], [1, 0])
        self.assertEqual([r['qemu_exit'] for r in row['records']], [-9, 1])
        self.reject(lambda r: r['records'][0].pop('injected_fault'), row)
        self.reject(lambda r: r['records'][0].update(qemu_exit=0), row)
        self.reject(lambda r: r['records'][1].update(stderr=r['records'][1]['stderr'].replace('SSI router EOF before acknowledged drain', 'hidden')), row)
        self.reject(lambda r: r['records'][1].update(forced_cleanup=True), row)

    def test_missing_pin_samples_cannot_pass_native_pin_checker(self):
        row = deepcopy(self.row)
        row['run'].update(variant='candidate', runtime_sha256=checker.pins.RUNTIMES['candidate'])
        for record in row['records']:
            record['qemu_sha256'] = row['run']['runtime_sha256']
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            checker.pins.check(row)

    def test_workspace_regression_and_stock_restoration_are_recorded(self):
        runs = self.evidence['workspace_runs']
        self.assertEqual([r['mode'] for r in runs], ['control', 'pair'])
        for row in runs:
            self.assertEqual(row['result']['qemu_sha256'], checker.RUNTIMES['candidate'])
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


if __name__ == '__main__':
    unittest.main()
