"""用实测原始记录拒绝提前恢复、伪造快照和被清理的失败进程。"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('resume', here / 'check-clock-resume.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
evidence = json.loads((here.parents[1] / 'docs/evidence/ssi-clock-resume-20261107.json').read_text())


def case(kind, fault=None):
    return copy.deepcopy(next(row for row in evidence['runs'] if row['kind'] == kind and
                              (fault is None or row['run']['fault'] == fault)))


class ClockResumeTest(unittest.TestCase):
    def test_real_complete_run_has_bounded_samples_and_clean_exit(self):
        result = checker.check(case('paired-resume'))
        self.assertEqual(result['cycles'], 7)
        self.assertFalse(result['full_ssi_accepted'])
        self.assertFalse(result['global_stop_command_verified'])

    def test_all_real_refusals_are_failure_stop_not_failover(self):
        rows = [row for row in evidence['runs'] if row['kind'] == 'rejected-resume']
        self.assertEqual({row['run']['fault'] for row in rows}, {'one-sided', 'silent', 'reset', 'future'})
        for row in rows:
            result = checker.check_failure(row)
            self.assertTrue(result['failed_without_resume'])
            self.assertFalse(result['failover_verified'])

    def test_original_limit_and_new_failed_runs_stay_visible(self):
        for kind in ('baseline-limit', 'discarded-coldstart-deadlock', 'post-drain-failure', 'capture-timeout'):
            with self.subTest(kind=kind), self.assertRaises((ValueError, KeyError)):
                checker.check(case(kind))
        with self.assertRaisesRegex(ValueError, 'Long readout interval'):
            checker.boot.validate(case('watchdog-failure')['records'][0]['serial'])

    def test_silent_peer_exposes_old_exit_callback_deadlock(self):
        row = case('deadline-exit-stack')
        self.assertIn('qemu_run_exit_notifiers', row['deadline_stacks'])
        self.assertIn('cluster_clock_watchdog', row['deadline_stacks'])
        self.assertIn('kvmclock_barrier', row['deadline_stacks'])
        self.assertIn('SSI clock preparation deadline expired', row['records'][0]['stderr'])
        self.assertTrue(row['records'][0]['forced_cleanup'])
        self.assertEqual(row['records'][0]['qemu_exit'], -9)

    def test_rejects_old_or_out_of_order_generation(self):
        for before, after in [('epoch=3 state=paused', 'epoch=2 state=paused'),
                              ('SSI_CLOCK_RECEIVE epoch=4 phase=2', 'SSI_CLOCK_RECEIVE epoch=4 phase=1'),
                              ('SSI_CLOCK_BARRIER epoch=2 phase=2', 'SSI_CLOCK_RELEASE epoch=2')]:
            row = case('paired-resume')
            row['records'][0]['stderr'] = row['records'][0]['stderr'].replace(before, after, 1)
            with self.subTest(before=before), self.assertRaises(ValueError):
                checker.check(row)

    def test_rejects_clock_below_peer_floor(self):
        row = case('paired-resume')
        row['records'][1]['stderr'] = re.sub(r'(SSI_CLOCK_PREPARED epoch=2 clock=)\d+', r'\g<1>1',
                                             row['records'][1]['stderr'], count=1)
        with self.assertRaisesRegex(ValueError, '下界'):
            checker.check(row)

    def test_rejects_counter_regression_across_pause(self):
        row = case('paired-resume')
        row['clock_log'] = re.sub(r'(CLOCK_SAMPLE round=1 cpu=0 tsc=)\d+', r'\g<1>1', row['clock_log'])
        with self.assertRaisesRegex(ValueError, '倒退'):
            checker.check(row)

    def test_rejects_snapshot_not_bound_to_qmp(self):
        row = case('paired-resume')
        row['records'][0]['snapshots'][1]['status']['running'] = True
        with self.assertRaisesRegex(ValueError, 'QMP'):
            checker.check(row)

    def test_rejects_missing_native_stop_event(self):
        row = case('paired-resume')
        for entry in row['records'][1]['qmp']:
            entry['responses'] = [value for value in entry['responses'] if value.get('event') != 'STOP']
        with self.assertRaisesRegex(ValueError, '原生事件'):
            checker.check(row)

    def test_rejects_forced_cleanup_as_success_or_refusal(self):
        for kind, check in [('paired-resume', checker.check), ('rejected-resume', checker.check_failure)]:
            row = case(kind)
            row['records'][1]['forced_cleanup'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                check(row)

    def test_rejects_premature_release_or_unbounded_timeout(self):
        row = case('paired-resume')
        row['run']['early_cont_reply'][2] = True
        with self.assertRaisesRegex(ValueError, '提前恢复'):
            checker.check(row)
        row = case('rejected-resume', 'one-sided')
        row['run']['failure_observed_ns'] = row['run']['last_resume_begin_ns'] + 60_000_000_000
        with self.assertRaisesRegex(ValueError, '有界'):
            checker.check_failure(row)
        row = case('rejected-resume', 'one-sided')
        row['records'][0]['stderr'] += '\nSSI_CLOCK_RELEASE epoch=2\n'
        with self.assertRaisesRegex(ValueError, '释放'):
            checker.check_failure(row)

    def test_restoration_and_scope_do_not_claim_a_production_cluster(self):
        self.assertFalse(evidence['full_ssi_accepted'])
        self.assertFalse(evidence['cross_physical_verified'])
        self.assertFalse(evidence['ceph_deployed'])
        self.assertEqual(len(evidence['restoration']['nodes']), 2)
        for node in evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertEqual(node['remaining_processes'], [])
            self.assertTrue(node['old_boot_files_unchanged'])
            self.assertTrue(node['firewall_matches_original'])
            self.assertTrue(node['identity_matches'])
            self.assertEqual(node['grub_environment'], '')

    def test_fault_injection_requires_the_captured_process_and_frame(self):
        row = case('rejected-resume', 'silent')
        row['run']['suspended_pid'] += 1
        with self.assertRaisesRegex(ValueError, '对端进程'):
            checker.check_failure(row)
        row = case('rejected-resume', 'future')
        row['run']['injection']['frame_hex'] = '00'
        with self.assertRaisesRegex(ValueError, '代际'):
            checker.check_failure(row)


if __name__ == '__main__':
    unittest.main()
