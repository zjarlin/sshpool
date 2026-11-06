"""重放真实反向依赖记录，拒绝提前解除暂存引用或用清理后的返回冒充进展。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pin_release', Path(__file__).with_name('check-pin-release.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PinReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-pin-release-20261106.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes'] if not row['record']['baseline']}

    def reject(self, mode, mutate):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaises(ValueError):
            checker.inspect(record)

    def test_both_nodes_reproduce_baseline_and_pass_six_candidate_modes(self):
        expected = {('pf23', n, 'dependency') for n in (0, 1)}
        expected |= {('pf24', n, mode) for n in (0, 1) for mode in ('dependency', 'pending', 'pending-write', 'empty', 'rollback', 'duplicate')}
        actual = {(row['record']['kernel'].rsplit('-', 1)[1], row['run']['node'], row['record']['mode']) for row in self.evidence['probes']}
        self.assertEqual(actual, expected)
        self.assertEqual(len(self.evidence['probes']), len(expected))
        for row in self.evidence['probes']:
            self.assertEqual(checker.inspect(row['record']), row['analysis'])
            self.assertEqual(row['run']['exit'], 0)
            self.assertTrue(row['firewall_restored_exactly'])
            self.assertFalse(row['analysis']['whole_vm_shutdown_verified'])
            self.assertEqual(row['analysis']['active_pin_slot_protection_verified'], row['record']['mode'] == 'empty')
            self.assertEqual(row['analysis']['unpin_progress_verified'],
                             not row['record']['baseline'] and row['record']['mode'] != 'empty')

    def test_runtime_and_capture_provenance(self):
        for path, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        for capture in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(capture['text'].encode()).hexdigest(), capture['sha256'])
        self.assertTrue(self.evidence['build']['patch_replay_matches_compiled_source'])
        self.assertTrue(self.evidence['build']['config_only_localversion_changed'])
        self.assertNotRegex(self.evidence['build_log'], r'warning:|error:')
        for row in self.evidence['probes']:
            version = row['record']['kernel'].rsplit('-', 1)[1]
            for name, digest in self.evidence['capture_versions'][version].items():
                self.assertEqual(row['runtime_hashes'][name], digest)
                if name != 'probe-pin-release.py':
                    self.assertEqual(hashlib.sha256((root / 'scripts/ssi-lab' / name).read_bytes()).hexdigest(), digest)
            expected = self.evidence['build']['kernel'] if version == 'pf24' else self.evidence['baseline_kernel_sha256']
            self.assertEqual(row['runtime_hashes']['vmlinuz-' + row['record']['kernel']], expected)

    def test_rejected_connection_attempt_and_firewall_fixture_are_retained(self):
        rejected = self.evidence['rejected_probes']
        self.assertEqual(len(rejected), 1)
        row = rejected[0]
        self.assertEqual(row['run']['exit'], 1)
        self.assertEqual(row['record']['errors'], ['timed out'])
        self.assertFalse(row['record']['requests'])
        self.assertEqual([c['name'] for c in row['record']['calls']], ['setup', 'setup_last'])
        self.assertTrue(row['record']['trace_cleanup_complete'])
        self.assertFalse(row['record']['remaining_tasks'])
        self.assertTrue(row['firewall_restored_exactly'])
        with self.assertRaises(ValueError):
            checker.inspect(row['record'])
        fixture = self.evidence['loopback_firewall_fixture']
        self.assertEqual([t['result']['connected'] for t in fixture['trials']], [False, True])
        self.assertEqual([t['result']['source'][1] for t in fixture['trials']], [40000, 40001])
        self.assertTrue(fixture['restored_exactly'])

    def test_callback_must_complete_before_remote_response(self):
        self.reject('dependency', lambda r: r['responses'][1].update(time_ns=r['injected']['time_ns'] + 1))
        self.reject('dependency', lambda r: r.update(before_release_readable=True))
        self.reject('dependency', lambda r: r.update(pin_alive_before_response=False))

    def test_unpin_must_finish_before_response_and_not_during_cleanup(self):
        def mutate(record):
            call = next(c for c in record['calls'] if c['name'] == 'release_old')
            call['end_ns'] = record['injected']['time_ns'] + 1
        self.reject('dependency', mutate)
        self.reject('dependency', lambda r: r.update(cleanup_rescue=True))

    def test_read_and_write_pending_references_are_not_releasable(self):
        for mode in ('pending', 'pending-write'):
            self.reject(mode, lambda r: next(c for c in r['calls'] if c['name'] == 'cannot_release_pending').update(errno=0))
            self.reject(mode, lambda r: next(c for c in r['calls'] if c['name'] == 'cannot_release_partial').update(errno=0))

    def test_status_cannot_drop_pending_references(self):
        def mutate(record):
            status = next(s for s in record['statuses'] if s['name'] == 'only_pending')
            status.update(values=[1, 1, 0, 0, 0, 0], hex=struct.pack('=IIQQiI', 1, 1, 0, 0, 0, 0).hex())
        self.reject('pending', mutate)
        self.reject('pending-write', mutate)

    def test_zero_reference_active_pin_still_blocks_slot_change(self):
        self.reject('empty', lambda r: next(c for c in r['calls'] if c['name'] == 'delete_active').update(errno=0))
        self.reject('empty', lambda r: r.update(trace=re.sub(r'(pr_busy: [^\n]*code=)1', r'\g<1>0', r['trace'], count=1)))

    def test_rollback_cannot_leave_a_new_reference(self):
        self.reject('rollback', lambda r: next(c for c in r['calls'] if c['name'] == 'waiting_pin').update(errno=0))
        self.reject('rollback', lambda r: next(c for c in r['calls'] if c['name'] == 'nothing_left').update(errno=0))
        self.reject('rollback', lambda r: next(s for s in r['statuses'] if s['name'] == 'completed').update(values=[1, 0, 1, 0, 0, 0]))

    def test_two_releases_cannot_both_succeed(self):
        def mutate(record):
            for call in record['calls']:
                if call['name'] in ('release_0', 'release_1'):
                    call['errno'] = 0
        self.reject('duplicate', mutate)

    def test_native_return_and_admission_token_are_checked(self):
        self.reject('pending', lambda r: r.update(trace=re.sub(r'(pr_done: [^\n]*code=)-22', r'\g<1>0', r['trace'], count=1)))
        self.reject('empty', lambda r: r.update(trace=re.sub(r'(pr_entered: [^\n]*code=)2', r'\g<1>1', r['trace'], count=1)))

    def test_wire_page_and_cleanup_are_checked(self):
        self.reject('dependency', lambda r: r['responses'][1].update(hex='00'))
        self.reject('pending', lambda r: r['injected'].update(hex='00' * 4110))
        self.reject('empty', lambda r: r.update(page_sha256='0' * 64))
        self.reject('duplicate', lambda r: r.update(live_workers=1))
        self.reject('dependency', lambda r: r.update(remaining_tasks={'123': {}}))

    def test_trace_loss_and_false_completion_are_rejected(self):
        self.reject('pending', lambda r: r['trace_stats'].__setitem__('cpu0', r['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1', 1)))
        self.reject('dependency', lambda r: r.update(trace=r['trace'].replace('pr_left:', 'missing:', 1)))
        self.reject('dependency', lambda r: r.update(trace_cleanup_complete=False))

    def test_guest_regression_does_not_hide_kernel_shutdown_errors(self):
        boot, clock = load('check-ssh-boot'), load('check-clock')
        for row in self.evidence['workspace_runs']:
            self.assertFalse(row['full_ssi_accepted'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['kernel'], self.evidence['build']['kernel'])
                self.assertEqual(hashes['qemu'], self.evidence['qemu_sha256'])
            trials = ['CLOCK_START' + part for part in row['clock_log'].split('CLOCK_START')[1:]]
            actual = []
            for trial in trials:
                try:
                    clock.validate(trial, 250000000)
                    actual.append(None)
                except ValueError as error:
                    actual.append(str(error))
            self.assertEqual(actual, row['validation']['clock'])
            for text, error in zip(row['host_logs'], row['validation']['hosts']):
                if error:
                    with self.assertRaises(ValueError):
                        boot.check_errors(text)
                else:
                    boot.check_errors(text)

    def test_stock_restoration_preserves_files_and_firewall(self):
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual({n['node'] for n in nodes}, {0, 1})
        for row in nodes:
            self.assertEqual(row['kernel'], '6.8.0-147-generic')
            self.assertTrue(row['old_boot_files_unchanged'])
            self.assertTrue(row['firewall_matches_original'])
            self.assertTrue(row['identity_matches'])
            self.assertFalse(row['remaining_processes'])
            self.assertFalse(row['trace_events'])
            self.assertFalse(row['trace_instances'])
            self.assertFalse(row['grub_environment'])


if __name__ == '__main__':
    unittest.main()
