"""重放真实固定页面证据，并验证检查器会拒绝计数、类型及清理伪造。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pins', Path(__file__).with_name('check-pins.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-pin-lifecycle-20261106.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes'] if not row['record']['baseline']}

    def reject(self, mode, mutate):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaises(ValueError):
            checker.inspect(record)

    def test_baseline_and_candidate_on_both_nodes(self):
        expected = {('pf22', n, 'service') for n in (0, 1)}
        expected |= {('pf23', n, mode) for n in (0, 1) for mode in ('service', 'lifecycle', 'active', 'rollback')}
        actual = {(row['record']['kernel'].rsplit('-', 1)[1], row['run']['node'], row['record']['mode']) for row in self.evidence['probes']}
        self.assertEqual(actual, expected)
        for row in self.evidence['probes']:
            self.assertEqual(checker.inspect(row['record']), row['analysis'])
            self.assertEqual(row['run']['exit'], 0)
            self.assertTrue(row['firewall_restored_exactly'])
            self.assertFalse(row['analysis']['whole_vm_shutdown_verified'])

    def test_exact_source_and_runtime_provenance(self):
        for path, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        for capture in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(capture['text'].encode()).hexdigest(), capture['sha256'])
        build = self.evidence['build']
        self.assertTrue(build['patch_replay_matches_compiled_source'])
        self.assertTrue(build['config_only_localversion_changed'])
        self.assertNotRegex(self.evidence['build_log'], r'warning:|error:')
        for row in self.evidence['probes']:
            version = row['record']['kernel'].rsplit('-', 1)[1]
            self.assertEqual(row['runtime_hashes']['probe-pins.py'], self.evidence['capture_versions'][version]['probe-pins.py'])
            digest = build['kernel'] if version == 'pf23' else self.evidence['baseline_kernel_sha256']
            self.assertEqual(row['runtime_hashes']['vmlinuz-' + row['record']['kernel']], digest)

    def test_busy_rejection_must_leave_admission_open(self):
        def mutate(record):
            row = next(c for c in record['calls'] if c['name'] == 'drain_pinned')
            row['admission_status'] = struct.pack('=IIQIiII', 1, 1, checker.GENERATION, 0, 0, 0, 0).hex()
        self.reject('service', mutate)

    def test_unpin_and_request_response_are_both_required(self):
        self.reject('service', lambda r: next(c for c in r['calls'] if c['name'] == 'release_read').update(errno=108))
        self.reject('service', lambda r: r['responses'][0].update(hex='00'))
        self.reject('service', lambda r: r.update(blocked_readable=True))

    def test_wrong_kind_and_partial_unpin_cannot_mutate(self):
        self.reject('lifecycle', lambda r: next(c for c in r['calls'] if c['name'] == 'wrong_kind').update(errno=0))
        self.reject('lifecycle', lambda r: next(s for s in r['statuses'] if s['name'] == 'unchanged_after_invalid').update(read=1))
        self.reject('lifecycle', lambda r: next(c for c in r['calls'] if c['name'] == 'partly_unmatched').update(errno=0))

    def test_overlap_counts_references_instead_of_unique_pages(self):
        def mutate(record):
            status = next(s for s in record['statuses'] if s['name'] == 'overlap_refs')
            status.update(read=2, hex=struct.pack('=IIQQiI', 1, 0, 2, 1, 0, 0).hex())
        self.reject('lifecycle', mutate)

    def test_memslot_changes_must_be_blocked_before_invalidating(self):
        self.reject('lifecycle', lambda r: next(c for c in r['calls'] if c['name'] == 'delete_pinned').update(errno=0))
        self.reject('lifecycle', lambda r: r.update(trace=re.sub(r'(pp_busy: [^\n]*code=)1', r'\g<1>0', r['trace'], count=1)))

    def test_pending_pin_requires_special_admission_token(self):
        self.reject('active', lambda r: r.update(trace=re.sub(r'(pp_entered: [^\n]*code=)2', r'\g<1>1', r['trace'], count=1)))
        self.reject('active', lambda r: next(s for s in r['statuses'] if s['name'] == 'pending').update(active=0))
        self.reject('active', lambda r: next(s for s in r['statuses'] if s['name'] == 'pending').update(time_ns=1))

    def test_partial_failure_retains_preexisting_reference(self):
        def mutate(record):
            status = next(s for s in record['statuses'] if s['name'] == 'rolled_back')
            status.update(read=0, hex=struct.pack('=IIQQiI', 1, 0, 0, 0, 0, 0).hex())
        self.reject('rollback', mutate)
        self.reject('rollback', lambda r: next(c for c in r['calls'] if c['name'] == 'failed_range').update(errno=0))

    def test_native_trace_result_cannot_be_replaced_by_summary(self):
        self.reject('rollback', lambda r: r.update(trace=re.sub(r'(pp_done: [^\n]*code=)-14', r'\g<1>0', r['trace'], count=1)))
        self.reject('active', lambda r: r.update(trace=re.sub(r'(pp_changed: [^\n]*code=)0', r'\g<1>-22', r['trace'], count=1)))

    def test_data_and_wire_identity_are_checked(self):
        self.reject('active', lambda r: r.update(injected='00' * 4110))
        self.reject('active', lambda r: r.update(page_sha256='0' * 64))
        self.reject('service', lambda r: r['requests'].__setitem__(0, '00' * 4110))

    def test_trace_loss_and_cleanup_cannot_pass(self):
        self.reject('service', lambda r: r.update(trace=r['trace'].replace('pp_left:', 'unknown:', 1)))
        self.reject('service', lambda r: r.update(trace_cleanup_complete=False))
        self.reject('service', lambda r: r.update(remaining_tasks={'123': {}}))
        self.reject('service', lambda r: r['trace_stats'].__setitem__('cpu0', r['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1', 1)))


    def test_guest_regression_keeps_timer_and_shutdown_failure(self):
        rows = {row['mode']: row for row in self.evidence['workspace_runs']}
        self.assertEqual(set(rows), {'control', 'pair'})
        self.assertTrue(rows['control']['operations_passed'])
        pair = rows['pair']
        self.assertFalse(pair['operations_passed'])
        self.assertGreater(pair['max_timer_ns'], 250000000)
        self.assertTrue(any(pair['validation']['clock']))
        self.assertEqual(pair['result']['qemu_ssh_exits'], [0, 0])
        self.assertFalse(pair['analysis']['kernel_shutdown_accepted'])
        for log in pair['host_logs']:
            self.assertRegex(log, r'ktcp_receive.*error')
        for row in rows.values():
            self.assertFalse(row['full_ssi_accepted'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['kernel'], self.evidence['build']['kernel'])
                self.assertEqual(hashes['qemu'], self.evidence['qemu_sha256'])

    def test_lab_restoration_preserves_stock_and_existing_boot_files(self):
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual({row['node'] for row in nodes}, {0, 1})
        for row in nodes:
            self.assertEqual(row['kernel'], '6.8.0-147-generic')
            self.assertTrue(row['identity_matches'])
            self.assertTrue(row['old_boot_files_unchanged'])
            self.assertTrue(row['firewall_matches_original'])
            self.assertFalse(row['remaining_processes'])
            self.assertFalse(row['trace_events'])
            self.assertFalse(row['trace_instances'])
            self.assertFalse(row['grub_environment'])


if __name__ == '__main__':
    unittest.main()
