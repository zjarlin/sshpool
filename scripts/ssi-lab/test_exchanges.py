"""重放真实事务证据，并拒绝伪造缓存消费、编号归属或提前结束的记录。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('exchanges', Path(__file__).with_name('check-exchanges.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
boot_spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('check-ssh-boot.py'))
boot = importlib.util.module_from_spec(boot_spec)
boot_spec.loader.exec_module(boot)


class ExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-exchange-accounting-20261106.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes']
                       if row['record']['kernel'].endswith('pf22')}

    def reject(self, mode, mutate):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaises(ValueError):
            checker.inspect(record)

    def test_all_six_modes_on_both_labs_and_versions(self):
        modes = ('external', 'reverse', 'unknown', 'duplicate', 'partial-cancel', 'connect-fault')
        expected = {(version, node, mode) for version in ('pf21', 'pf22') for node in (0, 1) for mode in modes}
        actual = {(row['record']['kernel'].rsplit('-', 1)[1], row['run']['node'], row['record']['mode'])
                  for row in self.evidence['probes']}
        self.assertEqual(actual, expected)
        for row in self.evidence['probes']:
            self.assertEqual(checker.inspect(row['record']), row['analysis'])
            self.assertEqual(row['run']['exit'], 0)
            self.assertTrue(row['firewall_restored_exactly'])
            self.assertFalse(row['analysis']['whole_vm_shutdown_verified'])

    def test_runtime_capture_and_patch_provenance(self):
        for name, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
        for capture in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(capture['text'].encode()).hexdigest(), capture['sha256'])
        for version, build in self.evidence['builds'].items():
            self.assertTrue(build['patch_replay_matches_compiled_source'])
            self.assertTrue(build['config_only_localversion_changed'])
            self.assertNotIn('warning:', self.evidence['build_logs'][version])
            self.assertNotIn('error:', self.evidence['build_logs'][version])
        for row in self.evidence['probes']:
            kernel = row['record']['kernel']
            version = kernel.rsplit('-', 1)[1]
            self.assertEqual(row['runtime_hashes']['vmlinuz-' + kernel], self.evidence['builds'][version]['kernel'])
            self.assertEqual(row['runtime_hashes']['probe-exchanges.py'],
                             self.evidence['capture_versions'][version]['probe-exchanges.py'])

    def test_allocator_exhaustion_failure_and_fix_are_both_preserved(self):
        boundary = self.evidence['allocator_boundary']
        old, new = boundary['versions']
        self.assertEqual(old['exit'], 124)
        self.assertEqual(old['stdout'], 'allocated=65535 unique=65535 reserved_unused=1\n')
        self.assertEqual(new['exit'], 0)
        self.assertIn('exhaustion_errno=28 reserved_unused=1\n', new['stdout'])
        self.assertIn('reclaimed_id=40000 reused_id=40000\n', new['stdout'])
        self.assertTrue(new['stdout'].endswith('all_transactions_removed=1 allocator_nodes_remaining=0\n'))
        for row in (old, new):
            version = row['version']
            self.assertEqual(row['stderr'], '')
            self.assertEqual(row['source_sha256'], self.evidence['builds'][version]['compiled_sources']['arch/x86/kvm/ktcp.c'])
            extracted = self.evidence['allocator_capture']['extracted'][version]
            self.assertEqual(hashlib.sha256(extracted.encode()).hexdigest(), row['extracted_sha256'])
            self.assertIn('-fsanitize=address', self.evidence['allocator_capture']['build_logs'][version])
        self.assertFalse(self.evidence['rejected_candidates'][0]['accepted'])
        self.assertFalse(self.evidence['allocator_capture']['provenance']['live_kvm_exhaustion_tested'])

    def test_cached_response_cannot_be_reported_as_consumed(self):
        def mutate(record):
            for row in record['statuses']:
                if row['name'] == 'cached':
                    row['cached'] = 0
                    row['hex'] = struct.pack('=IIIIiIII', 1, 2, 0, 2, 0, 0, 0, 0).hex()
        self.reject('reverse', mutate)

    def test_status_summary_cannot_disagree_with_raw_abi(self):
        self.reject('reverse', lambda r: r['statuses'][-1].update(exchanges=1))
        self.reject('reverse', lambda r: r['statuses'][0].update(reserved=[1, 0, 0]))

    def test_snapshot_must_belong_to_observed_live_interval(self):
        self.reject('reverse', lambda r: next(row for row in r['statuses'] if row['name'] == 'cached').update(time_ns=1))
        self.reject('reverse', lambda r: r.update(partial_reader_pid=r['partial_reader_pid'] + 1))

    def test_same_connection_ids_must_be_unique(self):
        def mutate(record):
            frames = record['outgoing_requests']
            first, second = bytes.fromhex(frames[0]), bytearray.fromhex(frames[1])
            second[12:14] = first[12:14]
            frames[1] = second.hex()
        self.reject('reverse', mutate)

    def test_registration_receive_and_retirement_must_match(self):
        self.reject('reverse', lambda r: r.update(trace=re.sub(r'(ex_retire: [^\n]*txid=)\d+', r'\g<1>50000', r['trace'], count=1)))
        self.reject('reverse', lambda r: r.update(trace=re.sub(r'(ex_retire: [^\n]*cb=)0x[0-9a-f]+', r'\g<1>0x0', r['trace'], count=1)))

    def test_fault_discard_cannot_claim_successful_consumption(self):
        self.reject('duplicate', lambda r: r.update(trace=r['trace'].replace('ex_cached: (ktcp_end_transaction+', 'ex_cached: (ktcp_receive+')))
        self.reject('unknown', lambda r: r.update(management_errno=0))
        self.reject('connect-fault', lambda r: r.update(management_errno=0))

    def test_injected_frames_and_returned_pages_are_checked(self):
        self.reject('unknown', lambda r: r['injected'].__setitem__(0, '00'))
        self.reject('external', lambda r: r.update(page_sha256='0' * 64))
        self.reject('reverse', lambda r: r['responses'][-1].update(hex='00'))

    def test_sealed_ioctl_gate_still_permits_reverse_service(self):
        self.reject('reverse', lambda r: r.update(ioctl_status_after_seal=struct.pack('=IIQIiII', 1, 0, 0, 0, 0, 0, 0).hex()))

    def test_lifecycle_completion_and_trace_losses_are_checked(self):
        self.reject('reverse', lambda r: r.update(trace=r['trace'].replace('ex_finished:', 'ex_missing:', 1)))
        self.reject('reverse', lambda r: r['trace_stats'].update(cpu0=r['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1', 1)))
        self.reject('partial-cancel', lambda r: r.update(tasks_before_cleanup={'123': {}}))

    def test_guest_regression_cannot_certify_full_ssi(self):
        self.assertEqual({row['mode'] for row in self.evidence['workspace_runs']}, {'control', 'pair'})
        for row in self.evidence['workspace_runs']:
            self.assertFalse(row['full_ssi_accepted'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['kernel'], self.evidence['builds']['pf22']['kernel'])
                self.assertEqual(hashes['qemu'], self.evidence['qemu_sha256'])

    def test_successful_guest_operations_do_not_hide_dsm_shutdown_errors(self):
        rows = {row['mode']: row for row in self.evidence['workspace_runs']}
        self.assertTrue(rows['control']['operations_passed'])
        pair = rows['pair']
        self.assertTrue(pair['operations_passed'])
        self.assertLessEqual(pair['max_timer_ns'], 250000000)
        self.assertEqual(pair['result']['qemu_ssh_exits'], [0, 0])
        self.assertFalse(pair['analysis']['kernel_shutdown_accepted'])
        for log in pair['host_logs']:
            self.assertRegex(log, r'ktcp_receive.*error')
            with self.assertRaises(ValueError):
                boot.check_errors(log)


if __name__ == '__main__':
    unittest.main()
