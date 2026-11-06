"""重放两台专用 VM 的入口屏障证据，并验证伪造计数或页面内容会被拒绝。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('check-ioctl-admission.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class IoctlAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-ioctl-admission-20261106.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes']}

    def reject(self, mode, mutate):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaises(ValueError):
            checker.inspect(record)

    def test_real_native_ioctls_on_both_labs(self):
        self.assertEqual({(row['run']['node'], row['record']['mode']) for row in self.evidence['probes']},
                         {(node, mode) for node in (0, 1) for mode in ('validation', 'active', 'timeout', 'fault', 'vcpu')})
        for row in self.evidence['probes']:
            self.assertEqual(checker.inspect(row['record']), row['analysis'])
            self.assertTrue(row['firewall_restored_exactly'])
            self.assertEqual(row['run']['exit'], 0)
            self.assertFalse(row['analysis']['whole_vm_drain_verified'])

    def test_build_runtime_and_capture_provenance(self):
        evidence = self.evidence
        for name, digest in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
        build = evidence['build']
        self.assertTrue(build['patch_replay_matches_compiled_source'])
        self.assertTrue(build['config_only_localversion_changed'])
        self.assertEqual(build['patch_sha256'], evidence['source_sha256']['scripts/ssi-lab/experiments/kernel-dsm-ioctl-admission.patch'])
        self.assertNotIn('warning:', evidence['build_log'])
        self.assertNotIn('error:', evidence['build_log'])
        for source in evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(source['text'].encode()).hexdigest(), source['sha256'])
        for row in evidence['probes']:
            self.assertEqual(row['runtime_hashes']['vmlinuz-' + row['record']['kernel']], build['kernel'])
            self.assertEqual(row['runtime_hashes']['probe-ioctl-admission.py'], evidence['capture_sources'][-1]['sha256'])

    def test_ioctls_must_keep_their_admission_token_until_exit(self):
        self.reject('active', lambda r: r.update(trace=r['trace'].replace('token=1', 'token=0', 1)))
        self.reject('active', lambda r: r.update(trace=r['trace'].replace('code=1\n', 'code=0\n', 1)))

    def test_worker_srcu_cannot_be_replaced_by_another_subsystem(self):
        self.reject('active', lambda r: r.update(trace=r['trace'].replace('ia_srcu_done: (kvm_vm_ioctl_dsm+',
                                                                           'ia_srcu_done: (unrelated_subsystem+')))

    def test_page_service_remains_real_after_sealing(self):
        def mutate(record):
            row = record['server_response_while_sealed']
            raw = bytearray.fromhex(row['hex'])
            raw[128] ^= 1
            row['hex'] = raw.hex()
        self.reject('active', mutate)
        self.reject('active', lambda r: r.update(page_sha256='0' * 64))

    def test_status_summary_must_match_raw_abi(self):
        self.reject('active', lambda r: r['statuses'][-1].update(active=1))
        self.reject('active', lambda r: r.update(generation=r['generation'] + 1))

    def test_timeout_does_not_reopen_or_abort_old_work(self):
        self.reject('timeout', lambda r: r.update(worker_alive_after_timeout=False))
        def shorten(record):
            row = next(row for row in record['calls'] if row['name'] == 'timeout')
            row['end_ns'] = row['start_ns'] + 1
        self.reject('timeout', shorten)

    def test_fault_cannot_be_reported_as_success(self):
        def mutate(record):
            row = record['waiters'][0]
            row['errno'] = 0
            next(call for call in record['calls'] if call['name'] == row['name'])['errno'] = 0
        self.reject('fault', mutate)

    def test_vcpu_requires_real_blocking_and_kernel_return(self):
        self.reject('vcpu', lambda r: r.update(blocked_stack='only a userspace thread'))
        self.reject('vcpu', lambda r: r.update(trace=r['trace'].replace('ia_run_done:', 'ia_run_missing:')))

    def test_lost_trace_and_early_drain_are_rejected(self):
        self.reject('active', lambda r: r.update(trace=r['trace'].replace('ia_left:', 'ia_left_missing:', 1)))
        self.reject('active', lambda r: r['before_release'].update(waiters_finished=1))

    def test_workspace_clock_and_boot_failures_remain_rejected(self):
        rows = {row['mode']: row for row in self.evidence['workspace_runs']}
        self.assertTrue(rows['control']['operations_passed'])
        pair = rows['pair']
        self.assertFalse(pair['operations_passed'])
        self.assertGreater(pair['max_timer_ns'], 250000000)
        self.assertIsNotNone(pair['validation']['clock'][0])
        self.assertIn('RTC interrupts', pair['validation']['boot'])
        self.assertFalse(pair['analysis']['kernel_shutdown_accepted'])
        self.assertFalse(pair['full_ssi_accepted'])
        directory = Path(__file__).resolve().parent
        for name, value in [('check-clock', pair['clock_log'].split('CLOCK_START')[1]),
                            ('check-ssh-boot', pair['serial_log'])]:
            spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with self.assertRaises(ValueError):
                if name == 'check-clock':
                    module.validate('CLOCK_START' + value, 250000000)
                else:
                    module.validate(value)

    def test_export_failure_is_kept_as_rejected(self):
        rejected = self.evidence['rejected_attempts']
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]['run']['exit'], 1)
        self.assertIn("name 'json' is not defined", rejected[0]['stderr'])
        self.assertFalse(rejected[0]['accepted'])


if __name__ == '__main__':
    unittest.main()
