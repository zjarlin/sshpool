"""防止把单物理机 VM 或真实构建卸载误报成跨物理 SSI 与存储容错。"""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('physical', Path(__file__).with_name('check-physical-host.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
EVIDENCE = json.loads((ROOT / 'docs/evidence/ssi-physical-host-20261107.json').read_text())


class PhysicalHostProofTests(unittest.TestCase):
    def reject(self, mutate):
        data = copy.deepcopy(EVIDENCE)
        mutate(data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            checker.check(data)

    def test_recorded_physical_execution_and_build_scope(self):
        result = checker.check(EVIDENCE)
        self.assertEqual(result['logical_cpus'], 32)
        self.assertEqual(result['isolated_vm_vcpus'], 8)
        self.assertTrue(result['build_offload_verified'])
        self.assertFalse(result['cross_physical_ssi_verified'])
        self.assertFalse(result['distributed_storage_verified'])
        self.assertFalse(result['full_ssi_accepted'])

    def test_public_evidence_contains_no_addresses_or_credentials(self):
        serialized = json.dumps(EVIDENCE, ensure_ascii=False)
        self.assertIsNone(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', serialized))
        for marker in ('password', 'ssh_user', 'private_key', '192.168.', 'Okmy'):
            self.assertNotIn(marker, serialized)

    def test_unconfirmed_disk_cannot_be_touched(self):
        for key in ('additional_disk_touched', 'raid_created', 'lvm_created', 'osd_created', 'ceph_deployed'):
            self.reject(lambda data, key=key: data['storage'].__setitem__(key, True))
        self.reject(lambda data: data['storage'].__setitem__('additional_disk_ownership_confirmed', True))
        self.reject(lambda data: data['storage'].__setitem__('additional_disk_filesystem_identified', True))

    def test_vm_cannot_mount_business_data_or_remain_running(self):
        for key in ('host_business_directory_mounted', 'host_business_block_device_passed', 'virtfs_or_9p_configured'):
            self.reject(lambda data, key=key: data['isolated_vm'].__setitem__(key, True))
        self.reject(lambda data: data['isolated_vm'].__setitem__('remaining_qemu_process', True))
        self.reject(lambda data: data['isolated_vm']['kvm_vcpu_thread_ticks'].pop())

    def test_failed_build_or_cleanup_cannot_pass(self):
        for key, value in (('phase', 'failed'), ('exit_code', 1), ('cleanup_confirmed', False),
                           ('container_remaining', True), ('artifact_runs_on_worker', False)):
            self.reject(lambda data, key=key, value=value: data['build_offload'].__setitem__(key, value))

    def test_scope_claims_are_not_promoted_from_offload_success(self):
        for key in ('full_ssi_accepted', 'automatic_host_failover_verified',
                    'database_migration_or_failover_verified', 'no_raid_distributed_storage_verified'):
            self.reject(lambda data, key=key: data['claims'].__setitem__(key, True))
        self.reject(lambda data: data['cross_physical_preflight'].__setitem__('same_process_across_physical_hosts', True))
        self.reject(lambda data: data['cross_physical_preflight'].__setitem__('cpu_and_memory_capacity_aggregated', True))

    def test_critical_configuration_hash_drift_is_rejected(self):
        self.reject(lambda data: data['physical_host']['critical_configuration'].__setitem__(
            'sshd_config_sha256_after', '0' * 64))
        self.reject(lambda data: data['privacy'].__setitem__('company_files_used', True))


if __name__ == '__main__':
    unittest.main()
