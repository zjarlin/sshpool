"""重放双节点原子计数，并验证重复返回值、假并发和关闭顺序不能冒充通过。"""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence'
spec = importlib.util.spec_from_file_location('atomic', HERE / 'check-atomic-grant.py')
atomic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atomic)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class AtomicGrantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((EVIDENCE / 'ssi-atomic-grant-20261109.json').read_text())
        cls.runs = {row['label']: row for row in cls.evidence['runs']}
        cls.data = json.loads(gzip.decompress((EVIDENCE / cls.runs['pair-off-a']['archive']['file']).read_bytes()))

    def reject(self, change, pattern):
        data = deepcopy(self.data)
        change(data)
        with self.assertRaisesRegex(ValueError, pattern):
            atomic.inspect(data)

    def test_all_complete_runs_replay(self):
        self.assertEqual(set(self.runs), {'control-a', 'pair-off-a', 'pair-1000-a', 'pair-off-c', 'pair-1000-b'})
        for label, run in self.runs.items():
            with self.subTest(label=label):
                raw = (EVIDENCE / run['archive']['file']).read_bytes()
                self.assertEqual(sha(raw), run['archive']['sha256'])
                self.assertEqual(len(raw), run['archive']['bytes'])
                unpacked = gzip.decompress(raw)
                self.assertEqual(sha(unpacked), run['raw_sha256'])
                data = json.loads(unpacked)
                self.assertEqual(data['binary_sha256'], self.evidence['probe_build']['binary_sha256'])
                result = atomic.inspect(data)
                self.assertEqual(result, run['analysis'])
                self.assertEqual(result['total_operations'], 128 if label == 'control-a' else 8192)
                self.assertTrue(result['all_tickets_unique_and_contiguous'])
                self.assertFalse(result['general_fairness_proven'])
                self.assertFalse(result['cross_host_clock_alignment_established'])
                self.assertFalse(result['full_ssi_accepted'])

    def test_cross_node_duplicate_is_rejected_even_when_local_order_is_valid(self):
        def change(data):
            operations = sorted((row for row in data['events'] if row['record']['op'] == 'atomic'),
                                key=lambda row: row['record']['previous'])
            first, second = next((a, b) for a, b in zip(operations, operations[1:]) if a['node'] != b['node'])
            first['record']['previous'] = second['record']['previous']
        self.reject(change, '跨节点原子计数')

    def test_local_counter_regression_and_missing_operation_are_rejected(self):
        def repeat(data):
            records = [row['record'] for row in data['events'] if row['node'] == 0 and row['record']['op'] == 'atomic']
            records[1]['previous'] = records[0]['previous']
        self.reject(repeat, '本节点返回计数')
        def remove(data):
            index = next(i for i, row in enumerate(data['events']) if row['record']['op'] == 'atomic')
            del data['events'][index]
        self.reject(remove, '次序或数量')

    def test_hlt_and_return_fields_are_required(self):
        for field, value in [('exit_reason', 4), ('rip', 0x1005), ('elapsed_ns', -1), ('previous', 8192), ('previous', True)]:
            def change(data):
                next(row['record'] for row in data['events'] if row['record']['op'] == 'atomic')[field] = value
            self.reject(change, '指令未完成或返回值越界')

    def test_adjacent_guard_and_final_count_are_not_optional(self):
        for field, value in [('guard', 0), ('value', 8191)]:
            def change(data):
                [row['record'] for row in data['events'] if row['record']['op'] == 'read'][-1][field] = value
            self.reject(change, '计数或相邻哨兵')

    def test_sequential_batches_do_not_prove_concurrency(self):
        def change(data):
            logs = [[row for row in data['events'] if row['node'] == node] for node in (0, 1)]
            amount = data['amount']
            prefix = logs[0][:4] + logs[1][:4]
            batches = logs[0][4:6 + amount] + logs[1][4:6 + amount]
            tail = logs[0][6 + amount:] + logs[1][6 + amount:]
            data['events'] = prefix + batches + tail
            for index, row in enumerate(data['events']):
                row['received_ns'] = index
        self.reject(change, '没有并发批次')

    def test_close_generation_cleanup_and_profile_are_required(self):
        def generation(data):
            next(row['record'] for row in data['events'] if row['record']['op'] == 'sealed')['generation'] += 1
        self.reject(generation, '代际')
        self.reject(lambda data: data.update(cleanup_verified=False), '清理')
        self.reject(lambda data: data.update(grace_after=[1000, 0]), '参数未恢复')
        self.reject(lambda data: data.update(grace_active=[1000, 0]), '不一致')
        self.reject(lambda data: data['kernel_hashes'].update({'1': '0' * 64}), '内核哈希')
        self.reject(lambda data: data['worker_exits'][0].update(exit=1), '探针退出')

    def test_atomic_instruction_boundary_uses_its_actual_hlt_address(self):
        rows = [
            {'name': 'tracing_mark_write', 'detail': 'grant_begin value=1', 'ns': 1},
            {'name': 'kvm_page_fault', 'detail': 'vcpu 0 rip 0x1007 address 0x1000 error_code 0x784', 'ns': 2},
            {'name': 'tracing_mark_write', 'detail': 'grant_end value=1', 'ns': 3},
        ]
        self.assertEqual(len(atomic.grant.invocations(rows, 0, hlt_rip=0x1007)), 1)
        with self.assertRaisesRegex(ValueError, '固定客体'):
            atomic.grant.invocations(rows, 0)

    def test_default_store_mode_still_replays_with_the_original_checker(self):
        record = self.evidence['compatibility']
        raw = (EVIDENCE / record['archive']['file']).read_bytes()
        self.assertEqual(sha(raw), record['archive']['sha256'])
        unpacked = gzip.decompress(raw)
        self.assertEqual(sha(unpacked), record['raw_sha256'])
        self.assertEqual(atomic.grant.inspect(json.loads(unpacked)), record['analysis'])
        self.assertEqual(record['analysis']['0']['writes'], 64)

    def test_source_and_compiled_binary_evidence_are_bound_to_new_runs(self):
        source = self.evidence['sources']
        raw = (EVIDENCE / source['archive']['file']).read_bytes()
        self.assertEqual(sha(raw), source['archive']['sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
        self.assertEqual({name: sha(data) for name, data in files.items()}, source['sha256'])
        self.assertEqual(files['probe-write-grant.c'], (HERE / 'probe-write-grant.c').read_bytes())
        self.assertEqual(sha(files['probe-write-grant.c']), self.evidence['probe_build']['source_sha256'])
        collectors = {
            'control-a': 'run_atomic-first.py', 'pair-off-a': 'run_atomic-first.py',
            'pair-1000-a': 'run_atomic-first.py', 'pair-off-c': 'run_atomic-readiness.py',
            'pair-1000-b': 'run_atomic.py',
        }
        for label, collector in collectors.items():
            self.assertEqual(self.runs[label]['collector_source'], collector)
            self.assertIn(collector, files)
        for node in self.evidence['restoration']['nodes']:
            before = files[f"node{node['node']}-before-boot.sha256"]
            self.assertEqual(sha(before), node['boot_hash_manifest_sha256'])
        prior = json.loads((EVIDENCE / 'ssi-write-grant-20261108.json').read_text())
        self.assertEqual(sha(files['probe-before.c']), prior['probe_build']['source_sha256'])

    def test_cli_rejects_a_corrupted_counter(self):
        data = deepcopy(self.data)
        next(row['record'] for row in data['events'] if row['record']['op'] == 'atomic')['previous'] = -1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'invalid.json'
            path.write_text(json.dumps(data))
            result = subprocess.run([sys.executable, str(HERE / 'check-atomic-grant.py'), str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('返回值越界', result.stderr)

    def test_original_boot_and_firewall_are_restored(self):
        self.assertFalse(self.evidence['runtime_kernel_changed'])
        self.assertFalse(self.evidence['full_ssi_accepted'])
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged',
                        'firewall_matches_original', 'stock_grub_default', 'pf30_grub_entry_removed',
                        'write_grace_reset_before_reboot'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])

    def test_startup_connection_failure_remains_a_rejected_run(self):
        self.assertEqual(len(self.evidence['failed_runs']), 1)
        failure = self.evidence['failed_runs'][0]
        self.assertEqual(failure['label'], 'pair-off-b')
        self.assertFalse(failure['accepted'])
        self.assertFalse(failure['cause_established'])
        self.assertEqual(failure['collector_source'], 'run_atomic-first.py')
        raw = (EVIDENCE / failure['archive']['file']).read_bytes()
        self.assertEqual(sha(raw), failure['archive']['sha256'])
        unpacked = gzip.decompress(raw)
        self.assertEqual(sha(unpacked), failure['raw_sha256'])
        data = json.loads(unpacked)
        with self.assertRaises(ValueError):
            atomic.inspect(data)
        self.assertFalse(any(row['record']['op'] in ('armed', 'batch_started', 'atomic', 'sealed', 'closed')
                             for row in data['events']))
        self.assertIn('errno=110', failure['logs']['node1-stderr'])
        self.assertIn('errno=111', failure['logs']['node0-stderr'])
        self.assertEqual(data['firewall_before'], data['firewall_after'])
        self.assertEqual(data['grace_after'], [0, 0])
        recovered_raw = (EVIDENCE / failure['recovered_trace']['file']).read_bytes()
        self.assertEqual(sha(recovered_raw), failure['recovered_trace']['sha256'])
        recovered = json.loads(gzip.decompress(recovered_raw))
        self.assertTrue(recovered['worker_pid_absent'])
        self.assertTrue(recovered['cleanup_complete'])


if __name__ == '__main__':
    unittest.main()
