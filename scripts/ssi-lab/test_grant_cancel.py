"""用真实 PF30 归档及破坏样本验证取消窗口、资源释放与失败传播。"""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence'
spec = importlib.util.spec_from_file_location('checker', HERE / 'check-grant-cancel.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class GrantCancelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((EVIDENCE / 'ssi-grant-cancel-20261109.json').read_text())
        cls.runs = {item['label']: item for item in cls.manifest['runs']}

    def capture(self, artifact):
        raw = (EVIDENCE / artifact['file']).read_bytes()
        self.assertEqual(len(raw), artifact['bytes'])
        self.assertEqual(sha(raw), artifact['sha256'])
        unpacked = gzip.decompress(raw)
        self.assertEqual(sha(unpacked), artifact['raw_sha256'])
        return json.loads(unpacked)

    def probe(self, label):
        return self.capture(self.runs[label]['archive'])['probe']

    def reject(self, change, message, label='handler-1000-c'):
        data = self.probe(label)
        change(data)
        with self.assertRaisesRegex(ValueError, message):
            checker.inspect(data)

    def test_real_control_cancel_and_reset_records_replay(self):
        self.assertEqual(set(self.runs), {'control-1000-b', 'control-off-a', 'handler-1000-b',
                                         'handler-1000-c', 'root-1000-a', 'reset-1000-d'})
        for record in self.runs.values():
            with self.subTest(label=record['label']):
                bundle = self.capture(record['archive'])
                self.assertEqual(checker.inspect(bundle['probe']), record['analysis'])
                self.assertEqual(bundle['runner']['exit'], 0)
                self.assertEqual(bundle['runner']['capture_exit'], 0)
                self.assertEqual(bundle['firewall']['before'], bundle['firewall']['after'])
                self.assertTrue(bundle['firewall']['restored_exactly'])
                self.assertNotRegex(bundle['host_log'], r'BUG:|WARNING:|Oops:|panic|scheduling while atomic')
                self.assertFalse(record['analysis']['full_ssi_accepted'])
                self.assertFalse(record['analysis']['native_close_accepted'])
        self.assertEqual(self.runs['control-off-a']['analysis']['sleep_count'], 0)
        self.assertEqual(self.runs['handler-1000-b']['analysis']['wait_return_code'], 0)
        self.assertEqual(self.runs['handler-1000-c']['analysis']['wait_return_code'], -4)
        self.assertEqual(self.runs['reset-1000-d']['analysis']['first_error'], -32)

    def test_preparation_and_incomplete_captures_stay_rejected(self):
        rejected = {row['label']: row for row in self.manifest['rejected']}
        self.assertEqual(set(rejected), {'control-1000-a', 'handler-1000-a', 'reset-1000-a', 'reset-1000-b', 'reset-1000-c'})
        for record in rejected.values():
            with self.subTest(label=record['label']):
                bundle = self.capture(record['archive'])
                self.assertFalse(record['accepted'])
                self.assertEqual(bundle['firewall']['before'], bundle['firewall']['after'])
                with self.assertRaises((ValueError, KeyError)):
                    checker.inspect(bundle['probe'])
        self.assertEqual(self.capture(rejected['control-1000-a']['archive'])['probe']['worker_records'], [])
        self.assertEqual(rejected['reset-1000-b']['reason'], '阶段记录不一致')

    def test_late_signal_cannot_count_as_in_wait_cancellation(self):
        def move(data):
            lines = data['trace'].splitlines()
            target = data['signal_target']
            index = next(i for i, line in enumerate(lines) if 'signal_generate:' in line and
                         f'pid={target} ' in line and 'code=-6 ' in line)
            original = lines.pop(index)
            wake = next(i for i in range(index, len(lines)) if 'gc_wake:' in lines[i])
            stamp = checker.safety.teardown.EVENT.fullmatch(lines[wake])[4]
            original = re.sub(r'\d+\.\d+(?=: signal_generate:)', stamp, original)
            lines.insert(wake + 1, original)
            data['trace'] = '\n'.join(lines) + '\n'
        self.reject(move, '取消或故障未落在已观察到的等待内')

    def test_sleeping_with_page_lock_or_srcu_is_rejected(self):
        def swap(data, event):
            lines = data['trace'].splitlines()
            sleep = next(i for i, line in enumerate(lines) if 'gc_sleep:' in line)
            before = max(i for i, line in enumerate(lines[:sleep]) if event + ':' in line)
            first = checker.safety.teardown.EVENT.fullmatch(lines[before])
            last = checker.safety.teardown.EVENT.fullmatch(lines[sleep])
            lines[before] = lines[before].replace(first[5] + ': ' + first[6], last[5] + ': ' + last[6])
            lines[sleep] = lines[sleep].replace(last[5] + ': ' + last[6], first[5] + ': ' + first[6])
            data['trace'] = '\n'.join(lines) + '\n'
        for event in ('gc_unlock', 'gc_srcu_done'):
            with self.subTest(event=event):
                self.reject(lambda data: swap(data, event), '等待时仍持锁或 SRCU')

    def test_loss_identity_and_forged_notification_are_rejected(self):
        def loss(data):
            key = next(iter(data['trace_stats']))
            data['trace_stats'][key] = data['trace_stats'][key].replace('overrun: 0', 'overrun: 1', 1)
        self.reject(loss, '跟踪丢失')
        self.reject(lambda data: data.update(worker_pid=data['worker_pid'] + 1), '工作进程身份错误')
        self.reject(lambda data: data.update(notification=data['notification'].replace('delay=100000', 'delay=99999')), '通知不属于归档等待')
        self.reject(lambda data: data.update(signal_target=data['root_pid']), '信号目标错误')

    def test_fault_must_exit_before_cleanup_and_reject_management(self):
        self.reject(lambda data: data.update(tasks_after_action={'1': {'name': 'kvm-dsm/0'}}), '缺少清理前已退出的完整快照与跟踪')
        self.reject(lambda data: data.update(worker_stderr=''), '缺少故障后的管理调用拒绝')
        self.reject(lambda data: data.update(after_action_data='ff'), '故障请求仍返回页面')
        def root_code(data):
            data['trace'] = re.sub(r'(gc_root_done:.*code=)-4', r'\g<1>0', data['trace'])
        self.reject(root_code, '首个故障被覆盖')

    def test_reset_requires_actual_tuple_and_failed_send(self):
        def wrong_peer(data):
            data['connection']['local'][1] += 1
        self.reject(wrong_peer, '复位不属于受控连接', 'reset-1000-d')
        def success(data):
            data['trace'] = re.sub(r'(gc_sent:.*code=)-32', r'\g<1>4110', data['trace'])
        self.reject(success, '复位后的发送伪装成功', 'reset-1000-d')

    def test_control_page_and_zero_grace_are_checked(self):
        def payload(data):
            raw = bytearray.fromhex(data['response']['hex'])
            raw[-1] ^= 1
            data['response']['hex'] = raw.hex()
        self.reject(payload, '对照页面内容错误', 'control-1000-b')
        self.reject(lambda data: data.update(grace_us=0), '零开关仍等待', 'control-1000-b')

    def test_sources_match_actual_collectors_and_kernel_snapshots(self):
        source = self.manifest['sources']
        raw = (EVIDENCE / source['file']).read_bytes()
        self.assertEqual(sha(raw), source['sha256'])
        self.assertEqual(sha(gzip.decompress(raw)), source['raw_sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            files = {item.name: archive.extractfile(item).read() for item in archive.getmembers()}
        self.assertEqual({name: sha(raw) for name, raw in files.items()}, source['members'])
        for name in ('probe-grant-cancel.py', 'check-grant-cancel.py'):
            self.assertEqual(files[name], (HERE / name).read_bytes())
        for record in self.manifest['runs'] + self.manifest['rejected']:
            bundle = self.capture(record['archive'])
            for name, digest in bundle['source_hashes'].items():
                self.assertEqual(sha(files['attempts/' + record['label'] + '/' + name]), digest)
            self.assertEqual(bundle['runner']['node']['kernel_sha256'], self.manifest['kernel_sha256'])
        compiled = json.loads(files['lab/compiled-source-hashes.json'])
        for name, digest in compiled.items():
            self.assertEqual(sha(files['kernel/' + name]), digest)
        self.assertEqual(sha(files['probe-write-grant.c']), self.manifest['probe_build']['source_sha256'])
        restored = self.manifest['restoration']['nodes']
        self.assertEqual(len(restored), 1)
        node = restored[0]
        self.assertEqual(node['kernel'], '6.8.0-147-generic')
        self.assertEqual(node['boot_hash_manifest_sha256'], sha(files['lab/node0-before-boot.sha256']))
        for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged', 'firewall_matches_original'):
            self.assertTrue(node[key])
        for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
            self.assertEqual(node[key], [])
        self.assertEqual(self.manifest['node1-final']['kernel'], '6.8.0-147-generic')
        self.assertTrue(self.manifest['node1-final']['unchanged'])

    def test_wrong_kernel_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(HERE / 'probe-grant-cancel.py'), '--require-kernel',
                                     'kernel-must-not-match', '--worker', '/does-not-exist', '--mode', 'control',
                                     '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
