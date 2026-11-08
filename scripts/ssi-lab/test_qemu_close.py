"""重放 QEMU 关闭与块层失败证据，防止退出零、漏采或删日志冒充整机验收。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from test_kernel_close import rewrite_trace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('close', HERE / 'check-qemu-close.py')
close = importlib.util.module_from_spec(spec)
spec.loader.exec_module(close)
block = close.load('check-close-devices')


class QemuCloseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-qemu-close-20261108.json').read_text())
        cls.pair = next(row for row in cls.evidence['workspace_runs'] if row['mode'] == 'pair')

    def reject(self, mutate, message=None):
        row = deepcopy(self.pair)
        mutate(row)
        with self.assertRaisesRegex(ValueError, message or '.'):
            close.inspect(row)

    def test_real_workspace_and_three_block_cases(self):
        self.assertEqual(close.inspect(self.pair), self.pair['close_analysis'])
        rows = self.evidence['block_runs']
        self.assertEqual([row['run']['error'] for row in rows], [0, 5, 28])
        for row in rows:
            self.assertEqual(block.inspect(row), row['analysis'])
            self.assertFalse(row['analysis']['persistent_io_accepted'])
            self.assertFalse(row['analysis']['full_ssi_accepted'])
            self.assertTrue(all(not value for name, value in row['supervision'].items() if 'stderr' in name))

    def test_workspace_operations_and_warnings_remain_separate(self):
        clock, stress = close.load('check-clock'), close.load('check-stress')
        self.assertEqual([row['mode'] for row in self.evidence['workspace_runs']], ['control', 'pair'])
        for row in self.evidence['workspace_runs']:
            result, files = row['result'], row['files']
            for name in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(result['phases'][name]['exit'], 0)
            self.assertEqual(result['phases']['poweroff']['exit'], 255)
            self.assertIn('reboot: Power down', row['serial_log'])
            self.assertEqual(result['qemu_ssh_exits'], [0] if row['mode'] == 'control' else [0, 0])
            stress.validate(files['stress.log'])
            trials = re.findall(r'CLOCK_START[^\n]*\n.*?CLOCK_PASS[^\n]*', files['clock.log'], re.S)
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250_000_000)
            self.assertEqual(row['sftp']['bytes'], 1048576)
            self.assertEqual(row['sftp']['input_sha256'], row['sftp']['output_sha256'])
            self.assertEqual(row['sftp']['output_sha256'], result['sftp_sha256'])
            self.assertEqual(row['firewall']['before'], row['firewall']['after'])
            for log in row['host_logs']:
                self.assertNotRegex(log, r'WARNING:|BUG:|Oops:|Kernel panic|hung task|kvm-dsm:.*failed')
            self.assertFalse(row['full_ssi_accepted'])
        self.assertIn('skipping watchdog check', self.pair['serial_log'])
        self.assertIn('hogged CPU', self.pair['serial_log'])

    def test_source_patch_replays_to_compiled_bytes(self):
        evidence = self.evidence
        build = evidence['build']
        self.assertEqual(build['sha256'], close.RUNTIME)
        patch = HERE / 'experiments/qemu-global-close.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), build['patch_sha256'])
        for field, hashes in (('original_sources', evidence['original_source_sha256']),
                              ('compiled_sources', build['compiled_source_sha256'])):
            for name, expected in hashes.items():
                self.assertEqual(hashlib.sha256(evidence[field][name].encode()).hexdigest(), expected)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name, source in evidence['original_sources'].items():
                file = target / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(source)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                           cwd=target, check=True, capture_output=True)
            for name, source in evidence['compiled_sources'].items():
                self.assertEqual((target / name).read_text(), source)
        for group in ('trace_sources', 'block_sources'):
            for name, expected in evidence[group]['hashes'].items():
                self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), expected)

    def test_unrealize_must_follow_cpu_quiescence(self):
        def reorder(row):
            log = row['qemu_stderr'][0]
            device = 'SSI_DEVICE_UNREALIZED type=virtio-net-device\n'
            log = log.replace(device, '')
            row['qemu_stderr'][0] = log.replace('SSI_QUIESCE_COMPLETE', device + 'SSI_QUIESCE_COMPLETE')
        self.reject(reorder, '设备清理早于')

    def test_peer_identity_and_both_barriers_are_required(self):
        self.reject(lambda row: row['qemu_stderr'].__setitem__(1, row['qemu_stderr'][1].replace(
                    'SSI_QUIESCE_ACK_SENT node=1 peer=0', 'SSI_QUIESCE_ACK_SENT node=1 peer=1')))
        self.reject(lambda row: row['qemu_stderr'].__setitem__(0, row['qemu_stderr'][0].replace(
                    'SSI_DRAIN_COMPLETE', 'MISSING_DRAIN_COMPLETE')))

    def test_zero_pins_and_matching_generations_are_required(self):
        self.reject(lambda row: row['qemu_stderr'].__setitem__(0, row['qemu_stderr'][0].replace(
                    'active=0 read=0 write=0', 'active=0 read=1 write=0')))
        self.reject(lambda row: row['qemu_stderr'].__setitem__(1, row['qemu_stderr'][1].replace(
                    'generation=2623579332469', 'generation=2623579332470')))

    def test_root_must_finish_before_close_returns(self):
        self.reject(lambda row: rewrite_trace(row['traces'][0],
                    lambda lines: [line for line in lines if 'kc_root_done:' not in line]), '根线程回收')
        def late_root(row):
            def reorder(lines):
                root = next(line for line in lines if 'kc_root_done:' in line)
                remaining = [line for line in lines if 'kc_root_done:' not in line]
                at = next(i for i, line in enumerate(remaining) if 'kc_closed:' in line) + 1
                return remaining[:at] + [root] + remaining[at:]
            rewrite_trace(row['traces'][0], reorder)
        self.reject(late_root, '根线程回收')

    def test_late_vm_ioctl_and_missing_connection_are_rejected(self):
        def late_ioctl(row):
            def reorder(lines):
                indices = [next(i for i, line in enumerate(lines) if token in line)
                           for token in ('kc_ioctl:', 'kc_return:')]
                moved = [lines[i] for i in indices]
                remaining = [line for i, line in enumerate(lines) if i not in indices]
                return remaining[:-1] + moved + remaining[-1:]
            rewrite_trace(row['traces'][0], reorder)
        self.reject(late_ioctl)
        self.reject(lambda row: rewrite_trace(row['traces'][0], lambda lines:
                    [line for line in lines if 'kc_eof:' not in line and 'kc_eof_done:' not in line]), 'EOF')

    def test_hash_lost_trace_and_remaining_tasks_are_rejected(self):
        self.reject(lambda row: row['result'].update(qemu_sha256='0' * 64), '身份')
        self.reject(lambda row: row['traces'][0].update(probe_sha256='0' * 64), '身份')
        self.reject(lambda row: row['traces'][0].update(trace=''), '.')
        self.reject(lambda row: row['traces'][0].update(remaining_tasks={'1': 'kvm-dsm/0'}), '线程')

    def test_block_error_cannot_be_relabelled_as_normal_shutdown(self):
        for original in self.evidence['block_runs'][1:]:
            row = deepcopy(original)
            row['records'][0]['qemu_exit'] = 0
            with self.assertRaisesRegex(ValueError, '错误退出'):
                block.inspect(row)
            row = deepcopy(original)
            row['records'][0]['stderr'] = row['records'][0]['stderr'].replace('retains I/O status', 'hidden')
            with self.assertRaisesRegex(ValueError, '后端错误'):
                block.inspect(row)
            row = deepcopy(original)
            row['records'][1]['stderr'] += '\nSSI_DEVICE_CLOSE_COMPLETE\n'
            with self.assertRaisesRegex(ValueError, '伪装'):
                block.inspect(row)

    def test_restore_and_scope_are_explicit(self):
        self.assertFalse(self.evidence['persistent_io_accepted'])
        self.assertFalse(self.evidence['full_ssi_accepted'])
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['post_restore']['kernel'].strip(), '6.8.0-147-generic')
            self.assertEqual(node['post_restore']['trace'], '')
            self.assertEqual(node['post_restore']['tcp'], '')
            self.assertEqual(node['remaining_processes'], [])
            self.assertTrue(node['identity_matches'] and node['old_boot_files_unchanged'] and
                            node['firewall_matches_original'] and node['stock_grub_default'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['grub_environment'], '')


if __name__ == '__main__':
    unittest.main()
