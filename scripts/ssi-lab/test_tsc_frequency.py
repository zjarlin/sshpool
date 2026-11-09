"""重放真实频率请求，拒绝只相信 ioctl 元数据、时间篡改和不完整清理。"""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence/ssi-tsc-frequency-20261109.json'
spec = importlib.util.spec_from_file_location('tsc', HERE / 'check-tsc-frequency.py')
tsc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tsc)


class TscFrequencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(EVIDENCE.read_text())
        cls.capture = json.loads(tsc.read_artifact(EVIDENCE.parent, cls.manifest['nodes'][0]['capture']))

    def inspect(self, capture):
        return tsc.inspect_capture(capture, self.manifest['build'], self.manifest['guest_hex'])

    def reject_run(self, mode, change, message):
        data = copy.deepcopy(self.capture)
        run = next(run for run in data['runs'] if run['mode'] == mode)
        rows = [json.loads(line) for line in run['stdout'].splitlines()]
        change(rows)
        run['stdout'] = ''.join(json.dumps(row) + '\n' for row in rows)
        with self.assertRaisesRegex(ValueError, message):
            self.inspect(data)

    def test_real_dual_node_matrix_and_failure_archives(self):
        results = tsc.check(EVIDENCE)
        self.assertEqual(len(results), 2)
        for runs in results.values():
            self.assertTrue(runs[0]['requested_rate_observed'])
            self.assertFalse(runs[1]['requested_rate_observed'])
            self.assertTrue(runs[2]['rejected_before_run'])
            self.assertLess(runs[1]['tsc_khz_bounds'][1], runs[1]['reported_khz_after_run'])

    def test_ioctl_metadata_cannot_override_actual_tsc(self):
        def change(rows):
            # 同时伪造 native 与请求读回值，实际采样仍维持原频率。
            rows[1]['native_khz'] *= 2
            rows[1]['requested_khz'] = rows[1]['reported_khz'] = rows[1]['native_khz'] * 6 // 5
            rows[-2]['reported_khz_after_run'] = rows[1]['requested_khz']
        self.reject_run('faster', change, '实测 TSC')

    def test_forged_host_elapsed_time_is_rejected(self):
        def change(rows):
            start = rows[2]['host_before_ns']
            for row in rows[2:-2]:
                for key in ('host_before_ns', 'host_after_ns'):
                    row[key] = start + (row[key] - start) * 6 // 5
        self.reject_run('faster', change, '实测 TSC')

    def test_average_cannot_hide_middle_sample_jump(self):
        self.reject_run('faster', lambda rows: rows[7].update(guest_tsc=rows[7]['guest_tsc'] + 10000000),
                        '实测 TSC')

    def test_pvclock_multiplier_and_time_are_not_trusted(self):
        for field in ('multiplier', 'system_time'):
            with self.subTest(field=field):
                def change(rows):
                    for row in rows[2:-2]:
                        row['pvclock'][field] *= 2
                self.reject_run('native', change, 'pvclock|客体时钟')

    def test_seqlock_odd_zero_and_wrong_base_are_rejected(self):
        for field, value in [('version', 7), ('version', 0), ('tsc', 2**64 - 1), ('multiplier', 0)]:
            with self.subTest(field=field, value=value):
                self.reject_run('native', lambda rows: rows[4]['pvclock'].update({field: value}), 'pvclock')

    def test_missing_duplicate_and_out_of_order_samples(self):
        self.reject_run('native', lambda rows: rows.pop(4), '生命周期顺序')
        self.reject_run('native', lambda rows: rows[4].update(index=1), '错序')
        self.reject_run('native', lambda rows: rows[4].update(guest_tsc=rows[3]['guest_tsc']), '倒退')

    def test_wide_or_reversed_bracket_is_rejected(self):
        for delta in (-1, 10000001):
            with self.subTest(delta=delta):
                self.reject_run('native', lambda rows: rows[4].update(host_after_ns=rows[4]['host_before_ns'] + delta),
                                '包络')

    def test_missing_close_and_unexpected_kvm_exit(self):
        self.reject_run('native', lambda rows: rows.pop(), '关闭')
        self.reject_run('native', lambda rows: rows[-2].update(exit_reason=2), 'HLT')
        self.reject_run('native', lambda rows: rows[-2].update(rip=4096), 'HLT')

    def test_set_rejection_cannot_execute(self):
        self.reject_run('slower', lambda rows: rows[-1].update(run_calls=1), '执行次数')
        sample = json.loads(self.capture['runs'][0]['stdout'].splitlines()[2])
        self.reject_run('slower', lambda rows: rows.insert(2, sample), '设置失败后仍执行')

    def test_changed_after_run_metadata_is_visible(self):
        self.reject_run('faster', lambda rows: rows[-2].update(reported_khz_after_run=1), '报告频率变化')

    def test_source_binary_hashes_and_dirty_state_rejected(self):
        for key in ('source_sha256', 'capture_sha256', 'binary_sha256'):
            data = copy.deepcopy(self.capture)
            data[key] = '0' * 64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '哈希'):
                self.inspect(data)
        data = copy.deepcopy(self.capture)
        data['after']['kvm_fds'].append({'pid': 123, 'fd': '7', 'target': 'anon_inode:kvm-vcpu'})
        with self.assertRaisesRegex(ValueError, '清理状态'):
            self.inspect(data)

    def test_corrupt_compressed_archive_or_raw_hash_rejected(self):
        artifact = self.manifest['nodes'][0]['capture']
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = (EVIDENCE.parent / artifact['file']).read_bytes()
            (directory / artifact['file']).write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, '归档哈希'):
                tsc.read_artifact(directory, artifact)
        bad = {**artifact, 'raw_sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, '原始内容哈希'):
            tsc.read_artifact(EVIDENCE.parent, bad)

    def test_wrong_kernel_guard_precedes_paths_and_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(HERE / 'capture-tsc-frequency.py'),
                '--require-kernel', 'kernel-must-not-match', '--binary', '/no/binary',
                '--binary-sha256', 'invalid', '--source', '/no/source', '--output', str(output)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
