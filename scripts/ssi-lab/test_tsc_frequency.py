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
CANDIDATE = EVIDENCE.with_name('ssi-tsc-frequency-candidate-20261109.json')
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


class CandidateFrequencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(CANDIDATE.read_text())

    def reject(self, change, message):
        data = copy.deepcopy(self.manifest)
        change(data)
        with self.assertRaisesRegex(ValueError, message):
            tsc.check_candidate(CANDIDATE, data)

    def test_new_candidate_capture_and_preflight_replay(self):
        runs = tsc.check(CANDIDATE)['candidate']
        self.assertEqual(runs[0]['requested_khz'], 2095148)
        self.assertEqual(runs[1]['reported_khz_after_run'], 2514177)
        self.assertFalse(runs[1]['requested_rate_observed'])
        self.assertTrue(runs[2]['rejected_before_run'])

    def test_preflight_cannot_substitute_another_identity_or_rate(self):
        def clone(data):
            peers = data['preflight']['report']['peers']
            peers[1]['probe']['machine_id_sha256'] = peers[0]['probe']['machine_id_sha256']
        self.reject(clone, '身份不对应或重复')
        self.reject(lambda data: data['preflight']['report']['peers'][1]['probe']['vcpus'][0].update(
            tsc_khz=2095147), '预检频率与实测')
        self.reject(lambda data: data['preflight']['report']['peers'].reverse(), '预检节点')

    def test_reboot_must_preserve_new_identity_and_change_boot(self):
        self.reject(lambda data: data['identity_audits']['after_reboot'].update(machine='0' * 64), '克隆身份')
        self.reject(lambda data: data['identity_audits']['after_reboot'].update(ssh_host_key='0' * 64), '未持久化')
        self.reject(lambda data: data['identity_audits']['after_reboot'].update(
            boot=data['identity_audits']['before_reboot']['boot']), '独立重启')
        self.reject(lambda data: data['identity_audits'].update(
            old_machine_sha256=data['identity_audits']['after_reboot']['machine']), '克隆身份')

    def test_preflight_rejection_cannot_be_promoted_to_acceptance(self):
        for field in ('native_tsc_precheck_passed', 'physical_topology_verified',
                      'running_clock_verified', 'full_ssi_accepted'):
            with self.subTest(field=field):
                self.reject(lambda data: data['preflight']['report'].update({field: True}), '运行时验收')
        self.reject(lambda data: data['preflight'].update(exit=0), '按预期拒绝')
        self.reject(lambda data: data['preflight']['report'].update(blockers=[]), '拒绝原因')
        self.reject(lambda data: data.update(cross_physical_verified=True), '不证明跨物理')

    def test_cleanup_and_baseline_are_bound_to_capture(self):
        self.reject(lambda data: data['cleanup'].update(temporary_directory_removed=False), '临时目录')
        self.reject(lambda data: data['cleanup']['snapshot']['kvm_fds'].append({'pid': 123}), '清理后的节点')
        self.reject(lambda data: data['baseline'].update(sha256='0' * 64), '基线清单哈希')

    def test_three_modes_cannot_use_different_native_rates(self):
        baseline = json.loads(EVIDENCE.read_text())
        data = json.loads(tsc.read_artifact(CANDIDATE.parent, self.manifest['candidate']['capture']))
        slower = data['runs'][2]
        rows = [json.loads(line) for line in slower['stdout'].splitlines()]
        rows[1].update(native_khz=2394374, requested_khz=1915499, reported_khz=1915499)
        slower['stdout'] = ''.join(json.dumps(row) + '\n' for row in rows)
        with self.assertRaisesRegex(ValueError, '原生频率不一致'):
            tsc.inspect_capture(data, baseline['build'], baseline['guest_hex'])


if __name__ == '__main__':
    unittest.main()
