"""用真实候选和保留失败验证计时准入，篡改任一路径都必须拒绝。"""
import copy
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence/ssi-tsc-scaling-20261109.json'
spec = importlib.util.spec_from_file_location('scaling', HERE / 'check-tsc-scaling.py')
scaling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scaling)


class TscScalingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(EVIDENCE.read_text())
        cls.build = cls.manifest['builds']['pf32']
        cls.capture = json.loads(scaling.read_artifact(EVIDENCE.parent, cls.manifest['captures'][3]['capture']))
        cls.identity = dict(cls.capture['before']['identity_sha256'], boot='0' * 64)
        cls.sources = json.loads(scaling.read_artifact(EVIDENCE.parent, cls.manifest['sources']))

    def inspect(self, data):
        return scaling.inspect_capture(data, self.build, self.identity, self.manifest['native_khz'],
                                       self.manifest['target_khz'], True)

    def reject(self, change, message, selection='software', mode='target'):
        data = copy.deepcopy(self.capture)
        run = next(row for row in data['runs'] if row['selection'] == selection and row['mode'] == mode)
        rows = [json.loads(line) for line in run['stdout'].splitlines()]
        change(rows)
        run['stdout'] = ''.join(json.dumps(row) + '\n' for row in rows)
        with self.assertRaisesRegex(ValueError, message):
            self.inspect(data)

    def test_actual_matrix_preserves_failed_msr_candidate(self):
        results = scaling.check(EVIDENCE)
        self.assertEqual(len(results), 4)
        self.assertEqual(sum('rejected' in run for run in results['pf31-on']), 3)
        self.assertTrue(all(run['requested_rate_observed'] for run in results['pf32-on'][4:]))
        self.assertTrue(results['pf32-off'][-1]['unavailable'])

    def test_every_clock_is_required_and_cannot_use_native_rate(self):
        for key in scaling.CLOCKS:
            with self.subTest(key=key):
                def change(rows):
                    start = rows[2][key]
                    for row in rows[2:14]:
                        row[key] = start + (row[key] - start) * 7 // 8
                self.reject(change, '顺序|实测速率|倒退')

    def test_matching_rates_with_wrong_zero_are_rejected(self):
        self.reject(lambda rows: [row.update(guest_msr=row['guest_msr'] + 10000000) for row in rows[2:14]], '零点')

    def test_requested_metadata_is_insufficient(self):
        self.reject(lambda rows: rows[1].update(reported_khz=2095148), '频率配置')
        self.reject(lambda rows: rows[14].update(reported_khz_after_run=2095148), '元数据')

    def test_pvclock_conversion_and_version_are_checked(self):
        self.reject(lambda rows: [row['pvclock'].update(multiplier=row['pvclock']['multiplier'] // 2)
                                  for row in rows[2:14]], 'pvclock')
        self.reject(lambda rows: rows[5]['pvclock'].update(version=3), 'pvclock')

    def test_middle_jump_cannot_hide_in_long_average(self):
        def change(rows):
            for key in scaling.CLOCKS:
                rows[7][key] += 10000000
        self.reject(change, '实测速率')

    def test_missing_duplicate_wide_or_reversed_samples(self):
        self.reject(lambda rows: rows.pop(5), '顺序')
        self.reject(lambda rows: rows[5].update(index=2), '错序')
        self.reject(lambda rows: rows[5].update(host_after_ns=rows[5]['host_before_ns'] - 1), '包络')
        self.reject(lambda rows: rows[5].update(host_after_ns=rows[5]['host_before_ns'] + 10000001), '包络')

    def test_rdtscp_aux_and_late_configuration_guards(self):
        self.reject(lambda rows: rows[5].update(tsc_aux=0), 'AUX')
        self.reject(lambda rows: rows[15].update(rate_result=0), '运行后改频')
        self.reject(lambda rows: rows[15].update(attribute_errno=22), '运行后改频')
        self.reject(lambda rows: rows[15].update(selected=True), '普通实例', selection='control')

    def test_hardware_unavailable_and_unselected_samples_are_not_accepted(self):
        for values in ({'control': 1}, {'selected': False}, {'attribute_supported': False}):
            with self.subTest(values=values):
                self.reject(lambda rows: rows[1].update(values), '硬件能力|选择')

    def test_failed_setup_must_not_execute_and_exit_must_halt(self):
        self.reject(lambda rows: rows[-1].update(run_calls=1), '执行次数', selection='control', mode='slower')
        self.reject(lambda rows: rows[14].update(exit_reason=2), 'HLT')
        self.reject(lambda rows: rows.pop(), '关闭')

    def test_mixed_node_stale_boot_dirty_state_and_wrong_kernel_rejected(self):
        for key in ('machine', 'dmi'):
            data = copy.deepcopy(self.capture)
            for side in ('before', 'after'):
                data[side]['identity_sha256'][key] = 'f' * 64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '其他节点'):
                self.inspect(data)
        data = copy.deepcopy(self.capture)
        data['after']['kvm_fds'] = [{'pid': 1, 'fd': '3', 'target': '/dev/kvm'}]
        with self.assertRaisesRegex(ValueError, '清理状态'):
            self.inspect(data)
        data = copy.deepcopy(self.capture)
        for side in ('before', 'after'):
            data[side]['identity_sha256']['boot'] = self.identity['boot']
        with self.assertRaisesRegex(ValueError, '原版启动身份'):
            self.inspect(data)
        data = copy.deepcopy(self.capture)
        data['binary_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '二进制'):
            self.inspect(data)

    def test_patches_reproduce_archived_sources_and_guard_wrong_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, source in self.sources['pf30'].items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            for label, patch in [('pf31', 'kernel-software-tsc.patch'), ('pf32', 'kernel-software-tsc-msr.patch')]:
                subprocess.run(['patch', '--batch', '-p1', '-d', str(root)], input=self.sources['patches'][patch],
                               text=True, capture_output=True, check=True)
                for name in self.sources['pf30']:
                    self.assertEqual((root / name).read_text(), self.sources[label][name])
            for kind, extension in [('probe', 'c'), ('capture', 'py')]:
                filename = kind + '-tsc-frequency.' + extension
                (root / filename).write_text(self.sources['base_' + kind])
                subprocess.run(['patch', '--batch', '-p1', '-d', str(root)],
                               input=self.sources['patches'][kind + '-tsc-scaling.patch'],
                               text=True, capture_output=True, check=True)
                self.assertEqual((root / filename).read_text(), self.sources[kind + '-tsc-scaling.' + extension])
            output = root / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(root / 'capture-tsc-frequency.py'),
                '--require-kernel', 'kernel-must-not-match', '--binary', '/no/binary', '--binary-sha256', 'invalid',
                '--source', '/no/source', '--output', str(output), '--kernel-directory', '/no/kernel',
                '--software', 'on', '--target-khz', '2394374'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            if platform.system() == 'Linux' and platform.machine() == 'x86_64':
                compiler = shutil.which('cc')
                self.assertIsNotNone(compiler)
                subprocess.run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                                str(root / 'probe-tsc-frequency.c'), '-o', str(root / 'probe')], check=True)
                result = subprocess.run([str(root / 'probe'), 'kernel-must-not-match', 'target', 'software', '2394374'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
