"""重放三版真实矩阵；测量不确定不能冒充同步通过或确定超限。"""
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
EVIDENCE = HERE.parents[1] / 'docs/evidence/ssi-tsc-multivcpu-20261109.json'
spec = importlib.util.spec_from_file_location('multivcpu', HERE / 'check-tsc-multivcpu.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TscMultivcpuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(EVIDENCE.read_text())
        cls.previous = json.loads((EVIDENCE.parent / cls.manifest['baseline']['file']).read_text())
        cls.sources = json.loads(m.read_artifact(EVIDENCE.parent, cls.manifest['sources']))
        cls.data = {row['label']: json.loads(m.read_artifact(EVIDENCE.parent, row['capture']))
                    for row in cls.manifest['captures']}

    def inspect(self, change=None, label='handshake-b', index=0):
        run = copy.deepcopy(self.data[label]['runs'][index])
        if change:
            rows = [json.loads(line) for line in run['stdout'].splitlines()]
            change(rows)
            run['stdout'] = ''.join(json.dumps(row) + '\n' for row in rows)
        return m.inspect_run(run, self.manifest['builds'][label], self.previous['native_khz'],
                             self.previous['target_khz'])

    def reject(self, change, message):
        with self.assertRaisesRegex(ValueError, message):
            self.inspect(change)

    def test_all_matrices_and_failures_are_preserved(self):
        result = m.check(EVIDENCE)
        self.assertEqual(list(result), ['io-envelope-a', 'handshake-b', 'handshake-c'])
        self.assertTrue(all(not r['rate_passed'] for r in result['io-envelope-a']))
        self.assertEqual([r['accepted'] for r in result['handshake-b']], [True, False, True, False, False])
        self.assertTrue(all(r['rate_passed'] and not r['offset_passed'] for r in result['handshake-c']))
        for run in result['handshake-c'][:4]:
            statuses = {s for pair in run['cross'] for s in pair['status'].values()}
            self.assertEqual(statuses, {'within', 'inconclusive'})
        for label in result:
            self.assertTrue(result[label][-1]['injected_skew_detected'])

    def test_interval_bounds_are_inclusive_and_uncertainty_is_not_failure_proof(self):
        self.assertEqual(m.interval_status((-100000, 100000), -100000, 100000), 'within')
        self.assertEqual(m.interval_status((-150000, 50000), -100000, 100000), 'inconclusive')
        self.assertEqual(m.interval_status((100001, 150000), -100000, 100000), 'outside')
        self.assertEqual(m.interval_status((-150000, -100001), -100000, 100000), 'outside')

    def test_identity_order_aux_and_cpu_rotation(self):
        for change, error in [
            (lambda r: r[5].update(vcpu=1-r[5]['vcpu']), '身份'),
            (lambda r: r[5].update(host_cpu=1-r[5]['host_cpu']), '轮换'),
            (lambda r: r[5].update(index=0), '顺序'),
            (lambda r: r[5].update(tsc_aux=0), 'AUX'),
            (lambda r: r.pop(5), '缺失'),
            (lambda r: r[0].update(vms=2), '拓扑'),
        ]:
            with self.subTest(error=error):
                self.reject(change, error)

    def test_equal_rates_do_not_prove_equal_offsets(self):
        def change(rows):
            shift = rows[0]['requested_khz'] // 2
            for row in rows[3:27]:
                if row['vcpu'] == 1:
                    for key in m.scaling.CLOCKS:
                        row[key] += shift
        result = self.inspect(change)
        self.assertTrue(result['rate_passed'])
        self.assertFalse(result['accepted'])
        self.assertTrue(all(pair['status']['guest_tsc'] == 'outside' for pair in result['cross']))
        self.reject(lambda r: r[2].update(reported=r[2]['reported']+1), '读回')
        def wrong_offset(rows):
            rows[2]['written'] += 1
            rows[2]['reported'] += 1
            rows[28]['offset_after'] += 1
        self.reject(wrong_offset, '共同偏移')

    def test_middle_jump_cannot_hide_in_overall_average(self):
        def change(rows):
            for row in rows[13:15]:
                for key in m.scaling.CLOCKS:
                    row[key] += 10000000
        result = self.inspect(change)
        self.assertFalse(result['rate_passed'])
        overall = [r for r in result['rates'] if r['sample_pair'] == [1, 11]]
        self.assertTrue(all(s == 'within' for r in overall for s in r['status'].values()))

    def test_pvclock_and_three_paths_must_all_agree(self):
        self.reject(lambda r: r[5]['pvclock'].update(version=3), 'pvclock')
        self.reject(lambda r: r[5].update(guest_msr=r[5]['guest_tsc']-1), '顺序')
        def drift(rows):
            for i, row in enumerate(rows[3:27]):
                row['pvclock']['system_time'] += (i // 2) * 1000000
        result = self.inspect(drift)
        self.assertFalse(result['rate_passed'])
        self.assertTrue(any(row['status']['pvclock_ns'] != 'within' for row in result['rates']))

    def test_time_envelopes_and_sample_spacing(self):
        self.reject(lambda r: r[5].update(host_after_ns=r[5]['host_before_ns']-1), '包络')
        self.reject(lambda r: r[5].update(host_after_ns=r[5]['host_before_ns']+1000001), '包络')
        def gap(rows):
            width = rows[5]['host_after_ns'] - rows[5]['host_before_ns']
            rows[5]['host_before_ns'] = rows[4]['host_after_ns'] + 50000000
            rows[5]['host_after_ns'] = rows[5]['host_before_ns'] + width
        self.reject(gap, '间隔')

    def test_negative_control_requires_observed_signed_skew(self):
        def erase(rows):
            shift = rows[0]['requested_khz'] * 50
            for row in rows[3:27]:
                if row['vcpu'] == 1:
                    for key in m.scaling.CLOCKS:
                        row[key] -= shift
                    row['pvclock']['tsc'] -= shift
        with self.assertRaisesRegex(ValueError, '实测拒绝'):
            self.inspect(erase, index=4)

    def test_late_guard_halt_and_cleanup(self):
        self.reject(lambda r: r[27].update(late_result=0), '比例偏移')
        self.reject(lambda r: r[27].update(offset_after=0), '比例偏移')
        self.reject(lambda r: r[28].update(exit_reason=2), '停止')
        self.reject(lambda r: r[-1].update(fds_closed=3), '关闭')

    def test_host_identity_build_parameters_and_dirty_capture(self):
        changes = [
            (lambda d: d['after'].update(kvm_fds=[{}]), '采集后'),
            (lambda d: d.update(binary_sha256='0'*64), '构建身份'),
            (lambda d: [d[s]['identity_sha256'].update(machine='0'*64) for s in ('before', 'after')], '节点身份'),
            (lambda d: [d[s]['parameters'].update({'kvm_intel/parameters/lab_tsc_scaling': 'N'})
                        for s in ('before', 'after')], '实验开关'),
            (lambda d: d['runs'].pop(), '矩阵'),
        ]
        for change, error in changes:
            data = copy.deepcopy(self.data['handshake-c'])
            change(data)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                m.inspect_capture(data, self.manifest['builds']['handshake-c'], self.previous)

    def test_manifest_cannot_drop_failures_change_thresholds_or_claim_acceptance(self):
        changes = [
            (lambda d: d['captures'].pop(0), '历史失败'),
            (lambda d: d['builds']['handshake-c'].update(interval_ns=100000000), '间隔'),
            (lambda d: d['captures'][2]['analysis'][0].update(accepted=True), '重算'),
            (lambda d: d['cleanup']['snapshot'].update(kvm_fds=[{}]), '遗留'),
            (lambda d: d['cleanup']['configuration_checks']['apt.sha256'].update(after_sha256='0'*64), '缓存'),
            (lambda d: d.update(multivcpu_alignment_verified=True), '完整准入'),
            (lambda d: d['builds']['handshake-c'].update(guest_hex='f4'), '指令身份'),
        ]
        for change, error in changes:
            manifest = copy.deepcopy(self.manifest)
            change(manifest)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                m.check_manifest(manifest, EVIDENCE.parent)

    def test_archived_elf_is_bound_to_emitted_guest_code(self):
        for build in self.manifest['builds'].values():
            binary = m.read_artifact(EVIDENCE.parent, build['binary'])
            self.assertEqual(m.guest_code(binary), build['guest_hex'])
            with self.assertRaisesRegex(ValueError, 'ELF'):
                m.guest_code(b'bad!' + binary[4:])

    def test_collector_patch_reproduces_source_and_refuses_wrong_kernel(self):
        previous_sources = json.loads(m.read_artifact(EVIDENCE.parent, self.previous['sources']))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = root / 'capture-tsc-scaling.py'
            collector.write_text(previous_sources['capture-tsc-scaling.py'])
            subprocess.run(['patch', '--batch', '-p1', '-d', str(root)],
                           input=self.sources['capture-tsc-multivcpu.patch'], text=True, capture_output=True, check=True)
            self.assertEqual(collector.read_text(), self.sources['capture-tsc-multivcpu.py'])
            output = root / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(collector), '--require-kernel', 'kernel-must-not-match',
                '--binary', '/missing', '--binary-sha256', 'invalid', '--source', '/missing', '--output', str(output),
                '--kernel-directory', '/missing', '--target-khz', '2394374'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            if platform.system() == 'Linux' and platform.machine() == 'x86_64':
                compiler = shutil.which('cc')
                self.assertIsNotNone(compiler)
                subprocess.run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                                str(HERE / 'probe-tsc-multivcpu.c'), '-o', str(root / 'probe')], check=True)
                self.assertEqual(m.guest_code((root / 'probe').read_bytes()),
                                 self.manifest['builds']['handshake-c']['guest_hex'])
                result = subprocess.run([str(root / 'probe'), 'kernel-must-not-match', 'target', '2394374', 'aligned'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
