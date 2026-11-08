"""重放完整单指令与客体实验，并主动破坏边界、结果、身份和清理记录。"""
from copy import deepcopy
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
spec = importlib.util.spec_from_file_location('grant', HERE / 'check-write-grant.py')
grant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grant)
irq = grant.guest.load('check-guest-irq')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class WriteGrantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((EVIDENCE / 'ssi-write-grant-20261108.json').read_text())
        cls.runs = {row['label']: row for row in cls.evidence['minimal_runs']}
        cls.data = json.loads(gzip.decompress((EVIDENCE / cls.runs['pf30-grant-pair-1000-a']['archive']['file']).read_bytes()))

    def reject(self, change, pattern):
        data = deepcopy(self.data)
        change(data)
        with self.assertRaisesRegex(ValueError, pattern):
            grant.inspect(data)

    def test_complete_minimal_archives_replay(self):
        for run in self.runs.values():
            with self.subTest(run=run['label']):
                raw = (EVIDENCE / run['archive']['file']).read_bytes()
                self.assertEqual(digest(raw), run['archive']['sha256'])
                self.assertEqual(len(raw), run['archive']['bytes'])
                decoded = gzip.decompress(raw)
                self.assertEqual(digest(decoded), run['raw_sha256'])
                self.assertEqual(grant.inspect(json.loads(decoded)), run['analysis'])
        self.assertEqual(self.runs['pf29-grant-pair-b']['analysis']['1']['max_faults_per_store'], 306)
        self.assertEqual(self.runs['pf30-grant-pair-off-a']['analysis']['1']['max_faults_per_store'], 482)
        for row in self.runs['pf30-grant-pair-1000-a']['analysis'].values():
            self.assertEqual(row['writes'], 320)
            self.assertEqual(row['repeated_stores'], 0)
            self.assertEqual(row['max_faults_per_store'], 1)

    def test_missing_end_wrong_value_and_overlapping_calls_are_rejected(self):
        def change(data, old, new):
            capture = data['traces']['0']['after']
            capture['trace'] = capture['trace'].replace(old, new, 1)
        self.reject(lambda d: change(d, 'grant_end value=1', 'grant_begin value=1'), '重叠')
        self.reject(lambda d: change(d, 'grant_end value=1', 'grant_end value=999'), '结束不匹配')
        self.reject(lambda d: change(d, 'grant_begin value=1', 'grant_end value=1'), '结束不匹配')
        rows = grant.parse_trace(self.data['traces']['0'], self.data['traces']['0']['before']['pid'])
        with self.assertRaisesRegex(ValueError, '缺少结束'):
            grant.invocations(rows[:-1], 0)

    def test_another_instruction_or_node_cannot_be_counted_as_the_store(self):
        def change(data, old, new):
            trace = data['traces']['0']['after']
            trace['trace'] = trace['trace'].replace(old, new)
        self.reject(lambda d: change(d, 'vcpu 0 rip', 'vcpu 1 rip'), '固定客体')
        self.reject(lambda d: change(d, 'rip 0x1000 address 0x0000000000002000',
                                    'rip 0x1004 address 0x0000000000002000'), '唯一写指令')
        self.reject(lambda d: change(d, 'error_code 0x7ea', 'error_code 0x7e8'), '唯一写指令')
        self.reject(lambda d: change(d, 'kvm_page_fault:', 'unknown_event:'), '未声明')

    def test_counts_loss_filter_and_cleanup_cannot_be_ignored(self):
        self.reject(lambda d: d['traces']['0']['after']['stats'].pop('cpu1'), 'CPU')
        self.reject(lambda d: d['traces']['0']['after'].update(cleanup_complete=False), '清理')
        self.reject(lambda d: d['traces']['0']['before'].update(filter='common_pid == 1'), '过滤器')
        self.reject(lambda d: d['traces']['0']['before'].update(trace_clock='[local] global'), '全局')
        self.reject(lambda d: d['traces']['0']['after']['stats'].update(
            cpu0=d['traces']['0']['after']['stats']['cpu0'].replace('overrun: 0', 'overrun: 1')), '丢失')
        self.reject(lambda d: d['traces']['0']['after'].update(
            trace=re.sub(r'entries-in-buffer/entries-written: (\d+)/(\d+)',
                         lambda m: f'entries-in-buffer/entries-written: {int(m[1]) + 1}/{m[2]}',
                         d['traces']['0']['after']['trace'])), '计数')

    def test_pid_reuse_and_mixed_kernels_are_rejected(self):
        def reuse(data):
            after = data['traces']['0']['after']
            prefix, fields = after['stat'].rsplit(')', 1)
            fields = fields.split()
            fields[19] = str(int(fields[19]) + 1)
            after['stat'] = prefix + ') ' + ' '.join(fields)
        self.reject(reuse, '复用')
        self.reject(lambda d: d['traces']['0']['before'].update(kernel='7.1.0-rc3-sshpool-gvm-pf29'), '内核')

    def test_hlt_rip_and_readback_must_all_match(self):
        for field, value in [('observed', 0), ('rip', 0x1000), ('exit_reason', 4), ('elapsed_ns', -1)]:
            def change(data):
                next(row['record'] for row in data['events'] if row['record']['op'] == 'write')[field] = value
            self.reject(change, '未完成')

    def test_reader_progress_peer_values_and_phase_order_are_required(self):
        for field, value in [('reads', 0), ('regressions', 1)]:
            def change(data):
                next(row['record'] for row in data['events'] if row['record']['op'] == 'reader_stopped')[field] = value
            self.reject(change, '读者')
        def wrong_peer(data):
            next(row['record'] for row in data['events'] if row['record']['op'] == 'read')['value'] = 0
        self.reject(wrong_peer, '最终数据')
        def wrong_order(data):
            index = next(i for i, row in enumerate(data['events']) if row['record']['op'] == 'reader_started')
            data['events'][index], data['events'][index + 1] = data['events'][index + 1], data['events'][index]
        self.reject(wrong_order, '次序')

    def test_close_generation_and_parameter_restoration_are_required(self):
        def wrong_generation(data):
            next(row['record'] for row in data['events'] if row['record']['op'] == 'sealed')['generation'] += 1
        self.reject(wrong_generation, '代际')
        self.reject(lambda d: d.update(grace_after=[1000, 0]), '恢复')
        self.reject(lambda d: d.update(grace_active=[1000, 0]), '不一致')
        self.reject(lambda d: d.update(firewall_after=[]), '防火墙')
        self.reject(lambda d: d.update(errors=['close failed']), '采集失败')

    def test_compiled_sources_replay_with_zero_fuzz(self):
        source = self.evidence['sources']
        raw = (EVIDENCE / source['archive']['file']).read_bytes()
        self.assertEqual(digest(raw), source['archive']['sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
        self.assertEqual({name: digest(data) for name, data in files.items()}, source['sha256'])
        for original, public in [('kernel-write-grace-candidate.patch', 'experiments/kernel-dsm-write-grace.patch'),
                                 ('qemu-pf30-profile.patch', 'experiments/qemu-pf30-lab-profile.patch')]:
            self.assertEqual(files[original], (HERE / public).read_bytes())
        # 历史二进制继续对应归档源码，新增原子模式由独立运行记录核对。
        self.assertEqual(digest(files['probe-grant.c']), self.evidence['probe_build']['source_sha256'])
        paths = ['arch/x86/include/asm/kvm_host.h', 'arch/x86/kvm/ivy.c']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in paths:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(files['pf29-source/' + name])
            subprocess.run(['patch', '-p1', '--fuzz=0'], input=files['kernel-write-grace-candidate.patch'],
                           cwd=root, check=True, capture_output=True)
            for name in paths:
                self.assertEqual((root / name).read_bytes(), files['pf30-source/' + name])
                self.assertEqual(digest((root / name).read_bytes()), self.evidence['kernel_build']['compiled_sources'][name])
            (root / 'system').mkdir()
            (root / 'system/ssi-close.inc').write_bytes(files['qemu-close-pf29.inc'])
            subprocess.run(['patch', '-p1', '--fuzz=0'], input=files['qemu-pf30-profile.patch'],
                           cwd=root, check=True, capture_output=True)
            self.assertEqual((root / 'system/ssi-close.inc').read_bytes(), files['qemu-close-pf30.inc'])
        self.assertEqual(files['config-pf29'].replace(b'-sshpool-gvm-pf29', b'-sshpool-gvm-pf30'), files['config-pf30'])
        for node in self.evidence['parameter_guards']:
            self.assertEqual([row['input'] for row in node['records']], ['1001', '-1', 'invalid'])
            self.assertTrue(all(row['errno'] == 22 and row['after'] == '0' for row in node['records']))
        failed = json.loads(files['pf29-grant-control-a.json'])
        with self.assertRaises(ValueError):
            grant.inspect(failed)

    def test_complete_guest_regressions_and_original_timer_gate(self):
        close = grant.guest.load('check-qemu-close')
        stress = grant.guest.load('check-stress')
        self.assertEqual({run['label'] for run in self.evidence['runs']},
                         {'control-off-b', 'pair-off-a', 'pair-1000-a', 'pair-1000-b'})
        for run in self.evidence['runs']:
            path = EVIDENCE / run['archive']['file']
            self.assertEqual(digest(path.read_bytes()), run['archive']['sha256'])
            files = irq.guest.read_archive(path)
            if run['label'] == 'pair-1000-a':
                self.assertEqual(run['attribution_error'], '缺少唯一睡眠切换')
                self.assertIsNone(run['analysis'])
                with self.assertRaisesRegex(ValueError, '缺少唯一睡眠切换'):
                    irq.inspect(files, run['files']['clock'])
            else:
                self.assertIsNone(run['attribution_error'])
                analysis = irq.inspect(files, run['files']['clock'])
                self.assertEqual(analysis, run['analysis'])
                self.assertEqual(analysis['timer_analysis']['timer_gate_ns'], 250_000_000)
                self.assertEqual(len(analysis['timer_analysis']['timers']), 24)
                if run['label'] == 'pair-1000-b':
                    self.assertTrue(analysis['timer_analysis']['timer_gate_passed'])
            self.assertEqual(grant.guest.application_intervals(run['files']['clock']), run['application_intervals'])
            result = run['result']
            for phase in ('identity', 'clock-upload', 'guest-trace-start', 'clock', 'guest-trace-stop', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(result['phases'][phase]['exit'], 0)
            self.assertFalse(any(result.get(key) for key in ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')))
            self.assertTrue(result['sftp_matches'])
            self.assertEqual(result['qemu_ssh_exits'], [0, 0] if result['mode'] == 'pair' else [0])
            self.assertEqual(run['firewall']['before'], run['firewall']['after'])
            self.assertTrue(run['firewall']['write_grace_restored'])
            stress.validate(run['files']['stress'])
            self.assertIn('reboot: Power down', run['serial_log'])
            if result['mode'] == 'pair':
                generation = close.inspect_barrier(run['qemu_stderr'], 'QUIESCE')
                close.inspect_barrier(run['qemu_stderr'], 'DRAIN')
                for log in run['qemu_stderr']:
                    self.assertIn(f'SSI_KERNEL_CLOSE_RESULT generation={generation} ret=0', log)
                    self.assertIn('SSI_DEVICE_CLOSE_COMPLETE', log)
            for hashes in run['hashes']:
                for key in ('host_kernel_sha256', 'qemu_sha256', 'guest_kernel_sha256', 'guest_initramfs_sha256'):
                    self.assertIn(self.evidence[key], hashes)

    def test_callback_without_actual_sleep_remains_rejected_for_attribution(self):
        run = next(row for row in self.evidence['runs'] if row['label'] == 'pair-1000-a')
        diagnostic = run['attribution_diagnostic']
        self.assertFalse(diagnostic['full_attribution_accepted'])
        self.assertEqual(diagnostic['max_application_ns'], 169_358_816)
        self.assertEqual(diagnostic['application_intervals'], run['application_intervals'])
        failures = diagnostic['failed_sleep_associations']
        self.assertEqual(len(failures), 1)
        failure = failures[0]
        self.assertEqual(failure['sleep_switches'], [])
        self.assertEqual(failure['generation']['expire']['comm'], 'ssi-clock')
        self.assertEqual([row['name'] for row in failure['nearby']], ['sched_waking', 'sched_wakeup'])

    def test_stock_restore_does_not_imply_full_ssi_acceptance(self):
        self.assertFalse(self.evidence['runtime_fix_proven'])
        self.assertFalse(self.evidence['full_ssi_accepted'])
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged',
                        'firewall_matches_original', 'stock_grub_default', 'pf29_grub_entry_removed',
                        'pf30_grub_entry_removed', 'write_grace_reset_before_reboot'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])

    def test_slow_baseline_cli_retains_original_failure(self):
        run = next(row for row in self.evidence['runs'] if row['label'] == 'pair-off-a')
        self.assertFalse(run['analysis']['timer_analysis']['timer_gate_passed'])
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'clock.log'
            log.write_text(run['files']['clock'])
            result = subprocess.run([sys.executable, str(HERE / 'check-guest-irq.py'),
                                     str(EVIDENCE / run['archive']['file']), str(log)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout), run['analysis'])


if __name__ == '__main__':
    unittest.main()
