"""重放实际写入者与宿主缺页记录，保留边界、身份和计时失败。"""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence'
spec = importlib.util.spec_from_file_location('irq', HERE / 'check-guest-irq.py')
irq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(irq)
faults = irq.guest.load('check-timekeeper-faults')
rewrite_trace = irq.guest.load('test_guest_timers').rewrite_trace


class TimekeeperWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((EVIDENCE / 'ssi-timekeeper-writer-20261108.json').read_text())
        cls.runs = {run['label']: run for run in cls.evidence['runs']}
        cls.control = cls.runs['control-d']
        cls.files = irq.guest.read_archive(EVIDENCE / cls.control['archive']['file'])
        cls.log = cls.control['files']['clock']
        cls.writer = cls.control['analysis']['writers']['longest'][0]

    def reject(self, change, pattern):
        files = deepcopy(self.files)
        change(files)
        with self.assertRaisesRegex(ValueError, pattern):
            irq.inspect(files, self.log)

    def change_row(self, files, index, change):
        rewrite_trace(files, lambda lines: [change(line) if at == index else line for at, line in enumerate(lines)])

    def change_hits(self, files, name, delta):
        files['profile-after'] = re.sub(r'(^\s*' + name + r'\s+)(\d+)',
                                        lambda match: match[1] + str(int(match[2]) + delta),
                                        files['profile-after'], flags=re.M)

    def test_complete_archives_replay_and_keep_the_application_gate(self):
        for label, run in self.runs.items():
            with self.subTest(label=label):
                archive = EVIDENCE / run['archive']['file']
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), run['archive']['sha256'])
                self.assertEqual(archive.stat().st_size, run['archive']['bytes'])
                result = irq.inspect(irq.guest.read_archive(archive), run['files']['clock'])
                self.assertEqual(result, run['analysis'])
                self.assertEqual(len(result['timer_analysis']['timers']), 24)
                self.assertEqual(result['timer_analysis']['timer_gate_ns'], 250_000_000)
                self.assertFalse(result['full_ssi_accepted'])
                self.assertFalse(result['stall_cause_established'])
        for label in ('pair-b', 'pair-c', 'pair-d'):
            self.assertFalse(self.runs[label]['analysis']['timer_analysis']['timer_gate_passed'])
        self.assertTrue(self.runs['pair-a']['analysis']['timer_analysis']['timer_gate_passed'])

    def test_long_writer_has_one_odd_sequence_and_two_distinct_stages(self):
        result = self.runs['pair-d']['analysis']
        writer = result['writers']['longest'][0]
        self.assertEqual(writer['duration_ns'], 952_614_000)
        self.assertEqual(writer['update_ns'], 264_033_000)
        self.assertEqual(writer['publish_ns'], 688_581_000)
        self.assertEqual(irq.sequence_value(writer['start'], 'seq'), 47019)
        self.assertEqual(irq.sequence_value(writer['end'], 'seq'), 47020)
        overlaps = [row for row in result['writers']['reader_overlap'] if writer in row['writers']]
        self.assertTrue(overlaps)
        for overlap in result['writers']['reader_overlap']:
            for write in overlap['writers']:
                self.assertLess(write['start']['ns'], overlap['reader']['end']['ns'])
                self.assertLess(overlap['reader']['start']['ns'], write['end']['ns'])

    def test_exact_addresses_offsets_and_unfiltered_probes_are_required(self):
        for symbol in ('ffffffff81212a30 t timekeeping_advance', 'ffffffff8401b4c0 b tk_core'):
            self.reject(lambda files: files.update(kallsyms=files['kallsyms'].replace(symbol, '')), '地址')
        self.reject(lambda files: files.update(probes=files['probes'].replace('timekeeping_advance+739', 'timekeeping_advance+740')), '定义')
        self.reject(lambda files: files.update({'filter-tk_write_end': 'seq == 2'}), '隐藏')
        self.reject(lambda files: self.change_row(files, self.writer['start']['index'],
                    lambda line: line.replace('+0x2e3/', '+0x2e4/')), '地址')

    def test_all_writer_hits_must_match_and_misses_are_rejected(self):
        for name in irq.WRITER_STAGES:
            self.reject(lambda files: self.change_hits(files, name, 1), '命中与事件')
        self.reject(lambda files: files.update({'profile-after': re.sub(
            r'(^\s*tk_write_begin\s+\d+\s+)0', r'\g<1>1', files['profile-after'], flags=re.M)}), '漏采')

    def test_missing_middle_or_entry_is_not_repaired_by_counts(self):
        for stage, name, error in [('update_done', 'tk_update_done', '更新阶段缺失'),
                                    ('start', 'tk_write_begin', '内部返回|缺少起点'),
                                    ('end', 'tk_write_end', '未完成')]:
            def change(files):
                index = self.writer[stage]['index']
                rewrite_trace(files, lambda lines: [line for at, line in enumerate(lines) if at != index])
                self.change_hits(files, name, -1)
            self.reject(change, error)

    def test_wrong_writer_thread_or_sequence_is_rejected(self):
        for stage in ('start', 'update_done', 'end'):
            self.reject(lambda files: self.change_row(files, self.writer[stage]['index'],
                        lambda line: re.sub(r'seq=\d+', 'seq=2', line)), '奇数到下一偶数')
        self.reject(lambda files: self.change_row(files, self.writer['update_done']['index'],
                    lambda line: re.sub(r'-(\d+)(\s+\[)', r'-9999\2', line)), '身份')
        self.reject(lambda files: self.change_row(files, self.writer['end']['index'],
                    lambda line: re.sub(r'-(\d+)(\s+\[)', r'-9999\2', line)), '线程')

    def test_sequence_wrap_is_valid_but_out_of_range_is_not(self):
        files = deepcopy(self.files)
        for stage, value in [('start', 2 ** 32 - 1), ('update_done', 2 ** 32 - 1), ('end', 0)]:
            self.change_row(files, self.writer[stage]['index'], lambda line: re.sub(r'seq=\d+', f'seq={value}', line))
        irq.inspect(files, self.log)
        self.reject(lambda files: self.change_row(files, self.writer['start']['index'],
                    lambda line: re.sub(r'seq=\d+', f'seq={2 ** 32}', line)), 'u32')

    def test_complete_calls_crossing_markers_are_not_measured(self):
        rows, marks = irq.guest.parse(self.files, irq.capture_events(self.files))
        marks = deepcopy(marks)
        marks[0]['index'] = self.writer['start']['index'] + 1
        marks[0]['ns'] = self.writer['start']['ns']
        result = irq.inspect_writers(rows, marks, [])
        self.assertNotIn(self.writer, result['longest'])
        self.assertLess(result['distribution']['count'], self.control['analysis']['writers']['distribution']['count'])

    def test_duplicate_update_or_overlapping_writers_are_rejected(self):
        rows, marks = irq.guest.parse(self.files, irq.capture_events(self.files))
        middle = self.writer['update_done']
        rows.insert(middle['index'], deepcopy(middle))
        with self.assertRaisesRegex(ValueError, '更新阶段缺失或重复'):
            irq.inspect_writers(rows, marks, [])
        # 第二个写入者有合法序列但跨 CPU 嵌入首个临界区，必须拒绝。
        rows = []
        order = [(0, 'start'), (0, 'update_done'), (1, 'start'), (0, 'end'), (1, 'update_done'), (1, 'end')]
        for index, (cpu, stage) in enumerate(order, 1):
            rows.append({**deepcopy(self.writer[stage]), 'cpu': cpu, 'index': index, 'ns': index * 1000})
        with self.assertRaisesRegex(ValueError, '临界区重叠'):
            irq.inspect_writers(rows, [{'index': 0}, {'index': 7}], [])

    def test_current_collector_is_the_source_used_for_both_public_runs(self):
        source = self.evidence['collector_sources']['public']
        raw = (HERE / 'trace-guest-timers.sh').read_bytes()
        self.assertEqual(raw.decode(), source['source'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), source['sha256'])
        for label in ('control-d', 'pair-d'):
            self.assertEqual(self.runs[label]['collector_version'], 'public')
        subprocess.run(['sh', '-n', str(HERE / 'trace-guest-timers.sh')], check=True)

    def test_all_workspaces_closed_and_stock_boot_was_restored(self):
        stress = irq.guest.load('check-stress')
        close = irq.guest.load('check-qemu-close')
        for run in self.runs.values():
            result = run['result']
            for phase in ('identity', 'clock-upload', 'guest-trace-start', 'clock', 'guest-trace-stop', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(result['phases'][phase]['exit'], 0)
            self.assertFalse(any(result.get(key) for key in ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')))
            self.assertEqual(result['qemu_ssh_exits'], [0, 0] if result['mode'] == 'pair' else [0])
            self.assertTrue(result['sftp_matches'])
            self.assertEqual(run['firewall']['before'], run['firewall']['after'])
            stress.validate(run['files']['stress'])
            self.assertIn('reboot: Power down', run['serial_log'])
            if result['mode'] == 'pair':
                self.assertIn('workqueue:', run['serial_log'])
                generation = close.inspect_barrier(run['qemu_stderr'], 'QUIESCE')
                close.inspect_barrier(run['qemu_stderr'], 'DRAIN')
                for log in run['qemu_stderr']:
                    self.assertIn(f'SSI_KERNEL_CLOSE_RESULT generation={generation} ret=0', log)
                    self.assertIn('SSI_DEVICE_CLOSE_COMPLETE', log)
            for hashes in run['hashes']:
                for key in ('host_kernel_sha256', 'qemu_sha256', 'guest_kernel_sha256', 'guest_initramfs_sha256'):
                    self.assertIn(self.evidence[key], hashes)
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)
        for node in self.evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            for key in ('identity_matches', 'old_boot_files_unchanged', 'grub_config_unchanged', 'firewall_matches_original', 'stock_grub_default', 'pf29_grub_entry_removed'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])
        self.assertFalse(self.evidence['runtime_fix_proven'])
        self.assertFalse(self.evidence['full_ssi_accepted'])

    def test_cli_still_fails_after_printing_valid_slow_capture(self):
        run = self.runs['pair-d']
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'clock.log'
            log.write_text(run['files']['clock'])
            result = subprocess.run([sys.executable, str(HERE / 'check-guest-irq.py'),
                                     str(EVIDENCE / run['archive']['file']), str(log)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout), run['analysis'])


class TimekeeperFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((EVIDENCE / 'ssi-timekeeper-writer-20261108.json').read_text())
        cls.capture = cls.evidence['host_fault_capture']
        cls.data = json.loads(gzip.decompress((EVIDENCE / cls.capture['nodes'][0]['archive']['file']).read_bytes()))

    def reject(self, change, pattern):
        data = deepcopy(self.data)
        change(data)
        with self.assertRaisesRegex(ValueError, pattern):
            faults.inspect(data)

    def test_full_host_fault_archives_replay(self):
        self.assertTrue(self.capture['full_replay_in_ci'])
        self.assertEqual(self.capture['coverage'], 'all_six_clock_trials')
        for node in self.capture['nodes']:
            archive = (EVIDENCE / node['archive']['file']).read_bytes()
            self.assertEqual(hashlib.sha256(archive).hexdigest(), node['archive']['sha256'])
            raw = gzip.decompress(archive)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), node['uncompressed_sha256'])
            self.assertEqual(len(raw), node['uncompressed_bytes'])
            result = faults.inspect(json.loads(raw))
            self.assertEqual(result, node['analysis'])
            self.assertFalse(result['single_invocation_proven'])
            self.assertFalse(result['cross_clock_alignment_established'])
            self.assertFalse(result['stall_cause_established'])
        limited = self.evidence['limited_host_capture']
        self.assertEqual(limited['coverage'], 'first_clock_trial_only')
        self.assertFalse(limited['full_replay_in_ci'])
        self.assertFalse(limited['later_trials_have_host_trace'])

    def test_copy_instruction_has_repeated_faults_not_a_measured_service_time(self):
        group = next(group for group in self.capture['nodes'][0]['analysis']['longest_sequences']
                     if group['first']['rip'] == 0xffffffff81212d35)
        self.assertEqual(group['count'], 41)
        self.assertEqual(group['span_ns'], 313_402_000)
        self.assertEqual(group['first']['address'], 0x401b4c8)
        self.assertEqual(group['span_ns'], group['last']['ns'] - group['first']['ns'])

    def test_other_faults_interrupt_a_sequence_but_other_vcpus_do_not(self):
        common = {'pid': 1, 'vcpu': 0, 'rip': 10, 'address': 20, 'error_code': 30}
        events = [{**common, 'ns': 1}, {**common, 'pid': 2, 'vcpu': 1, 'ns': 2},
                  {**common, 'ns': 3}, {**common, 'address': 99, 'ns': 4}, {**common, 'ns': 5}]
        groups = faults.consecutive_faults(events)
        self.assertEqual(len(groups), 1)
        self.assertEqual((groups[0]['count'], groups[0]['span_ns']), (2, 2))
        for key in ('rip', 'error_code'):
            changed = [{**common, 'ns': 1}, {**common, key: 99, 'ns': 2}, {**common, 'ns': 3}]
            self.assertEqual(faults.consecutive_faults(changed), [])

    def test_missing_counts_loss_and_clock_mismatch_are_rejected(self):
        self.reject(lambda data: data['trace_stats'].pop('cpu1'), 'CPU')
        self.reject(lambda data: data['trace_stats'].update(cpu0=data['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1')), '丢失')
        self.reject(lambda data: data['trace_stats'].update(cpu0=re.sub(r'entries: \d+', 'entries: 0', data['trace_stats']['cpu0'])), '逐 CPU')
        self.reject(lambda data: data.update(trace_clock='[local] global'), '全局')
        self.reject(lambda data: data.update(trace_cleanup_complete=False), '清理')
        self.reject(lambda data: data.update(kernel='another-kernel'), '固定实验')

    def test_unknown_event_bad_field_and_wrong_vcpu_are_rejected(self):
        self.reject(lambda data: data.update(trace=data['trace'].replace('kvm_page_fault:', 'other_event:', 1)), '未声明')
        self.reject(lambda data: data.update(trace=data['trace'].replace('error_code ', 'missing_code ', 1)), '字段')
        self.reject(lambda data: data.update(trace=re.sub(r'vcpu \d+ rip', 'vcpu 99 rip', data['trace'], count=1)), 'vCPU')
        self.reject(lambda data: data.update(task_filter='common_pid == 1'), '过滤器')

    def test_reused_pid_is_rejected(self):
        pid = next(iter(self.data['tasks_before']))
        def change(data):
            stat = data['tasks_after'][pid]['stat']
            prefix, fields = stat.rsplit(')', 1)
            fields = fields.split()
            fields[19] = str(int(fields[19]) + 1)
            data['tasks_after'][pid]['stat'] = prefix + ') ' + ' '.join(fields)
        self.reject(change, 'PID 被复用')


if __name__ == '__main__':
    unittest.main()
