"""重放真实 QEMU/KVM 证据，拒绝假成功、错误引用、漏采和缺失失败日志。"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

root = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('check-qemu-map')


class QemuMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((root / 'docs/evidence/ssi-qemu-map-failure-20261106.json').read_text())
        cls.records = {r['run']['mode']: r for r in cls.evidence['probes']
                       if r['run']['variant'] == 'candidate-probe' and r['run']['node'] == 0}

    def reject(self, mode, mutate):
        row = deepcopy(self.records[mode])
        mutate(row)
        with self.assertRaises(ValueError):
            checker.inspect(row)

    def change_event(self, row, phase, **values):
        node = row['run']['node']
        lines = row['qemu_stderr'][node].splitlines()
        for index, line in enumerate(lines):
            if not line.startswith('SSI_MAP '):
                continue
            event = json.loads(line.removeprefix('SSI_MAP '))
            if event['phase'] == phase:
                event.update(values)
                lines[index] = 'SSI_MAP ' + json.dumps(event)
        row['qemu_stderr'][node] = '\n'.join(lines) + '\n'

    def test_complete_native_matrix(self):
        expected = {('baseline-fixed', n, m) for n in (0, 1) for m in (1, 3)}
        expected |= {('candidate-probe', n, m) for n in (0, 1) for m in range(5)}
        actual = {(r['run']['variant'], r['run']['node'], r['run']['mode']) for r in self.evidence['probes']}
        self.assertEqual(actual, expected)
        self.assertEqual(len(self.evidence['probes']), len(expected))
        for row in self.evidence['probes']:
            self.assertEqual(checker.inspect(row), row['analysis'])
            self.assertFalse(row['analysis']['whole_vm_shutdown_verified'])

    def test_runtime_source_and_capture_provenance(self):
        for path, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        for source in self.evidence['capture_sources']:
            self.assertEqual(hashlib.sha256(source['text'].encode()).hexdigest(), source['sha256'])
        captures = {r['sha256'] for r in self.evidence['capture_sources']}
        for row in self.evidence['probes']:
            self.assertEqual(row['run']['qemu_sha256'], self.evidence['builds'][row['run']['variant']]['sha256'])
            self.assertIn(row['run']['probe_hashes']['probe-qemu-map.py'], captures)
            self.assertEqual(row['run']['probe_hashes']['trace-teardown.py'], self.evidence['trace_helper_sha256'])
        for log in self.evidence['build_logs'].values():
            self.assertNotRegex(log, r'warning:|error:')
        self.assertTrue(all(self.evidence['patch_replay'].values()))
        normal = self.evidence['builds']['candidate']['sources']
        diagnostic = self.evidence['builds']['candidate-probe']['sources']
        self.assertEqual(normal['system/physmem.c'], diagnostic['system/physmem.c'])
        for path in ('monitor/hmp-cmds.c', 'include/monitor/hmp.h', 'hmp-commands.hx'):
            self.assertEqual(normal[path], self.evidence['original_source_sha256'][path])
            self.assertNotEqual(normal[path], diagnostic[path])

    def test_rejected_attempts_and_build_warning_remain_visible(self):
        self.assertEqual(len(self.evidence['rejected_probes']), 3)
        for row in self.evidence['rejected_probes']:
            with self.assertRaises(ValueError):
                checker.inspect(row)
            self.assertTrue(row['reason'])
        warning = self.evidence['rejected_builds']['baseline-warning']
        self.assertIn('warning:', warning['log'])
        self.assertNotIn(warning['build']['sha256'], {r['run']['qemu_sha256'] for r in self.evidence['probes']})

    def test_failure_cannot_return_success_or_leave_process_alive(self):
        self.reject(1, lambda r: r['run']['qemu_ssh_exits'].__setitem__(0, 0))
        self.reject(1, lambda r: r['run']['qemu_ssh_exits'].__setitem__(1, -9))
        self.reject(1, lambda r: r['run']['qemu_ssh_exits'].__setitem__(1, 124))
        self.reject(3, lambda r: r['record'].update(qemu_remaining=True))
        self.reject(2, lambda r: self.change_event(r, 'exit', returned=True))
        self.reject(4, lambda r: r['record'].update(command_return={}))

    def test_ref_leak_or_overrelease_is_rejected(self):
        for mode in range(5):
            for value in (0, 999):
                self.reject(mode, lambda r: self.change_event(r, 'exit', owner_after=value))
        self.reject(0, lambda r: self.change_event(r, 'unmap_return', owner_after=999))

    def test_real_native_failures_cannot_be_forged_as_success(self):
        for mode, error in ((1, -108), (2, -108), (3, -22), (4, -22)):
            self.reject(mode, lambda r: r['record'].update(trace=r['record']['trace'].replace(f'code={error}', 'code=0')))
        self.reject(0, lambda r: r['record'].update(trace=r['record']['trace'].replace('qm_return:', 'unknown:', 1)))

    def test_pin_arguments_and_address_are_checked(self):
        for mode in (1, 2, 3, 4):
            self.reject(mode, lambda r: r['record'].update(trace=r['record']['trace'].replace('ioctl=0x4018aef2 write=', 'ioctl=0x4018aef2 write=9')))
        self.reject(2, lambda r: r['record'].update(trace=r['record']['trace'].replace('length=8192', 'length=4096')))
        self.reject(3, lambda r: r['record'].update(trace=r['record']['trace'].replace('unpin=1', 'unpin=0', 1)))
        self.reject(0, lambda r: r['record'].update(trace=re.sub(r'(hva=0x)[0-9a-f]+( length=4096)', r'\g<1>1\2', r['record']['trace'], count=1)))

    def test_only_main_process_native_events_are_accepted(self):
        self.reject(1, lambda r: r['record'].update(trace=r['record']['trace'].replace('qemu-system-x86-' + str(r['record']['pid']), 'qemu-system-x86-1', 1)))
        self.reject(3, lambda r: r['run'].update(pid=1))
        self.reject(1, lambda r: r['record'].update(qemu_sha256='0' * 64))
        self.reject(0, lambda r: r['record'].update(kernel='stock'))

    def test_phase_order_and_stopped_state_are_checked(self):
        self.reject(1, lambda r: r['record'].update(trace=r['record']['trace'].replace('case_begin', 'process_ended', 1)))
        self.reject(2, lambda r: r['record']['events'][1].update(time_ns=0))
        self.reject(0, lambda r: r['record']['status'].update(running=True))
        self.reject(4, lambda r: r['record'].update(trace_cleanup_complete=False))

    def test_trace_loss_and_kprobe_misses_are_rejected(self):
        self.reject(1, lambda r: r['record']['trace_stats'].__setitem__('cpu0', r['record']['trace_stats']['cpu0'].replace('overrun: 0', 'overrun: 1', 1)))
        self.reject(2, lambda r: r['record'].update(kprobe_profile=re.sub(r'0\s*$', '1', r['record']['kprobe_profile'])))
        self.reject(3, lambda r: r['record'].update(trace=r['record']['trace'].replace('entries-written:', 'missing:')))
        self.reject(4, lambda r: r['record']['trace_stats'].clear())

    def test_success_requires_real_mapping_and_released_kernel_refs(self):
        self.reject(0, lambda r: self.change_event(r, 'map_return', pointer=False))
        self.reject(0, lambda r: self.change_event(r, 'map_return', dsm=False))
        self.reject(0, lambda r: self.change_event(r, 'mapped_status', read_refs=0))
        self.reject(0, lambda r: self.change_event(r, 'final_status', read_refs=1))
        self.reject(4, lambda r: self.change_event(r, 'mapped_status', write_refs=1))

    def test_failure_preparation_and_stderr_cannot_be_omitted(self):
        self.reject(1, lambda r: self.change_event(r, 'seal', ret=-16))
        self.reject(3, lambda r: self.change_event(r, 'consume_pin', ret=-22))
        self.reject(1, lambda r: r['qemu_stderr'].__setitem__(0, r['qemu_stderr'][0].replace('Distributed DSM map pin failed', 'lost message')))
        self.reject(4, lambda r: r['qemu_stderr'].__setitem__(0, r['qemu_stderr'][0] + '\nsegmentation fault\n'))

    def test_full_guest_runs_use_normal_binary_and_keep_shutdown_errors(self):
        boot, clock, stress = [load(n) for n in ('check-ssh-boot', 'check-clock', 'check-stress')]
        for row in self.evidence['workspace_runs']:
            self.assertFalse(row['full_ssi_accepted'])
            for hashes in row['runtime_hashes']:
                self.assertEqual(hashes['qemu'], self.evidence['builds']['candidate']['sha256'])
                self.assertEqual(hashes['kernel'], self.evidence['kernel_sha256'])
            trials = ['CLOCK_START' + s for s in row['clock_log'].split('CLOCK_START')[1:]]
            actual = []
            for trial in trials:
                try:
                    clock.validate(trial, 250000000)
                    actual.append(None)
                except ValueError as error:
                    actual.append(str(error))
            self.assertEqual(actual, row['validation']['clock'])
            for text, error in zip(row['host_logs'], row['validation']['hosts']):
                if error:
                    with self.assertRaises(ValueError):
                        boot.check_errors(text)
                else:
                    boot.check_errors(text)
            if row['operations_passed']:
                boot.validate(row['serial_log'])
                stress.validate(row['stress_log'])
                self.assertTrue(row['result']['sftp_matches'])
                self.assertEqual(len(trials), 3)
                self.assertNotRegex('\n'.join(row['qemu_stderr']), r'Distributed DSM .* failed')

    def test_final_restoration_preserves_existing_system(self):
        self.assertEqual(len(self.evidence['restoration']['nodes']), 2)
        for row in self.evidence['restoration']['nodes']:
            self.assertEqual(row['kernel'], '6.8.0-147-generic')
            for name in ('identity_matches', 'old_boot_files_unchanged', 'firewall_matches_original'):
                self.assertTrue(row[name])
            for name in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(row[name])


if __name__ == '__main__':
    unittest.main()
