"""重算实机 RTC 证据，保留初步误判、关闭失败及有限实验边界。"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

root = Path(__file__).resolve().parents[2]
directory = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rtc, clock, boot, stress = [load(name) for name in ('check-rtc', 'check-clock', 'check-ssh-boot', 'check-stress')]


class RtcEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((root / 'docs/evidence/ssi-rtc-20261106.json').read_text())

    def test_compiled_sources_and_runtime_are_linked(self):
        data = self.data
        for path, expected in data['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        self.assertTrue(data['build']['patch_replay_matches_compiled_source'])
        self.assertEqual(data['build']['patch_sha256'],
                         data['source_sha256']['scripts/ssi-lab/experiments/qemu-dsm-pio-coalescing.patch'])
        self.assertEqual(data['probe_build']['source_sha256'], data['source_sha256']['scripts/ssi-lab/guest-rtc.c'])
        self.assertEqual(len(data['runtime_final_checks']), 2)
        for node in data['runtime_final_checks']:
            self.assertTrue(node['identity_matches'])
            self.assertEqual(node['kernel'], '7.1.0-rc3-sshpool-gvm-pf15')
            self.assertEqual(node['pause_exiting'], 'Y')
            self.assertEqual(node['qemu_sha256'], data['build']['binary'])
        for run in data['rtc_runs'] + data['workspace_runs']:
            expected = data['build']['binary'] if 'candidate' in run['label'] or 'workspace' in run['label'] else data['baseline_qemu_sha256']
            self.assertEqual(run['result']['qemu_sha256'], expected)
            for hashes in run['runtime_hashes']:
                self.assertEqual(hashes['qemu'], expected)
                self.assertEqual(hashes['kernel'], data['kernel_sha256'])
                self.assertEqual(hashes['guest'], '41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f')
                if run in data['rtc_runs']:
                    self.assertEqual(hashes['initramfs'], data['probe_build']['initramfs_sha256'])

    def test_independent_reference_recomputes_every_accepted_and_failed_read(self):
        expected_failures = {'rtc-reference-baseline-pair-1': 32, 'rtc-registration-baseline-pair-1': 16}
        self.assertEqual(len(self.data['rtc_runs']), 7)
        for run in self.data['rtc_runs']:
            self.assertTrue(run['reference_validated'])
            analysis = rtc.inspect(run['serial_log'], run['result'])
            self.assertEqual(analysis, run['analysis'])
            self.assertEqual(analysis['failures'], expected_failures.get(run['label'], 0))
            self.assertEqual(run['rtc_passed'], analysis['failures'] == 0)
            self.assertEqual(run['result']['qemu_ssh_exits'], [0] * len(run['runtime_hashes']))
            self.assertFalse(run['result']['sample_errors'])
        for run in self.data['preliminary_runs']:
            self.assertFalse(run['reference_validated'])
            self.assertFalse(run['rtc_passed'])
            self.assertNotIn('analysis', run)
        preliminary_pair = self.data['preliminary_runs'][1]
        self.assertIn('year=2004 month=4 day=4 hour=4 minute=4 second=4', preliminary_pair['serial_log'])
        self.assertIn('RTCPROBE_RESULT reads=32 failures=0', preliminary_pair['serial_log'])

    def test_registration_observations_preserve_single_node_and_pointer_limit(self):
        traces = []
        for run in self.data['rtc_runs']:
            for trace in run['registration_traces']:
                traces.append(trace)
                lines = trace['relevant_lines']
                self.assertTrue(any('KVM_CAP_COALESCED_PIO) = 1' in line for line in lines))
                for field, name in [('successful_registers', 'KVM_REGISTER_COALESCED_MMIO'),
                                    ('successful_unregisters', 'KVM_UNREGISTER_COALESCED_MMIO')]:
                    count = sum(name in line and line.endswith('= 0') for line in lines)
                    self.assertEqual(count, trace[field])
                disabled = run['result']['mode'] == 'pair' and 'candidate' in run['label']
                self.assertEqual((trace['successful_registers'], trace['successful_unregisters']),
                                 (0, 0) if disabled else (4, 1))
                self.assertFalse(trace['zone_arguments_decoded'])
                artifact = self.data['raw_artifacts'][f"{run['label']}-node{trace['node']}-ioctl.log"]
                self.assertEqual(artifact, {'sha256': trace['raw_sha256'], 'bytes': trace['raw_bytes']})
        self.assertEqual(len(traces), 5)

    def test_workspace_regression_passes_operations_but_retains_shutdown_failure(self):
        self.assertEqual(len(self.data['workspace_runs']), 2)
        for run in self.data['workspace_runs'][:1]:
            trials = ['CLOCK_START' + part for part in run['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, 250000000)
            self.assertEqual(run['max_timer_ns'], max(map(int, re.findall(r'elapsed_ns=(\d+)', run['clock_log']))))
            stress.validate(run['stress_log'])
            boot.validate(run['serial_log'])
            self.assertTrue(run['result']['sftp_matches'])
            for phase in ('identity', 'clock-upload', 'clock', 'stress', 'pause-user', 'sftp'):
                self.assertEqual(run['result']['phases'][phase]['exit'], 0)
            self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
            self.assertIn('Power down', run['serial_log'])
            self.assertFalse(run['full_workspace_passed'])
            for host_log in run['host_logs']:
                with self.assertRaisesRegex(ValueError, 'ktcp_receive'):
                    boot.check_errors(host_log)

    def test_second_boot_failure_is_not_overridden_by_the_first_pass(self):
        run = self.data['workspace_runs'][1]
        self.assertFalse(run['full_workspace_passed'])
        self.assertIsNone(run['clock_log'])
        self.assertIsNone(run['max_timer_ns'])
        self.assertFalse(run['result']['sftp_matches'])
        self.assertNotIn('clock', run['result']['phases'])
        for name in ('identity', 'clock-upload', 'stress', 'pause-user', 'sftp', 'poweroff'):
            self.assertNotEqual(run['result']['phases'][name]['exit'], 0)
        self.assertNotIn('Power down', run['serial_log'])
        self.assertIn('Lost 5 RTC interrupts', run['serial_log'])
        with self.assertRaisesRegex(ValueError, 'RTC interrupts'):
            boot.validate(run['serial_log'])
        failure = self.data['failed_workspace']
        self.assertIn('ivy.c:439', failure['snapshots'][0])
        self.assertIn('exited server loop, error -22', failure['snapshots'][0])
        with self.assertRaisesRegex(ValueError, 'WARNING'):
            boot.check_errors(run['host_logs'][0])
        for node in failure['termination']['nodes']:
            self.assertTrue(node['guard_passed'])
            self.assertEqual(node['signal'], 'SIGTERM')
        for node in failure['termination']['escalation']:
            initial = failure['termination']['nodes'][node['node']]
            self.assertTrue(node['guard_passed'])
            self.assertEqual(node['signal'], 'SIGKILL')
            self.assertGreater(node['sent_realtime_ns'] - initial['sent_realtime_ns'], 45_000_000_000)

    def test_restoration_does_not_imply_storage_or_business_acceptance(self):
        self.assertEqual(len(self.data['restoration']['nodes']), 2)
        for node in self.data['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            for key in ('remaining_processes', 'trace_events', 'trace_instances', 'grub_environment'):
                self.assertFalse(node[key])
        for node in self.data['lab_storage_check']['nodes']:
            self.assertFalse(node['ceph_installed'])
            self.assertFalse(node['ceph_units'])
            self.assertGreater(node['disk_free_bytes'], 1024 ** 3)
        self.assertEqual(self.data['lab_storage_check']['lima_status'], 'Stopped')
        for name in ('Ceph', 'Docker', 'PostgreSQL', 'Redis', 'sub2api', 'failover', 'normal DSM shutdown'):
            self.assertIn(name, self.data['not_accepted'])


if __name__ == '__main__':
    unittest.main()
