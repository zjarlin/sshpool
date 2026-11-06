"""重算真实双节点设备记录，保留失败与缺失证据，避免只相信 PASS 标记。"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest


directory = Path(__file__).resolve().parent
root = directory.parents[1]
spec = importlib.util.spec_from_file_location('check_io_order', directory / 'check-io-order.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
evidence = json.loads((root / 'docs/evidence/ssi-device-order-20261106.json').read_text())
runs = {run['label']: run for run in evidence['runs']}


class IoOrderTests(unittest.TestCase):
    def test_real_delay_exposes_stale_reads_and_completion_preserves_order(self):
        expected = {
            'io-order-baseline-control-1': 0,
            'io-order-baseline-pair-1': 0,
            'io-order-delayed-pair-2': 23,
            'io-order-completion-delayed-pair-2': 0,
            'io-order-completion-control-1': 0,
            'io-order-completion-pair-1': 0,
        }
        for label, failures in expected.items():
            with self.subTest(label=label):
                run = runs[label]
                self.assertEqual(checker.inspect(run['nodes'][0]['serial_log']),
                                 {'checks': 256, 'failures': failures})
                self.assertEqual(run['result']['qemu_ssh_exits'], [0] * len(run['nodes']))
                self.assertEqual(run['result']['sample_errors'], [])
                self.assertIn('Power down', run['nodes'][0]['serial_log'])
                hashes = [node['runtime_hashes'].splitlines() for node in run['nodes']]
                self.assertTrue(all(value == hashes[0] for value in hashes))
                self.assertEqual(hashes[0][1].split()[0], run['result']['qemu_sha256'])
        for label in ('io-order-delayed-pair-2', 'io-order-completion-delayed-pair-2'):
            run = runs[label]
            self.assertEqual(run['result']['delay_edu_us'], 50000)
            self.assertEqual(run['nodes'][0]['stderr_log'].count(
                'SSHPOOL_LAB_EDU_DELAY addr=0xfeb00004 us=50000'), 128)

    def test_interleaved_failed_attempt_is_not_complete_evidence(self):
        run = runs['io-order-delayed-pair-1']
        with self.assertRaises(ValueError):
            checker.inspect(run['nodes'][0]['serial_log'])
        self.assertIn('segfault', run['nodes'][0]['host_log'])
        self.assertNotEqual(run['result']['qemu_ssh_exits'][0], 0)

    def test_startup_failure_is_not_a_device_probe_result(self):
        run = runs['io-order-completion-delayed-pair-1']
        with self.assertRaises(ValueError):
            checker.inspect(run['nodes'][0]['serial_log'])
        self.assertIn('bind failed, return -98', run['nodes'][1]['pre_reboot_host_log'])
        self.assertIn('error: -111', run['nodes'][0]['host_log'])
        self.assertFalse(run['intervention']['guest_probe_reached'])
        self.assertIn('SIGKILL', run['intervention']['signals'])

    def test_missing_duplicate_or_misassigned_records_are_rejected(self):
        log = runs['io-order-baseline-control-1']['nodes'][0]['serial_log']
        row = next(line for line in log.splitlines(True) if line.startswith('IORDER_ROUND'))
        variants = (
            log.replace(row, '', 1),
            log + log,
            log.replace('requested_cpu=3 observed_cpu=3', 'requested_cpu=3 observed_cpu=2'),
            log.replace('checks=256 failures=0 expected_checks=256',
                        'checks=255 failures=0 expected_checks=256'),
            log.replace('IORDER_EXIT status=0', 'IORDER_EXIT status=1'),
            log + 'IORDER_ERROR operation=test\n',
            log + 'IORDER_MISMATCH round=0 cpu=\n',
        )
        for variant in variants:
            with self.subTest(variant=variant[-100:]), self.assertRaises(ValueError):
                checker.inspect(variant)

    def test_new_peer_rejects_old_source_protocol_before_guest_probe(self):
        run = runs['io-order-protocol-old-source-1']
        self.assertIn('SSI/KVM clock startup failed: Protocol error',
                      run['nodes'][1]['stderr_log'])
        self.assertEqual(run['result']['qemu_ssh_exits'][1], 1)
        self.assertNotEqual(run['result']['qemu_ssh_exits'][0], 0)
        self.assertIn('terminating on signal 15', run['nodes'][0]['stderr_log'])
        for node in run['nodes']:
            self.assertNotIn('IORDER_START', node['serial_log'])

    def test_failure_details_cannot_be_dropped_or_forged(self):
        log = runs['io-order-delayed-pair-2']['nodes'][0]['serial_log']
        row = next(line for line in log.splitlines(True) if line.startswith('IORDER_MISMATCH'))
        variants = (
            log.replace(row, '', 1),
            log.replace(row, row + row, 1),
            re.sub(r'(expected=)([0-9a-f]{8}) observed=[0-9a-f]{8}',
                   r'\g<1>\g<2> observed=\g<2>', log, count=1),
            log.replace('IORDER_EXIT status=1', 'IORDER_EXIT status=0'),
        )
        for variant in variants:
            with self.subTest(variant=variant[-100:]), self.assertRaises(ValueError):
                checker.inspect(variant)

    def test_sources_match_recorded_experiment(self):
        for name, expected in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), expected)
        self.assertIn('实验端口仍有 TCP 状态', evidence['live_preflight_log'])
        self.assertIn('LISTEN', evidence['live_preflight_log'])
        self.assertIn('TIME-WAIT', evidence['timewait_preflight_log'])
        self.assertIn('实验端口仍有 TCP 状态', evidence['timewait_preflight_log'])

    def test_full_workspace_preserves_data_but_still_fails_clock_acceptance(self):
        checkers = {}
        for name in ('check-clock', 'check-stress', 'check-ssh-boot'):
            module_spec = importlib.util.spec_from_file_location(name, directory / f'{name}.py')
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
            checkers[name] = module
        run = evidence['workspace']
        checkers['check-stress'].validate(run['stress_log'])
        checkers['check-clock'].validate(run['clock_log'])
        with self.assertRaisesRegex(ValueError, '超过'):
            checkers['check-clock'].validate(run['clock_log'], max_timer_ns=250_000_000)
        with self.assertRaises(ValueError):
            checkers['check-ssh-boot'].validate(run['nodes'][0]['serial_log'])
        self.assertTrue(run['result']['sftp_matches'])
        self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
        self.assertIn('Power down', run['nodes'][0]['serial_log'])
        self.assertEqual(run['result']['phases']['poweroff']['exit'], 255)


if __name__ == '__main__':
    unittest.main()
