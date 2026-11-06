"""重算真实启动、回收与回归证据；缺失或乱序记录不能当作成功。"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest


directory = Path(__file__).resolve().parent
root = directory.parents[1]


def load_checker(name):
    spec = importlib.util.spec_from_file_location(name, directory / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load_checker('check-startup')
evidence = json.loads((root / 'docs/evidence/ssi-startup-20261106.json').read_text())


class StartupEvidenceTests(unittest.TestCase):
    def test_old_kernel_reports_false_success_and_candidate_returns_bind_error(self):
        baseline = evidence['baseline']
        self.assertEqual(baseline['result']['exit'], 1)
        self.assertIn('case=occupied result=0 errno=0 expected_errno=98', baseline['stdout'])
        with self.assertRaises(ValueError):
            checker.validate(baseline['stdout'])
        self.assertEqual(len(evidence['startup']), 6)
        combinations = set()
        for run in evidence['startup']:
            result = checker.validate(run['stdout'])
            combinations.add((run['result']['node'], result['mode']))
            self.assertEqual(run['result']['exit'], 0)
            self.assertEqual(run['result']['remaining'], '')
            self.assertEqual(result['kernel'], evidence['kernel'])
        self.assertEqual(combinations, {(node, mode) for node in range(2)
                                       for mode in ('occupied', 'cycles', 'invalid')})

    def test_missing_retries_wrong_errno_and_reordered_closes_are_rejected(self):
        log = next(run['stdout'] for run in evidence['startup']
                   if run['result']['mode'] == 'occupied')
        retry = 'STARTUP_ENABLE case=retry result=0 errno=0 expected_errno=0\n'
        variants = (
            log.replace(retry, ''),
            log.replace('errno=98', 'errno=48'),
            log.replace('result=-1', 'result=0'),
            log.replace('STARTUP_CLOSE_DONE\n', ''),
            log.replace('STARTUP_CLOSE_BEGIN\nSTARTUP_CLOSE_DONE',
                        'STARTUP_CLOSE_DONE\nSTARTUP_CLOSE_BEGIN'),
            log.replace(retry, '').replace('STARTUP_RESULT', retry + 'STARTUP_RESULT'),
            log + 'STARTUP_RESULT passed=1\n',
            log + 'STARTUP_RESULT passed=\n',
            log + 'STARTUP_ERROR operation=close\n',
            log + log,
        )
        for changed in variants:
            with self.subTest(log=changed), self.assertRaises(ValueError):
                checker.validate(changed)

    def test_cycle_counts_cannot_replace_per_close_port_release_evidence(self):
        log = next(run['stdout'] for run in evidence['startup']
                   if run['result']['mode'] == 'cycles')
        self.assertEqual(checker.validate(log)['closed_vms'], 64)
        variants = (
            log.replace('STARTUP_CYCLE index=32 released=1\n', ''),
            log.replace('index=32', 'index=31'),
            log.replace('index=32 released=1', 'index=32 released=0'),
            log.replace('STARTUP_CLOSE_DONE\nSTARTUP_CYCLE index=0 released=1',
                        'STARTUP_CYCLE index=0 released=1\nSTARTUP_CLOSE_DONE'),
        )
        for changed in variants:
            with self.subTest(log=changed[-200:]), self.assertRaises(ValueError):
                checker.validate(changed)

    def test_real_qemu_reports_conflict_before_guest_execution(self):
        self.assertEqual(len(evidence['qemu_conflict']), 2)
        for run in evidence['qemu_conflict']:
            result = run['result']
            self.assertEqual(result['exit'], 1)
            self.assertIn('Enable kernel DSM failed: Address already in use', result['stderr'])
            self.assertNotIn('Linux version', result['stdout'])
            self.assertTrue(result['port_released'])
            self.assertEqual(result['remaining'], '')
            self.assertIn('bind failed, return -98', run['host_log'])

    def test_connected_workers_still_sleep_and_both_close_orders_finish(self):
        self.assertEqual(len(evidence['receive']), 4)
        for run in evidence['receive']:
            result = run['result']
            self.assertEqual(result['errors'], [])
            self.assertTrue(result['closed'])
            self.assertEqual(result['exit'], 0)
            self.assertEqual(result['remaining_threads'], [])
            self.assertTrue(run['firewall_restored_exactly'])
            self.assertEqual([p['phase'] for p in result['phases']], ['idle', 'partial_frame'])
            for phase in result['phases']:
                before, after = phase['before'], phase['after']
                self.assertEqual(len(before), 8)
                self.assertEqual(before.keys(), after.keys())
                self.assertGreaterEqual(phase['elapsed_ns'], 3_000_000_000)
                runtime = 0
                for tid, task in after.items():
                    self.assertEqual(task['stat'].rsplit(')', 1)[1].split()[19],
                                     before[tid]['stat'].rsplit(')', 1)[1].split()[19])
                    delta = task['runtime_ns'] - before[tid]['runtime_ns']
                    self.assertGreaterEqual(delta, 0)
                    runtime += delta
                self.assertEqual(runtime, phase['cpu_ns'])
                self.assertLess(runtime / phase['elapsed_ns'], 0.1)
            self.assertIn('ktcp_receive', run['host_log'])

    def test_pvclock_page_handoffs_preserve_remote_and_adjacent_records(self):
        probe = load_checker('probe-pvclock')
        lines = evidence['pvclock']['log'].splitlines()
        checks, closed = [], []
        history = []
        for line in lines:
            if line.startswith('PVCLOCK_CHECK '):
                row = json.loads(line.removeprefix('PVCLOCK_CHECK '))
                before, previous, latest, observed = [history[i] for i in (-5, -3, -2, -1)]
                cpu = row['cpu']
                self.assertEqual([history[i]['op'] for i in range(-6, 0)],
                                 ['claim', 'tick', 'claim', 'read', 'tick', 'read'])
                self.assertEqual([history[i]['node'] for i in range(-6, 0)],
                                 [cpu, cpu, 1 - cpu, 1 - cpu, cpu, 1 - cpu])
                self.assertTrue(probe.check_exchange(before, previous, latest, observed,
                                                     cpu, 1 - cpu)['pass'])
                checks.append((row['round'], cpu))
            elif line.startswith('{'):
                record = json.loads(line)
                history.append(record)
                if record['op'] == 'closed':
                    closed.append(record['node'])
        self.assertEqual(checks, [(r, cpu) for r in range(4) for cpu in range(2)])
        self.assertEqual(closed, [1, 0])
        self.assertEqual(json.loads(lines[-1].removeprefix('PVCLOCK_RESULT ')),
                         {'checks': 8, 'failures': 0, 'errors': []})

    def test_experiment_sources_and_compiled_patch_replay_match(self):
        for path, expected in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for record in evidence['compiled_sources'].values():
            self.assertEqual(record['candidate'], record['compiled'])
            self.assertEqual(record['candidate'], record['replayed'])

    def test_local_probes_have_no_new_host_kernel_faults(self):
        runs = evidence['startup'] + evidence['qemu_conflict'] + evidence['receive']
        for run in runs:
            with self.subTest(label=run['label']):
                self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                           run['host_log'], re.IGNORECASE))

    def test_full_guest_preserves_data_without_hiding_boot_and_close_errors(self):
        run = evidence['workspace']
        load_checker('check-stress').validate(run['stress_log'])
        load_checker('check-clock').validate(run['clock_log'], max_timer_ns=250_000_000)
        serial = run['nodes'][0]['serial_log']
        with self.assertRaisesRegex(ValueError, 'watchdog'):
            load_checker('check-ssh-boot').validate(serial)
        self.assertEqual(serial.count('Long readout interval, skipping watchdog check'), 2)
        self.assertIn('hogged CPU', serial)
        self.assertIn('Power down', serial)
        self.assertTrue(run['result']['sftp_matches'])
        self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
        self.assertEqual(run['result']['samples_errors'], [])
        self.assertEqual(run['result']['phases']['poweroff']['exit'], 255)
        for phase in ('identity', 'clock-upload', 'clock', 'stress', 'sftp'):
            self.assertEqual(run['result']['phases'][phase]['exit'], 0)
        self.assertIn('ret -104', run['nodes'][0]['host_log'])
        self.assertIn('ret -4', run['nodes'][1]['host_log'])
        for node in run['nodes']:
            hashes = [line.split()[0] for line in node['runtime_hashes'].splitlines()]
            self.assertEqual(hashes[0], evidence['kernel_sha256'])
            self.assertEqual(hashes[1], run['result']['qemu_sha256'])
            self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                       node['host_log'], re.IGNORECASE))


if __name__ == '__main__':
    unittest.main()
