"""从真实 KVM 探针的线程累计计数重新计算忙等回归，不采信通过标记。"""
import json
import importlib.util
from pathlib import Path
import unittest


class ReceiveEvidenceTests(unittest.TestCase):
    def test_pf6_spins_and_pf7_sleeps_on_both_nodes(self):
        path = Path(__file__).resolve().parents[2] / 'docs/evidence/ssi-receive-probes-20261106.json'
        runs = json.loads(path.read_text())['runs']
        self.assertEqual(len(runs), 6)
        for run in runs:
            result = run['result']
            with self.subTest(run=run['label']):
                self.assertEqual(result['errors'], [])
                self.assertTrue(result['closed'])
                self.assertEqual(result['exit'], 0)
                self.assertEqual(result['remaining_threads'], [])
                self.assertEqual([phase['phase'] for phase in result['phases']],
                                 ['idle', 'partial_frame'])
                self.assertIn('ktcp_receive error', run['host_log'])
                for phase in result['phases']:
                    before, after = phase['before'], phase['after']
                    self.assertEqual(len(before), 8)
                    self.assertEqual(before.keys(), after.keys())
                    elapsed = phase['elapsed_ns']
                    self.assertGreaterEqual(elapsed, 3_000_000_000)
                    runtime = 0
                    for tid, task in after.items():
                        start = before[tid]['stat'].rsplit(')', 1)[1].split()[19]
                        end = task['stat'].rsplit(')', 1)[1].split()[19]
                        self.assertEqual(start, end)
                        delta = task['runtime_ns'] - before[tid]['runtime_ns']
                        self.assertGreaterEqual(delta, 0)
                        runtime += delta
                    ratio = runtime / elapsed
                    self.assertEqual(runtime, phase['cpu_ns'])
                    if result['kernel'].endswith('pf6'):
                        self.assertGreater(ratio, 0.9)
                    else:
                        self.assertTrue(result['kernel'].endswith('pf7'))
                        self.assertLess(ratio, 0.1)
                        stacks = '\n'.join(frame for task in after.values() for frame in task['stack'])
                        self.assertIn('sk_wait_data+', stacks)

    def test_open_partial_connection_does_not_prevent_vm_destruction(self):
        path = Path(__file__).resolve().parents[2] / 'docs/evidence/ssi-receive-probes-20261106.json'
        runs = [run for run in json.loads(path.read_text())['runs']
                if run['result'].get('close_order') == 'vm-first']
        self.assertEqual(len(runs), 2)
        for run in runs:
            self.assertTrue(run['result']['closed'])
            self.assertEqual(run['result']['exit'], 0)
            self.assertEqual(run['result']['remaining_threads'], [])
            self.assertIn('ret -4', run['host_log'])

    def test_full_workloads_pass_but_boot_acceptance_still_fails(self):
        directory = Path(__file__).resolve().parent
        checkers = {}
        for name in ('check-clock', 'check-stress', 'check-ssh-boot'):
            spec = importlib.util.spec_from_file_location(name, directory / f'{name}.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            checkers[name] = module
        path = directory.parents[1] / 'docs/evidence/ssi-receive-workspaces-20261106.json'
        runs = json.loads(path.read_text())['runs']
        self.assertEqual(len(runs), 3)
        for run in runs:
            with self.subTest(run=run['label']):
                checkers['check-stress'].validate(run['stress_log'])
                checkers['check-clock'].validate(run['clock_log'])
                if run['label'].startswith('pf7'):
                    checkers['check-clock'].validate(run['clock_log'], max_timer_ns=250_000_000)
                else:
                    with self.assertRaises(ValueError):
                        checkers['check-clock'].validate(run['clock_log'], max_timer_ns=250_000_000)
                with self.assertRaises(ValueError):
                    checkers['check-ssh-boot'].validate(run['serial_log'])
                self.assertTrue(run['result']['sftp_matches'])
                self.assertTrue(all(code == 0 for code in run['result']['qemu_ssh_exits']))
                self.assertIn('Power down', run['serial_log'])


if __name__ == '__main__':
    unittest.main()
