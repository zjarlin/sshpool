"""用真实内核跟踪核对关闭顺序，并拒绝丢失、乱序与身份不符的证据。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest


directory = Path(__file__).resolve().parent
root = directory.parents[1]
spec = importlib.util.spec_from_file_location('check_teardown', directory / 'check-teardown.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
evidence = json.loads((root / 'docs/evidence/ssi-teardown-20261106.json').read_text())


def load_checker(name):
    spec = importlib.util.spec_from_file_location(name, directory / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TeardownTests(unittest.TestCase):
    def test_baseline_destroys_resources_before_workers_exit(self):
        baseline = evidence['baseline']['result']
        self.assertFalse(checker.inspect(baseline)['workers_stopped_before_destroy'])
        with self.assertRaisesRegex(ValueError, '晚于'):
            checker.validate(baseline)

    def test_candidate_joins_all_workers_before_destroy_on_both_nodes(self):
        runs = evidence['candidates']
        self.assertEqual({(run['node'], run['result']['close_order']) for run in runs},
                         {(node, order) for node in (0, 1) for order in ('peer-first', 'vm-first')})
        for run in runs:
            with self.subTest(label=run['label']):
                self.assertEqual(checker.validate(run['result']),
                                 {'vcpu_destroys': 2, 'dsm_thread_exits': 9,
                                  'workers_stopped_before_destroy': True, 'events': 20})
                self.assertTrue(run['firewall_restored_exactly'])
                self.assertIn('ktcp_receive', run['host_log'])
                self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                           run['host_log'], re.IGNORECASE))

    def test_missing_or_duplicate_exit_records_are_rejected(self):
        original = evidence['candidates'][0]['result']
        row = next(line for line in original['trace'].splitlines(True)
                   if 'sched_process_exit:' in line)
        for changed in (original['trace'].replace(row, '', 1),
                        original['trace'].replace(row, row + row, 1)):
            value = copy.deepcopy(original)
            value['trace'] = changed
            with self.assertRaises(ValueError):
                checker.validate(value)

    def test_overruns_and_missed_kprobes_cannot_be_hidden(self):
        original = evidence['candidates'][0]['result']
        for field in ('overrun', 'commit overrun', 'dropped events'):
            value = copy.deepcopy(original)
            cpu = next(iter(value['trace_stats']))
            value['trace_stats'][cpu] = re.sub('^' + field + ': 0$', field + ': 1',
                                               value['trace_stats'][cpu], flags=re.MULTILINE)
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.validate(value)
        value = copy.deepcopy(original)
        value['kprobe_profile'] = re.sub(r'(pre\s+1\s+)0', r'\g<1>1', value['kprobe_profile'])
        with self.assertRaises(ValueError):
            checker.validate(value)
        value['kprobe_profile'] = ''
        with self.assertRaises(ValueError):
            checker.validate(value)

    def test_wrong_thread_or_destroy_caller_is_rejected(self):
        original = evidence['candidates'][0]['result']
        value = copy.deepcopy(original)
        value['trace'] = value['trace'].replace('comm=dsm-conn/0:0', 'comm=dsm-conn/0:9')
        with self.assertRaises(ValueError):
            checker.validate(value)
        value = copy.deepcopy(original)
        tid = next(iter(value['receive']['phases'][-1]['after']))
        del value['receive']['phases'][-1]['after'][tid]
        with self.assertRaises(ValueError):
            checker.validate(value)
        value = copy.deepcopy(original)
        value['trace'] = re.sub(r'(probe-pvclock-)\d+', r'\g<1>99999', value['trace'], count=1)
        with self.assertRaises(ValueError):
            checker.validate(value)

    def test_returning_from_stop_before_last_thread_exit_is_rejected(self):
        value = copy.deepcopy(evidence['candidates'][0]['result'])
        lines = value['trace'].splitlines(True)
        root_exit = next(i for i, row in enumerate(lines) if 'comm=kvm-dsm/0 ' in row)
        stop_done = next(i for i, row in enumerate(lines) if ': stop_done:' in row)
        # 交换事件身份并保留原时间戳，避免仅靠时间倒退检查发现乱序。
        left, right = lines[root_exit], lines[stop_done]
        left_time = checker.EVENT.fullmatch(left.rstrip()).group(4)
        right_time = checker.EVENT.fullmatch(right.rstrip()).group(4)
        lines[root_exit] = re.sub(r'\d+\.\d+(?=: )', left_time, right, count=1)
        lines[stop_done] = re.sub(r'\d+\.\d+(?=: )', right_time, left, count=1)
        value['trace'] = ''.join(lines)
        with self.assertRaisesRegex(ValueError, '停止函数返回时'):
            checker.validate(value)

    def test_failed_setup_and_incomplete_instrumentation_are_not_acceptance(self):
        self.assertEqual(len(evidence['attempts']), 3)
        for run in evidence['attempts']:
            with self.subTest(label=run['label']), self.assertRaises(ValueError):
                checker.validate(run['result'])

    def test_sources_match_compiled_and_replayed_patch(self):
        for path, expected in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for record in evidence['compiled_sources'].values():
            self.assertEqual(record['candidate'], record['compiled'])
            self.assertEqual(record['candidate'], record['replayed'])

    def test_startup_failure_and_repeated_close_regressions(self):
        startup = load_checker('check-startup')
        self.assertEqual(len(evidence['startup']), 6)
        for run in evidence['startup']:
            with self.subTest(label=run['label']):
                self.assertEqual(startup.validate(run['stdout'])['kernel'], evidence['kernel'])
                self.assertEqual(run['result']['exit'], 0)
                self.assertEqual(run['result']['remaining'], '')

    def test_pvclock_handoffs_still_preserve_remote_page_contents(self):
        probe = load_checker('probe-pvclock')
        history, checks, closed = [], [], []
        lines = evidence['pvclock']['log'].splitlines()
        for line in lines:
            if line.startswith('PVCLOCK_CHECK '):
                row = json.loads(line.removeprefix('PVCLOCK_CHECK '))
                before, previous, latest, observed = [history[i] for i in (-5, -3, -2, -1)]
                cpu = row['cpu']
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

    def test_full_workspace_preserves_data_but_retains_unresolved_errors(self):
        run = evidence['workspace']
        load_checker('check-stress').validate(run['stress_log'])
        load_checker('check-clock').validate(run['clock_log'], max_timer_ns=250_000_000)
        serial = run['nodes'][0]['serial_log']
        with self.assertRaisesRegex(ValueError, 'watchdog'):
            load_checker('check-ssh-boot').validate(serial)
        self.assertEqual(serial.count('Long readout interval, skipping watchdog check'), 3)
        self.assertIn('Power down', serial)
        self.assertTrue(run['result']['sftp_matches'])
        self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
        self.assertEqual(run['result']['samples_errors'], [])
        self.assertEqual(run['result']['phases']['poweroff']['exit'], 255)
        for phase in ('identity', 'clock-upload', 'clock', 'stress', 'sftp'):
            self.assertEqual(run['result']['phases'][phase]['exit'], 0)
        self.assertIn('kvm_dsm_stop: node-0 dsm root server exited with -104',
                      run['nodes'][0]['host_log'])
        self.assertIn('ret -4', run['nodes'][1]['host_log'])
        for node in run['nodes']:
            self.assertEqual(node['runtime_hashes'].split()[0], evidence['kernel_sha256'])
            self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                       node['host_log'], re.IGNORECASE))


if __name__ == '__main__':
    unittest.main()
