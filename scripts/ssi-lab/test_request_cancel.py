"""重算完整请求的真实实验，拒绝伪取消、内容损坏、错误身份和丢失事件。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest


directory = Path(__file__).resolve().parent
root = directory.parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('check-request-cancel')
evidence = json.loads((root / 'docs/evidence/ssi-request-cancel-20261106.json').read_text())


def candidate(mode):
    return copy.deepcopy(next(run['result'] for run in evidence['candidates']
                              if run['result']['mode'] == mode))


class RequestCancelTests(unittest.TestCase):
    def test_baseline_requires_registration_to_escape_retry(self):
        baseline = evidence['baseline']['result']
        self.assertFalse(checker.inspect(baseline)['cancelled_without_registration'])
        with self.assertRaisesRegex(ValueError, '依赖补注册'):
            checker.validate(baseline)
        checker.validate(evidence['baseline_read']['result'])

    def test_both_nodes_pass_all_three_complete_request_modes(self):
        self.assertEqual({(run['node'], run['result']['mode']) for run in evidence['candidates']},
                         {(node, mode) for node in (0, 1)
                          for mode in ('late-register', 'cancel-root', 'close-vm')})
        for run in evidence['candidates']:
            with self.subTest(label=run['label']):
                observed = checker.validate(run['result'])
                self.assertEqual(observed['thread_exits'], 9)
                self.assertEqual(observed['complete_requests'], 1)
                self.assertTrue(run['firewall_restored_exactly'])
                self.assertEqual(run['runtime_hashes']['kernel'], evidence['kernel_sha256'])
                log = run['host_log_summary']
                self.assertGreater(log['missing_slot_warning_count'], 0)
                self.assertEqual(log['raw_lines'], log['missing_slot_warning_count'] + len(log['other_lines']))
                self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                           '\n'.join(log['other_lines']), re.IGNORECASE))

    def test_process_directed_signal_attempts_are_not_valid_cancellation(self):
        self.assertEqual(len(evidence['attempts']), 2)
        for run in evidence['attempts']:
            with self.subTest(label=run['label']), self.assertRaises(ValueError):
                checker.validate(run['result'])

    def test_complete_frame_and_page_hash_are_required(self):
        for frame in (bytes(8), bytes(4110), bytes(4111)):
            result = candidate('cancel-root')
            result['request_hex'] = frame.hex()
            with self.assertRaises(ValueError):
                checker.validate(result)
        result = candidate('late-register')
        result['response']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '页面内容'):
            checker.validate(result)
        result = candidate('cancel-root')
        result['trace'] = result['trace'].replace('len=24', 'len=8')
        with self.assertRaisesRegex(ValueError, '完整请求'):
            checker.validate(result)

    def test_signal_target_group_and_error_cannot_be_falsified(self):
        for old, new in (('grp=0', 'grp=1'), ('code=128', 'code=-6'),
                         ('res=0', 'res=1'), ('code=-4', 'code=0')):
            result = candidate('cancel-root')
            result['trace'] = result['trace'].replace(old, new, 1)
            with self.subTest(old=old), self.assertRaises(ValueError):
                checker.validate(result)
        result = candidate('cancel-root')
        result['trace'] = result['trace'].replace('comm=dsm-conn/0:0', 'comm=dsm-conn/0:9', 1)
        with self.assertRaises(ValueError):
            checker.validate(result)

    def test_snapshot_boolean_alone_cannot_claim_cancellation(self):
        result = copy.deepcopy(evidence['baseline']['result'])
        result['tasks_before_registration'] = {}
        with self.assertRaisesRegex(ValueError, '快照'):
            checker.validate(result)
        result = candidate('close-vm')
        result['worker_pid'] += 100000
        with self.assertRaisesRegex(ValueError, '其他进程'):
            checker.validate(result)

    def test_missing_duplicate_or_dropped_events_are_rejected(self):
        original = candidate('cancel-root')
        row = next(line for line in original['trace'].splitlines(True)
                   if 'sched_process_exit:' in line)
        for changed in (original['trace'].replace(row, '', 1),
                        original['trace'].replace(row, row + row, 1)):
            result = copy.deepcopy(original)
            result['trace'] = changed
            with self.assertRaises(ValueError):
                checker.validate(result)
        for field in ('overrun', 'commit overrun', 'dropped events'):
            result = copy.deepcopy(original)
            cpu = next(iter(result['trace_stats']))
            result['trace_stats'][cpu] = re.sub('^' + field + ': 0$', field + ': 1',
                                               result['trace_stats'][cpu], flags=re.MULTILINE)
            with self.assertRaises(ValueError):
                checker.validate(result)
        result = copy.deepcopy(original)
        result['kprobe_profile'] = re.sub(r'(req_receive\s+8\s+)0', r'\g<1>1', result['kprobe_profile'])
        with self.assertRaises(ValueError):
            checker.validate(result)

    def test_candidate_replay_and_actual_compiled_source_match(self):
        for path, expected in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), expected)
        for record in evidence['compiled_sources'].values():
            self.assertEqual(record['candidate'], record['compiled'])
            self.assertEqual(record['candidate'], record['replayed'])
        self.assertTrue(evidence['config_comparison']['only_localversion_changed'])

    def test_cross_node_page_handoffs_preserve_contents(self):
        probe = load('probe-pvclock')
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

    def test_workspace_data_passes_but_clock_and_watchdog_gate_still_fails(self):
        run = evidence['workspace']
        load('check-stress').validate(run['stress_log'])
        # 先单独核对样本完整性和单调性，随后仍按原定上限明确拒绝本轮延迟。
        load('check-clock').validate(run['clock_log'])
        with self.assertRaisesRegex(ValueError, '超过 250000000'):
            load('check-clock').validate(run['clock_log'], max_timer_ns=250_000_000)
        serial = run['nodes'][0]['serial_log']
        with self.assertRaisesRegex(ValueError, 'watchdog'):
            load('check-ssh-boot').validate(serial)
        self.assertIn('Power down', serial)
        self.assertIn('hogged CPU', serial)
        self.assertTrue(run['result']['sftp_matches'])
        self.assertEqual(run['result']['sftp_sha256'],
                         'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83')
        self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])
        self.assertEqual(run['result']['samples_errors'], [])
        self.assertEqual(run['result']['phases']['poweroff']['exit'], 255)
        for phase in ('identity', 'clock-upload', 'clock', 'stress', 'sftp'):
            self.assertEqual(run['result']['phases'][phase]['exit'], 0)
        for node in run['nodes']:
            self.assertEqual(node['runtime_hashes'].split()[0], evidence['kernel_sha256'])
            self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic',
                                       node['host_log'], re.IGNORECASE))

    def test_lab_restored_to_stock_without_pending_work(self):
        nodes = evidence['restoration']['nodes']
        self.assertEqual([node['node'] for node in nodes], [0, 1])
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            self.assertEqual(node['grub_environment'], '')
            self.assertEqual(node['trace_events'], '')
            self.assertEqual(node['trace_instances'], '')


if __name__ == '__main__':
    unittest.main()
