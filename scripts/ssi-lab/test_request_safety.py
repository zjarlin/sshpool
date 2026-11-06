"""重算实机证据并破坏关键事件，保证边界、释放和取消验收不会只看摘要。"""
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


checker = load('check-request-safety')
evidence = json.loads((root / 'docs/evidence/ssi-request-safety-20261106.json').read_text())


def candidate(mode):
    return copy.deepcopy(next(run['result'] for run in evidence['candidates'] if run['result']['mode'] == mode))


class RequestSafetyTests(unittest.TestCase):
    def test_both_nodes_validate_malformed_requests_and_contended_lock(self):
        self.assertEqual({(run['node'], run['result']['mode']) for run in evidence['candidates']},
                         {(node, mode) for node in (0, 1) for mode in ('malformed', 'lock-cancel')})
        for run in evidence['candidates']:
            with self.subTest(label=run['label']):
                outcome = checker.validate(run['result'])
                self.assertEqual(outcome['temporary_pages_freed'], 128 if outcome['mode'] == 'malformed' else 8)
                self.assertTrue(run['firewall_restored_exactly'])
                self.assertEqual(run['runtime_hashes']['kernel'], evidence['kernel_sha256'])
                self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic', run['host_log'], re.I))
                self.assertIn('error -71' if outcome['mode'] == 'malformed' else 'error -4', run['host_log'])

    def test_wrong_frames_and_error_codes_are_rejected(self):
        result = candidate('malformed')
        result['cases'][0]['frame_hex'] = bytes(4110).hex()
        with self.assertRaisesRegex(ValueError, '异常帧'):
            checker.validate(result)
        result = candidate('malformed')
        result['cases'][0]['expected_code'] = 0
        with self.assertRaisesRegex(ValueError, '错误码'):
            checker.validate(result)
        result = candidate('malformed')
        result['trace'] = result['trace'].replace('capacity=24', 'capacity=4096')
        with self.assertRaisesRegex(ValueError, '接收容量'):
            checker.validate(result)

    def test_page_release_is_checked_by_actual_pointer_and_call_site(self):
        result = candidate('lock-cancel')
        row = next(line for line in result['trace'].splitlines() if 'kfree: call_site=ivy_kvm_dsm_handle_req+' in line)
        result['trace'] = result['trace'].replace(row, re.sub(r'ptr=\w+', 'ptr=0000000000000000', row), 1)
        with self.assertRaisesRegex(ValueError, '恰好释放一次'):
            checker.validate(result)
        result = candidate('lock-cancel')
        row = next(line for line in result['trace'].splitlines() if 'kmalloc: call_site=ivy_kvm_dsm_handle_req+' in line)
        result['trace'] = result['trace'].replace(row, row.replace('bytes_req=4096', 'bytes_req=1'), 1)
        with self.assertRaisesRegex(ValueError, '页面分配'):
            checker.validate(result)

    def test_waiter_must_contend_for_same_page_and_retain_eintr(self):
        result = candidate('lock-cancel')
        events, _ = checker.parse(result)
        lock = checker.one(events, 'safe_lock', result['waiter_pid'])
        row = next(line for line in result['trace'].splitlines()
                   if f"-{lock['pid']} " in line and 'safe_lock:' in line)
        result['trace'] = result['trace'].replace(row, re.sub(r'vfn=\S+', 'vfn=0x0', row), 1)
        with self.assertRaisesRegex(ValueError, '同一页面锁'):
            checker.validate(result)
        result = candidate('lock-cancel')
        events, _ = checker.parse(result)
        returned = checker.one(events, 'safe_locked', result['waiter_pid'])
        result['trace'] = result['trace'].replace(returned['detail'], returned['detail'].replace('code=-4', 'code=0'), 1)
        with self.assertRaisesRegex(ValueError, '错误码'):
            checker.validate(result)

    def test_srcu_release_and_targeted_signal_are_required(self):
        result = candidate('lock-cancel')
        events, _ = checker.parse(result)
        waiter = result['waiter_pid']
        lock = checker.one(events, 'safe_lock', waiter)
        entry = [e for e in events[:lock['index']] if e['pid'] == waiter and e['name'] == 'safe_srcu'][-1]
        release = next(e for e in events if e['name'] == 'safe_srcu_done' and e['pid'] == waiter
                       and checker.field(e, 'srcu') == checker.field(entry, 'srcu') and e['index'] > lock['index'])
        row = next(line for line in result['trace'].splitlines()
                   if f"-{waiter} " in line and 'safe_srcu_done:' in line and release['detail'] in line)
        result['trace'] = result['trace'].replace(row, re.sub(r'srcu=\S+', 'srcu=0x0', row), 1)
        with self.assertRaisesRegex(ValueError, 'SRCU'):
            checker.validate(result)
        result = candidate('lock-cancel')
        result['trace'] = result['trace'].replace('grp=0', 'grp=1', 1)
        with self.assertRaisesRegex(ValueError, '定向投递'):
            checker.validate(result)

    def test_response_hash_alone_and_nonzero_padding_cannot_pass(self):
        result = candidate('malformed')
        frame = bytearray.fromhex(result['normal_response']['hex'])
        frame[100] ^= 1
        result['normal_response']['hex'] = frame.hex()
        with self.assertRaisesRegex(ValueError, '响应内容'):
            checker.validate(result)
        result = candidate('malformed')
        frame = bytearray.fromhex(result['invalidate_response']['hex'])
        frame[-1] = 1
        result['invalidate_response']['hex'] = frame.hex()
        with self.assertRaisesRegex(ValueError, '尾部未清零'):
            checker.validate(result)

    def test_missing_events_and_missed_probes_cannot_pass(self):
        result = candidate('lock-cancel')
        row = next(line for line in result['trace'].splitlines(True) if 'safe_done:' in line)
        result['trace'] = result['trace'].replace(row, '', 1)
        with self.assertRaisesRegex(ValueError, '事件缺失'):
            checker.validate(result)
        result = candidate('lock-cancel')
        result['kprobe_profile'] = re.sub(r'(safe_locked\s+3\s+)0', r'\g<1>1', result['kprobe_profile'])
        with self.assertRaisesRegex(ValueError, '遗漏'):
            checker.validate(result)
        result = candidate('lock-cancel')
        cpu = next(iter(result['trace_stats']))
        result['trace_stats'][cpu] = result['trace_stats'][cpu].replace('overrun: 0', 'overrun: 1')
        with self.assertRaisesRegex(ValueError, '丢失'):
            checker.validate(result)

    def test_sampling_failures_are_preserved_and_not_accepted(self):
        failed = [run for run in evidence['attempts'] if run['errors']]
        self.assertEqual(len(failed), 3)
        for run in evidence['attempts']:
            self.assertTrue(run['trace_cleanup_complete'])
            self.assertTrue(run['firewall_restored_exactly'])
            self.assertEqual(len(run['result_sha256']), 64)
        for run in failed:
            self.assertIsNone(run['exit'])

    def test_existing_missing_slot_cancellation_still_works(self):
        previous = load('check-request-cancel')
        self.assertEqual({run['result']['mode'] for run in evidence['regressions']}, {'cancel-root', 'close-vm'})
        for run in evidence['regressions']:
            previous.validate(run['result'])
            self.assertTrue(run['firewall_restored_exactly'])

    def test_compiled_candidate_and_replayed_sources_match(self):
        for path, digest in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        self.assertEqual(len(evidence['compiled_sources']), 5)
        for values in evidence['compiled_sources'].values():
            self.assertEqual(values['candidate'], values['compiled'])
            self.assertEqual(values['candidate'], values['replayed'])
        self.assertTrue(evidence['config_comparison']['only_localversion_changed'])
        probe_hash = evidence['source_sha256']['scripts/ssi-lab/probe-request-safety.py']
        for run in evidence['candidates']:
            self.assertEqual(run['runtime_hashes']['files']['probe-request-safety.py'], probe_hash)

    def test_cross_node_page_versions_are_recomputed(self):
        history, checks, closed = [], [], []
        probe = load('probe-pvclock')
        for line in evidence['pvclock']['log'].splitlines():
            if line.startswith('PVCLOCK_CHECK '):
                row = json.loads(line.removeprefix('PVCLOCK_CHECK '))
                before, previous, latest, observed = [history[i] for i in (-5, -3, -2, -1)]
                cpu = row['cpu']
                self.assertTrue(probe.check_exchange(before, previous, latest, observed, cpu, 1 - cpu)['pass'])
                checks.append((row['round'], cpu))
            elif line.startswith('{'):
                record = json.loads(line)
                history.append(record)
                if record['op'] == 'closed':
                    closed.append(record['node'])
        self.assertEqual(checks, [(r, cpu) for r in range(4) for cpu in range(2)])
        self.assertEqual(closed, [1, 0])

    def test_lab_is_restored_to_stock(self):
        nodes = evidence['restoration']['nodes']
        self.assertEqual([node['node'] for node in nodes], [0, 1])
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'])
            self.assertTrue(node['firewall_matches_original'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            for field in ('grub_environment', 'trace_events', 'trace_instances'):
                self.assertEqual(node[field], '')

    def test_workspace_data_passes_but_full_clock_gate_still_fails(self):
        run = evidence['workspace']
        load('check-stress').validate(run['stress_log'])
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
            self.assertIsNone(re.search(r'WARNING:|BUG:|Oops:|segfault|Kernel panic', node['host_log'], re.I))


if __name__ == '__main__':
    unittest.main()
