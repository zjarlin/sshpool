"""重放两台 VM 的原生关闭证据，拒绝遗漏连接、提前成功及损坏的对端报文。"""
from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('kernel_close', HERE / 'check-kernel-close.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def rewrite_trace(record, transform):
    """同步计数元数据后修改事件，用来验证协议检查而非只触发头部计数错误。"""
    lines = record['trace'].splitlines()
    headers = [line for line in lines if line.startswith('#')]
    events = [line for line in lines if line.strip() and not line.startswith('#')]
    times = [re.search(r' (\d+\.\d+): ', line)[1] for line in events]
    events = transform(events)
    events = [re.sub(r' \d+\.\d+: ', ' ' + stamp + ': ', line, count=1)
              for line, stamp in zip(events, times)]
    cpus = Counter()
    probes = Counter()
    for line in events:
        match = checker.native.drain.safety.teardown.EVENT.fullmatch(line)
        cpus['cpu' + str(int(match[3]))] += 1
        probes[match[5]] += 1
    headers = [re.sub(r'entries-in-buffer/entries-written: \d+/\d+',
                      f'entries-in-buffer/entries-written: {len(events)}/{len(events)}', line)
               for line in headers]
    record['trace'] = '\n'.join(headers + events) + '\n'
    for cpu, stats in record['trace_stats'].items():
        record['trace_stats'][cpu] = re.sub(r'^entries: \d+$', f'entries: {cpus[cpu]}',
                                          stats, flags=re.MULTILINE)
    record['kprobe_profile'] = '\n'.join(
        f'{line.split()[0]} {probes[line.split()[0]]} 0'
        for line in record['kprobe_profile'].splitlines()) + '\n'


class KernelCloseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((ROOT / 'docs/evidence/ssi-kernel-close-20261108.json').read_text())
        cls.records = {row['record']['mode']: row['record'] for row in cls.evidence['probes']}

    def reject(self, mode, mutate, message=None):
        record = deepcopy(self.records[mode])
        mutate(record)
        with self.assertRaisesRegex(ValueError, message or '.'):
            checker.inspect(record)

    def test_all_native_cases_and_real_remote_pair(self):
        probes = self.evidence['probes']
        modes = set(checker.probe.MODES) - {'single', 'remote'}
        self.assertEqual({(row['run']['node'], row['record']['mode']) for row in probes},
                         {(node, mode) for node in (0, 1) for mode in modes})
        self.assertEqual(len(probes), 40)
        for row in probes + self.evidence['remote_probes']:
            with self.subTest(label=row['label']):
                self.assertEqual(checker.inspect(row['record']), row['analysis'])
                self.assertEqual(row['firewall']['before'], row['firewall']['after'])
                self.assertNotRegex(row['host_log'], r'WARNING:|BUG:|Oops:|Kernel panic|hung task')
                self.assertEqual(hashlib.sha256((json.dumps(row['record'], indent=2) + '\n').encode()).hexdigest(),
                                 row['record_sha256'])
        remote = self.evidence['remote_probes']
        self.assertEqual(len(remote), 2)
        self.assertEqual({next(call['node'] for call in row['record']['calls'] if call['name'] == 'close')
                          for row in remote}, {0, 1})

    def test_sources_and_patch_match_executed_build(self):
        for name, digest in self.evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        for row in self.evidence['probes'] + self.evidence['remote_probes']:
            self.assertEqual(row['runtime_hashes']['probe-kernel-close.py'], row['record']['probe_sha256'])
            sources = self.evidence['probe_source_versions'][row['record']['probe_sha256']]
            for name, digest in sources.items():
                self.assertEqual(row['runtime_hashes'][name], digest)
        self.assertTrue(self.evidence['build']['patch_replay_matches_compiled_source'])
        self.assertTrue(self.evidence['build']['config_only_localversion_changed'])

    def test_root_completion_is_required_even_with_matching_trace_counts(self):
        self.reject('pair', lambda r: rewrite_trace(r, lambda lines:
                    [line for line in lines if 'kc_root_done:' not in line]), '根线程未完成')

    def test_close_cannot_return_before_root_releases_connections(self):
        def reorder(record):
            def transform(lines):
                roots = [line for line in lines if 'kc_root_done:' in line]
                remaining = [line for line in lines if 'kc_root_done:' not in line]
                at = max(i for i, line in enumerate(remaining) if 'kc_closed:' in line) + 1
                return remaining[:at] + roots + remaining[at:]
            rewrite_trace(record, transform)
        self.reject('pair', reorder, '关闭先于根线程资源回收返回')

    def test_invalid_parameter_cases_cannot_be_replaced_by_duplicates(self):
        def duplicate(record):
            invalid = [row for row in record['calls'] if row['name'] == 'invalid']
            invalid[-1]['input_hex'] = invalid[0]['input_hex']
        self.reject('validation', duplicate, '非法参数集合')

    def test_payload_is_verified_beyond_its_supplied_hash(self):
        def corrupt(record):
            row = next(row for row in record['calls'] if row['name'] == 'read')
            payload = bytes(8192)
            row.update(payload_hex=payload.hex(), payload_sha256=hashlib.sha256(payload).hexdigest())
        self.reject('pair', corrupt, '实际页面内容错误')

    def test_absolute_deadline_cannot_be_extended_by_later_phases(self):
        def delayed(record):
            row = next(row for row in record['calls'] if row['name'] == 'close')
            row['end_ns'] = row['start_ns'] + 3_000_000_000
        self.reject('synthetic-budget', delayed, '总期限')
        self.reject('synthetic-budget', lambda r: next(row for row in r['calls']
                    if row['name'] == 'close').update(errno=0))

    def test_wire_identity_and_final_confirmation_are_required(self):
        def bad_target(record):
            frame = next(row for row in record['synthetic_wire']
                         if row['direction'] == 'send' and bytes.fromhex(row['hex'])[14:18] ==
                         struct.pack('<I', 0x44534d43))
            raw = bytearray.fromhex(frame['hex'])
            struct.pack_into('<H', raw, 24, 1)
            frame['hex'] = raw.hex()
        self.reject('synthetic-clean', bad_target, '确认端点错误')
        self.reject('synthetic-missing-final', lambda r: r.update(withheld_final=False))
        self.reject('synthetic-clean', lambda r: r.update(requester_eof='00'))

    def test_send_pressure_and_half_ack_need_actual_observations(self):
        self.reject('synthetic-half-ack', lambda r: r.update(partial_ack_hex='00'))
        self.reject('synthetic-send-pressure', lambda r: r.update(pressure_blocked_tids=[]))
        self.reject('synthetic-send-pressure', lambda r: r.update(pressure_sent_sha256='0' * 64))

    def test_missing_or_lost_native_trace_is_rejected(self):
        self.reject('pair', lambda r: r['trace_stats'].update(cpu0=r['trace_stats']['cpu0'].replace(
                    'overrun: 0', 'overrun: 1', 1)))
        self.reject('pair', lambda r: r.update(trace=r['trace'].replace('kc_closed:', 'kc_missing:', 1)))
        self.reject('pair', lambda r: r.update(kprobe_profile=r['kprobe_profile'].replace('kc_ack', 'kc_missing')))

    def test_native_active_call_must_finish_before_fencing(self):
        self.reject('active-ioctl', lambda r: r.update(close_waiting_before_unpin=False))
        self.reject('active-ioctl', lambda r: r.update(active_memory_hex=bytes(8192).hex()))
        self.reject('active-ioctl', lambda r: r.update(tasks_before_cleanup={'123': {}}))

    def test_native_proof_cannot_claim_full_qemu_shutdown(self):
        self.reject('pair', lambda r: r.update(qemu_shutdown_accepted=True))
        self.reject('pair', lambda r: r.update(trace_cleanup_complete=False))

    def test_probe_refuses_other_kernels_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist.json'
            result = subprocess.run([sys.executable, str(HERE / 'probe-kernel-close.py'),
                                     '--require-kernel', 'kernel-must-not-match', '--mode', 'pair',
                                     '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
