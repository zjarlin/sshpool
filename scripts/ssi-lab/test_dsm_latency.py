"""以真实单节点/双节点记录回归，并拒绝损坏的时间、整页内容和调用配对。"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import unittest

directory = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('latency', directory / 'check-dsm-latency.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
evidence = json.loads((directory.parents[1] / 'docs/evidence/ssi-latency-20261106.json').read_text())


def candidate():
    return copy.deepcopy(evidence['probes'][1])


def change_record(log, predicate, mutate):
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith('{'):
            continue
        record = json.loads(line)
        if predicate(record):
            mutate(record)
            lines[i] = json.dumps(record)
            return '\n'.join(lines) + '\n'
    raise AssertionError('未找到要破坏的记录')


class DsmLatencyTests(unittest.TestCase):
    def test_real_control_and_pair(self):
        for run in evidence['probes']:
            summary = checker.validate_probe(run['log'], run['traces'])
            self.assertEqual(summary, run['summary'])
            self.assertEqual(summary['serial_operations'], 160)
            self.assertEqual(summary['burst_writes'], 512 * summary['nodes'])

    def test_burst_duration_and_ioctl_failure_are_checked(self):
        run = candidate()
        for field, value in (('elapsed_ns', 0), ('ioctl_result', -1), ('tid', 0)):
            log = change_record(run['log'], lambda r: r.get('thread') == 0,
                                lambda r: r.update({field: value}))
            with self.assertRaises(ValueError):
                checker.validate_log(log)

    def test_burst_checksum_and_thread_order_are_checked(self):
        run = candidate()
        for field, value in (('checksum', '0' * 16), ('seed', 1000007), ('thread', 2)):
            log = change_record(run['log'], lambda r: r.get('thread') == 0,
                                lambda r: r.update({field: value}))
            with self.assertRaises(ValueError):
                checker.validate_log(log)

    def test_final_page_cannot_be_a_partial_or_stale_write(self):
        run = candidate()
        log = change_record(run['log'], lambda r: r.get('op') == 'read' and r.get('seed') == 0,
                            lambda r: r.update(observed_seed=1000001,
                                               checksum=checker.probe.page_checksum(1000001)))
        with self.assertRaisesRegex(ValueError, '最终页面'):
            checker.validate_log(log)

    def test_duplicate_or_missing_close_does_not_pass(self):
        run = candidate()
        log = change_record(run['log'], lambda r: r['op'] == 'closed' and r['node'] == 1,
                            lambda r: r.update(node=0))
        with self.assertRaises(ValueError):
            checker.validate_log(log)

    def test_missing_trace_and_wrong_tid_are_rejected(self):
        run = candidate()
        with self.assertRaisesRegex(ValueError, '节点跟踪'):
            checker.validate_probe(run['log'], run['traces'][:1])
        log = change_record(run['log'], lambda r: r.get('thread') == 0,
                            lambda r: r.update(tid=999999))
        with self.assertRaises(ValueError):
            checker.validate_probe(log, run['traces'])

    def test_missed_probe_and_overrun_are_rejected(self):
        run = candidate()
        trace = run['traces'][0]
        trace['kprobe_profile'] = re.sub(r'(lat_ioctl\s+\d+\s+)0', r'\g<1>1', trace['kprobe_profile'])
        with self.assertRaisesRegex(ValueError, '遗漏'):
            checker.inspect_trace(trace)
        trace = candidate()['traces'][0]
        cpu = next(iter(trace['trace_stats']))
        trace['trace_stats'][cpu] = trace['trace_stats'][cpu].replace('overrun: 0', 'overrun: 1', 1)
        with self.assertRaisesRegex(ValueError, '丢失'):
            checker.inspect_trace(trace)

    def test_trace_duration_cannot_exceed_userspace_ioctl(self):
        run = candidate()
        log = change_record(run['log'], lambda r: r.get('thread') == 0,
                            lambda r: r.update(end_ns=r['begin_ns'] + 1, elapsed_ns=1))
        with self.assertRaisesRegex(ValueError, '内核耗时'):
            checker.validate_probe(log, run['traces'])

    def test_listener_idle_is_separate_from_response_latency(self):
        run = candidate()
        _, summary = checker.inspect_trace(run['traces'][0])
        groups = summary['functions']
        self.assertGreater(groups['lat_receive:listener']['max_ns'], 500000000)
        self.assertLess(groups['lat_receive:response']['max_ns'], 10000000)

    def test_window_boundaries_do_not_hide_internal_missing_calls(self):
        pairs = checker.PAIRS
        trace = {'errors': [], 'exit': 0, 'trace_cleanup_complete': True, 'qemu_pid': 10,
                 'capture_started_ns': 1, 'capture_stopped_ns': 4000000000,
                 'trace_stats': {'cpu0': 'overrun: 0\ncommit overrun: 0\ndropped events: 0\n'}}
        names = set(pairs) | set(pairs.values()) | {'lat_unlock'}
        trace['kprobe_profile'] = '\n'.join(f'{name} 10 0' for name in sorted(names))
        trace['trace'] = ('# entries-in-buffer/entries-written: 2/2\n'
                          ' CPU 0/KVM-10 [000] ..... 1.000000: lat_received: (return) code=0\n'
                          ' CPU 0/KVM-10 [000] ..... 2.000000: lat_receive: (enter) txid=42 capacity=4096\n')
        _, result = checker.inspect_trace(trace)
        self.assertEqual(result['boundary_censored_calls'], 2)
        trace['trace'] = trace['trace'].replace('lat_receive: (enter) txid=42 capacity=4096',
                                               'lat_received: (return) code=0')
        with self.assertRaisesRegex(ValueError, '窗口内部'):
            checker.inspect_trace(trace)

    def test_tcp_ack_excerpt_covers_request_before_response(self):
        packets = evidence['packets']
        request, _, ack, response, _ = packets['transaction_49270_packets']
        self.assertEqual(request['size'], 4110)
        self.assertEqual(ack['ack'], (request['seq'] + request['size']) % (1 << 32))
        self.assertEqual(ack['size'], 0)
        self.assertEqual(ack['us'] - request['us'], packets['request_to_full_ack_us'])
        self.assertEqual(response['us'] - ack['us'], packets['full_ack_to_response_us'])
        self.assertLess(packets['request_to_full_ack_us'], 10000)
        self.assertGreater(packets['full_ack_to_response_us'], 2000000)
        data = bytes.fromhex(request['data_prefix'])
        self.assertEqual(struct.unpack_from('<QHHH', data), (38, 0, 0, 49270))
        self.assertEqual(struct.unpack_from('<Q', data, 22)[0], 0x401b)
        self.assertEqual(struct.unpack_from('<QHHH', bytes.fromhex(response['data_prefix']))[3], 49270)

    def test_guest_instructions_match_symbol_excerpt(self):
        attribution = evidence['page_attribution']
        symbols = [line.split() for line in attribution['symbol_excerpt']]
        for sample in attribution['samples']:
            fault = sample['fault']
            for value, mapped in ((fault['rip'], sample['rip_symbol']),
                                  (fault['address'] + int(attribution['kernel_virtual_base'], 0), sample['data_symbol'])):
                start = int(mapped['start'], 0)
                self.assertEqual(value, start + int(mapped['offset'], 0))
                self.assertTrue(any(int(address, 16) == start and name == mapped['name']
                                    for address, _, name in symbols))
                self.assertLess(value, min(int(address, 16) for address, _, _ in symbols if int(address, 16) > start))
            self.assertIn(hex(fault['rip']), fault['raw'])
            self.assertIn(f"address 0x{fault['address']:016x}", fault['raw'])
            self.assertEqual(fault['address'] // 4096, int(sample['gfn'], 0))

    def test_clock_samples_pass_but_full_workspace_stays_failed(self):
        clock, stress, boot = [checker.load(name) for name in ('check-clock', 'check-stress', 'check-ssh-boot')]
        for run in evidence['workspaces']:
            trials = ['CLOCK_START' + part for part in run['clock_log'].split('CLOCK_START')[1:]]
            self.assertEqual(len(trials), 3)
            for trial in trials:
                clock.validate(trial, max_timer_ns=250000000)
            stress.validate(run['stress_log'])
            with self.assertRaises(ValueError):
                boot.validate(run['nodes'][0]['serial_log'])
            self.assertFalse(run['full_workspace_passed'])
            self.assertTrue(run['result']['sftp_matches'])
            self.assertEqual(run['result']['qemu_ssh_exits'], [0, 0])

    def test_provenance_and_lab_restoration(self):
        root = directory.parents[1]
        for path, digest in evidence['source_sha256'].items():
            self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        for run in evidence['probes']:
            for node in run['runtime_hashes']:
                self.assertEqual(node['files']['trace-dsm-latency.py'],
                                 evidence['source_sha256']['scripts/ssi-lab/trace-dsm-latency.py'])
        self.assertEqual(len(evidence['restoration']['nodes']), 2)
        for node in evidence['restoration']['nodes']:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertTrue(node['identity_matches'] and node['firewall_matches_original'])
            self.assertEqual(node['lib_target'], 'usr/lib')
            self.assertEqual(node['remaining_processes'], [])
            for key in ('trace_events', 'trace_instances', 'grub_environment'):
                self.assertEqual(node[key], '')


if __name__ == '__main__':
    unittest.main()
