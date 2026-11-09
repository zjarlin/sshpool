"""核对真实返回包丢弃与修正，拒绝空抓包、错误规则和不完整恢复。"""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[1] / 'docs/evidence'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('check-tcp-reply')
atomic = load('check-atomic-grant')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class TcpReplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((EVIDENCE / 'ssi-tcp-reply-20261109.json').read_text())
        cls.runs = {row['label']: row for row in cls.evidence['runs']}

    def capture(self, artifact):
        raw = (EVIDENCE / artifact['file']).read_bytes()
        self.assertEqual(len(raw), artifact['bytes'])
        self.assertEqual(sha(raw), artifact['sha256'])
        unpacked = gzip.decompress(raw)
        self.assertEqual(sha(unpacked), artifact['raw_sha256'])
        return json.loads(unpacked)

    def reject(self, label, change, message):
        data = self.capture(self.runs[label]['archive'])
        change(data)
        with self.assertRaisesRegex(ValueError, message):
            checker.inspect(data)

    def test_both_directions_and_both_protected_ranges_replay(self):
        self.assertEqual(len(self.runs), 14)
        expected = set()
        for n in (0, 1):
            expected.update(f'legacy-n{n}-{port}' for port in (37742, 40042))
            expected.update(f'fixed-n{n}-{port}-b' for port in (37742, 40042))
            expected.update((f'legacy-n{n}-36042-b', f'fixed-n{n}-foreign-local', f'fixed-n{n}-unselected-port'))
        self.assertEqual(set(self.runs), expected)
        for run in self.runs.values():
            with self.subTest(run=run['label']):
                self.assertEqual(checker.inspect(self.capture(run['archive'])), run['analysis'])
                self.assertFalse(run['analysis']['full_ssi_accepted'])
                self.assertFalse(run['analysis']['historical_atomic_failure_cause_proven'])

    def test_fast_success_with_empty_capture_is_not_accepted(self):
        rejected = self.evidence['rejected_captures']
        self.assertEqual(len(rejected), 6)
        for record in rejected:
            self.assertFalse(record['accepted'])
            data = self.capture(record['archive'])
            self.assertTrue(all(event['record']['success'] for event in data['events'] if event['record']['op'] == 'result'))
            with self.assertRaisesRegex(ValueError, '抓包为空'):
                checker.inspect(data)

    def test_raw_packet_truncation_and_capture_loss_are_rejected(self):
        def truncate(data):
            capture = data['captures']['0']
            raw = base64.b64decode(capture['pcap_base64'])
            capture['pcap_base64'] = base64.b64encode(raw[:-1]).decode()
        self.reject('fixed-n0-37742-b', truncate, '截断')
        def loss(data):
            capture = data['captures']['0']
            capture['tcpdump_stderr'] = capture['tcpdump_stderr'].replace('0 packets dropped', '1 packets dropped')
        self.reject('fixed-n0-37742-b', loss, '抓包丢失')

    def test_an_unrelated_synack_cannot_prove_a_handshake(self):
        def change(data):
            capture = data['captures']['0']
            raw = bytearray(base64.b64decode(capture['pcap_base64']))
            offset = 24
            while offset < len(raw):
                size = struct.unpack_from('<I', raw, offset + 8)[0]
                ip = offset + 16 + 20
                tcp = ip + (raw[ip] & 15) * 4
                if raw[tcp + 13] == 18:
                    struct.pack_into('!I', raw, tcp + 8, 0)
                    break
                offset += 16 + size
            capture['pcap_base64'] = base64.b64encode(raw).decode()
        self.reject('fixed-n0-37742-b', change, '关联 SYN-ACK')

    def test_rule_verdict_and_peer_scope_are_required(self):
        def verdict(data):
            capture = data['captures']['1']
            capture['nft_trace'] = capture['nft_trace'].replace('(verdict drop)', '(verdict accept)')
        self.reject('legacy-n0-37742', verdict, '规则判定')
        def peer(data):
            capture = data['captures']['1']
            capture['nft_trace'] = capture['nft_trace'].replace('rule ip saddr 192.168.31.131 tcp sport', 'rule tcp sport')
        self.reject('fixed-n0-37742-b', peer, '限定返回规则')

    def test_success_flags_do_not_replace_echo_or_cleanup(self):
        def payload(data):
            next(event['record'] for event in data['events'] if event['record']['op'] == 'result')['payload_sha256'] = '0' * 64
        self.reject('fixed-n0-37742-b', payload, '回显数据')
        self.reject('fixed-n0-37742-b', lambda data: data.update(firewall_after=[]), '宿主未恢复')
        self.reject('fixed-n0-37742-b', lambda data: data['worker_exits'][0].update(exit=1), '正常结束')

    def test_rule_generator_rejects_unbounded_or_injected_inputs(self):
        for peer in ('0.0.0.0', '127.0.0.1', '224.0.0.1', '192.0.2.1/24', '192.0.2.1; flush ruleset', '::1'):
            with self.assertRaises(ValueError):
                checker.firewall.rules(peer, 'sshpool-test')
        for label in ('"; flush ruleset', 'sshpool-test\naccept', 'other', 'sshpool-' + 'a' * 49):
            with self.assertRaises(ValueError):
                checker.firewall.rules('192.0.2.1', label)
        result = subprocess.run([sys.executable, str(HERE / 'lab-firewall.py'), '192.0.2.1/24', 'sshpool-test'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_archived_sources_bind_actual_collectors_and_probe(self):
        source = self.evidence['sources']
        raw = (EVIDENCE / source['file']).read_bytes()
        self.assertEqual(sha(raw), source['sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
        self.assertEqual({name: sha(data) for name, data in files.items()}, source['members'])
        for name in ('lab-firewall.py', 'probe-tcp-reply.py', 'check-tcp-reply.py'):
            self.assertEqual(files[name], (HERE / name).read_bytes())
        self.assertEqual(sha(files['probe-write-grant.c']), self.evidence['native']['probe_build']['source_sha256'])
        for record in self.evidence['runs'] + self.evidence['rejected_captures']:
            data = self.capture(record['archive'])
            self.assertEqual(data['source_hashes']['probe-tcp-reply.py'], sha(files['probe-tcp-reply.py']))
            self.assertEqual(data['source_hashes']['tcp-reply-collector.py'], sha(files[record['collector']]))
        for node in self.evidence['restoration']['nodes']:
            self.assertEqual(node['boot_hash_manifest_sha256'], sha(files[f"node{node['node']}-before-boot.sha256"]))

    def test_native_dsm_uses_protected_source_ports_and_restores_hosts(self):
        native = self.evidence['native']
        data = self.capture(native['archive'])
        self.assertEqual(atomic.inspect(data), native['analysis'])
        self.assertEqual(data['binary_sha256'], native['probe_build']['binary_sha256'])
        self.assertEqual(native['analysis']['total_operations'], 8192)
        ports = native['port_range_control']
        self.assertEqual(ports['before'], ports['after'])
        self.assertEqual([row.split() for row in ports['active']], [['37742', '37773']] * 2)
        self.assertEqual(ports['runner_exit'], 0)
        for n in (0, 1):
            lines = data['connections_after_batch'][str(n)].splitlines()
            outgoing = [line.split()[3:5] for line in lines if line.split()[4].endswith(':' + str(37710 + 1-n))]
            self.assertEqual(len(outgoing), 1)
            source = int(outgoing[0][0].rsplit(':', 1)[1])
            self.assertTrue(37742 <= source <= 37773)
        nodes = self.evidence['restoration']['nodes']
        self.assertEqual(len(nodes), 2)
        for node in nodes:
            self.assertEqual(node['kernel'], '6.8.0-147-generic')
            self.assertEqual(node['ephemeral_range'], [32768, 60999])
            self.assertEqual(node['reserved_ports'], '')
            self.assertTrue(node['tcp_collectors_absent'])
            for key in ('old_boot_files_unchanged', 'grub_config_unchanged', 'firewall_matches_original', 'pf30_grub_entry_removed'):
                self.assertTrue(node[key])
            for key in ('remaining_processes', 'remaining_trace_instances', 'remaining_experiment_tcp'):
                self.assertEqual(node[key], [])


if __name__ == '__main__':
    unittest.main()
