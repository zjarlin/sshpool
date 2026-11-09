#!/usr/bin/env python3
"""重放 TCP 抓包、nft 命中规则和回显，区分返回包丢弃与监听失败。"""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('firewall', HERE / 'lab-firewall.py')
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)
PAYLOAD = b'sshpool isolated TCP reply probe\n' * 4
PORTS = [37710, 37711, 40000, 40001]


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def packets(encoded):
    """直接解析原始 PCAP 的 Linux cooked v2、IPv4 和 TCP 头，不信任文本摘要。"""
    raw = base64.b64decode(encoded, validate=True)
    demand(len(raw) >= 24 and raw[:4] == b'\xd4\xc3\xb2\xa1', 'PCAP 头不符')
    major, minor, _, _, snaplen, link = struct.unpack_from('<HHIIII', raw, 4)
    demand((major, minor, link) == (2, 4, 276) and snaplen >= 65535, 'PCAP 版本或链路类型不符')
    offset, result = 24, []
    while offset < len(raw):
        demand(offset + 16 <= len(raw), 'PCAP 记录头截断')
        sec, usec, captured, original = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        demand(captured == original and captured >= 60 and offset + captured <= len(raw), 'PCAP 包截断')
        frame = raw[offset:offset + captured]
        offset += captured
        demand(struct.unpack_from('!H', frame)[0] == 0x0800, '不是 IPv4')
        ip = frame[20:]
        ihl = (ip[0] & 15) * 4
        length = struct.unpack_from('!H', ip, 2)[0]
        demand(ip[0] >> 4 == 4 and ihl >= 20 and length <= len(ip) and length >= ihl + 20 and
               ip[9] == 6 and struct.unpack_from('!H', ip, 6)[0] & 0x3fff == 0, 'IP 长度分片或协议不符')
        tcp = ip[ihl:length]
        header = (tcp[12] >> 4) * 4
        demand(20 <= header <= len(tcp), 'TCP 头截断')
        sport, dport, seq, ack = struct.unpack_from('!HHII', tcp)
        result.append({'src': str(ipaddress.IPv4Address(ip[12:16])), 'dst': str(ipaddress.IPv4Address(ip[16:20])),
                       'sport': sport, 'dport': dport, 'seq': seq, 'ack': ack, 'flags': tcp[13],
                       'payload': tcp[header:], 'time_us': sec * 1_000_000 + usec})
    # 多 CPU 抓包队列不保证时间戳按文件顺序递增；此处只核对包与序号，不计算延迟。
    demand(result, '抓包为空')
    return result


def verdicts(text):
    """按 nft trace id 关联入站四元组与最后判定，不能拼接不同包的规则。"""
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'trace id ([0-9a-f]+) inet sshpool_ssi_lab input (.*)', line)
        demand(match is not None, '未声明的 nft 跟踪记录')
        key, detail = match.groups()
        detail = detail.rstrip()
        if detail.startswith('packet:'):
            demand(key not in result, 'nft trace id 重复')
            fields = re.search(r'ip saddr ([\d.]+) ip daddr ([\d.]+).*tcp sport (\d+) tcp dport (\d+)', detail)
            demand(fields is not None, 'nft 包缺少四元组')
            result[key] = {'tuple': (fields[1], fields[2], int(fields[3]), int(fields[4])), 'rules': []}
        else:
            demand(key in result, 'nft 规则没有对应包')
            verdict = re.search(r'\(verdict (continue|accept|drop)\)$', detail)
            if detail == 'policy accept':
                value = 'accept'
            else:
                demand(verdict is not None, 'nft 判定缺失')
                value = verdict[1]
            result[key]['rules'].append((detail, value))
    demand(result and all(row['rules'] and row['rules'][-1][1] in ('accept', 'drop') for row in result.values()),
           'nft 跟踪缺少终态')
    return list(result.values())


def endpoint(packet):
    return packet['src'], packet['dst'], packet['sport'], packet['dport']


def inspect(data):
    """核对有限双节点网络实验；不推导历史缺失四元组或完整 SSI 已通过。"""
    demand(data['mode'] in ('legacy', 'fixed') and not data['errors'], '采集模式或错误不符')
    demand(data['firewall_before'] == data['firewall_after'] and data['cleanup'] == data['nodes'], '宿主未恢复')
    server, client = data['server'], data['client']
    demand(server in (0, 1) and client in (0, 1) and len(data['nodes']) == 2, '节点不符')
    addresses = [node['address'] for node in data['nodes']]
    demand(len(set(addresses)) == 2, '不是两个节点')
    cp, sp = data['source_port'], data['dest_port']
    demand(cp in (36042, 36043, 36044, 37742, 40042) and sp in (37710, 37711, 37743), '实验端口不符')
    forward = addresses[client], addresses[server], cp, sp
    reverse = addresses[server], addresses[client], sp, cp
    negative = client == server or sp not in PORTS
    success = not negative and (data['mode'] == 'fixed' or cp == 36042)
    for n in (0, 1):
        node = data['nodes'][n]
        demand(node['kernel'] == '6.8.0-147-generic' and node['reserved_ports'].strip() == '', '宿主配置不符')
        low, high = map(int, node['ephemeral_range'].split())
        demand(low <= 37742 <= high and low <= 40042 <= high, '未证明保护区间与临时端口重叠')
        expected = firewall.rules(addresses[1-n], 'sshpool-tcp-reply')
        if data['mode'] == 'legacy':
            expected = expected.splitlines(keepends=True)[0]
        demand(data['rules'][str(n)] == expected, '临时规则不符')
    records = [event['record'] for event in data['events'] if event['record']['op'] == 'result']
    demand(len(records) == 2 and [row['mode'] for row in records] == ['client', 'server'], '结果缺失或次序不符')
    demand(data['worker_exits'] == [{'node': client, 'exit': 0, 'stderr': ''},
                                   {'node': server, 'exit': 0, 'stderr': ''}], '探针没有正常结束')
    for row, local, peer in zip(records, [(forward[0], cp), (forward[1], sp)], [(forward[1], sp), (forward[0], cp)]):
        demand(row['local'] == list(local) and row['peer'] == list(peer) and row['success'] is success, '回显结果不符')
        if success:
            demand(row['payload_sha256'] == hashlib.sha256(PAYLOAD).hexdigest(), '实际回显数据不符')
        else:
            demand(row['error'] == 'TimeoutError' and row['tcp_state'] == (2 if row['mode'] == 'client' else 10),
                   '不是握手等待超时')
    demand(set(data['captures']) == {str(n) for n in {server, client}}, '抓包节点缺失')
    analysis, handshakes = {}, []
    for key, capture in data['captures'].items():
        demand(capture['tcpdump_exit'] == 0 and capture['nft_exit'] == -15 and
               not capture['nft_stderr'] and not capture['collector_stderr'], '抓包进程异常')
        rows = packets(capture['pcap_base64'])
        demand(re.findall(r'^(\d+) packets captured$', capture['tcpdump_stderr'], re.M) == [str(len(rows))] and
               re.findall(r'^(\d+) packets dropped by kernel$', capture['tcpdump_stderr'], re.M) == ['0'], '抓包丢失')
        demand(all(endpoint(row) in (forward, reverse) for row in rows), '抓包包含无关连接')
        syn = [row for row in rows if endpoint(row) == forward and row['flags'] == 2]
        synack = [row for row in rows if endpoint(row) == reverse and row['flags'] == 18]
        demand(syn, '缺少实际 SYN')
        if negative:
            demand(not synack, '拒绝边界出现 SYN-ACK')
        else:
            demand(synack and all(any(reply['ack'] == (request['seq'] + 1) % 2**32 for request in syn)
                                 for reply in synack), '缺少关联 SYN-ACK')
            handshakes.append(({row['seq'] for row in syn}, {(row['seq'], row['ack']) for row in synack}))
        traces = verdicts(capture['nft_trace']) if capture['nft_trace'] else []
        relevant = forward if int(key) == server else reverse
        matching = [row for row in traces if row['tuple'] == relevant]
        if negative and int(key) != server:
            demand(not matching, '已被服务端拒绝的连接却出现返回包规则')
            wanted = None
        else:
            demand(matching, '缺少关键方向的 nft 命中')
            wanted = 'drop' if negative or (not success and int(key) == client) else 'accept'
        demand(all(row['rules'][-1][1] == wanted for row in matching), '关键方向的规则判定不符')
        if wanted == 'drop':
            demand(all(row['rules'][-1][0] == 'rule tcp dport { 37710-37773, 40000-40063 } drop (verdict drop)'
                       for row in matching), '没有命中原始保护区间丢弃规则')
        if success and data['mode'] == 'fixed' and int(key) == client:
            reply = firewall.rules(addresses[server], 'sshpool-tcp-reply').splitlines()[1]
            final = reply.replace('insert rule inet sshpool_ssi_lab input ', 'rule ', 1) + ' (verdict accept)'
            demand(all(row['rules'][-1][0] == final for row in matching),
                   '没有命中限定返回规则')
        if success:
            for route in (forward, reverse):
                demand(any(endpoint(row) == route and row['payload'] == PAYLOAD for row in rows), '缺少实际双向数据')
        analysis[key] = {'packets': len(rows), 'syn': len(syn), 'synack': len(synack), 'critical_verdict': wanted,
                         'timestamp_backsteps': sum(a['time_us'] > b['time_us'] for a, b in zip(rows, rows[1:]))}
    demand(not handshakes or all(value == handshakes[0] for value in handshakes), '双端握手序号不对应')
    return {'success': success, 'negative_control': negative, 'captures': analysis,
            'historical_atomic_failure_cause_proven': False, 'full_ssi_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    try:
        raw = args.capture.read_bytes()
        if args.capture.suffix == '.gz':
            raw = gzip.decompress(raw)
        print(json.dumps(inspect(json.loads(raw)), indent=2))
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
