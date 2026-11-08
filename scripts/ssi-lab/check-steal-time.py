#!/usr/bin/env python3
"""从原始交互重算 steal-time 页面交接与关闭结果，不采信探针的通过标记。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pvclock', HERE / 'probe-pvclock.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
spec = importlib.util.spec_from_file_location('qemu_close', HERE / 'check-qemu-close.py')
close = importlib.util.module_from_spec(spec)
spec.loader.exec_module(close)


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(log, nodes):
    demand(nodes in (1, 2), '需要一个对照节点或两个实验节点')
    rows = []
    for line in log.splitlines():
        prefix = next((value for value in ('PVCLOCK_CHECK ', 'PVCLOCK_RESULT ') if line.startswith(value)), '')
        row = json.loads(line[len(prefix):])
        demand(isinstance(row, dict), '交互记录必须是对象')
        if not prefix:
            demand(type(row.get('node')) is int and row['node'] in range(nodes), '节点身份不合法')
        rows.append((prefix, row))
    position = 0

    def take(node, operation):
        nonlocal position
        demand(position < len(rows), '交互记录提前结束')
        prefix, row = rows[position]
        position += 1
        demand(prefix == '' and row.get('node') == node and row.get('op') == operation, '交互节点或操作顺序错误')
        if operation == 'claim':
            demand(row == {'node': node, 'op': 'claim'}, '页面交接记录不完整')
        if operation not in ('tick', 'read'):
            return row
        demand(set(row) == {'node', 'op', 'marker', 'records'} and
               isinstance(row['records'], list) and len(row['records']) == 2, '页面快照不完整')
        demand(type(row['marker']) is int and row['marker'] in (1, 2), '页面标记不合法')
        for record in row['records']:
            demand(isinstance(record, dict) and set(record) ==
                   {'version', 'steal', 'flags', 'preempted', 'padding'}, 'steal-time 字段不完整')
            for key, bits in (('version', 32), ('steal', 64), ('flags', 32), ('preempted', 8)):
                demand(type(record[key]) is int and 0 <= record[key] < 1 << bits, 'steal-time 字段越界')
            demand(record['flags'] == 0 and record['padding'] == '00' * 47, '保留字段被破坏')
        return row

    for node in range(nodes):
        demand(take(node, 'ready') == {'node': node, 'op': 'ready', 'nodes': nodes}, '启动节点数不符')
    for cpu in range(2):
        writer = cpu % nodes
        take(writer, 'claim')
        first = take(writer, 'tick')
        demand(first['marker'] == writer + 1 and first['records'][cpu]['version'] > 0, '初始记录没有更新')
    exchanges = []
    for round_number in range(4):
        for cpu in range(2):
            writer, reader = cpu % nodes, (1 - cpu) % nodes
            take(writer, 'claim')
            before = take(writer, 'tick')
            take(reader, 'claim')
            previous = take(reader, 'read')
            latest = take(writer, 'tick')
            observed = take(reader, 'read')
            demand(before['marker'] == writer + 1 and previous['marker'] == observed['marker'] == reader + 1,
                   '页面交接没有保存双方标记')
            result = {'round': round_number, 'cpu': cpu,
                      **probe.check_exchange(before, previous, latest, observed, cpu, reader, 'steal')}
            demand(position < len(rows) and rows[position] == ('PVCLOCK_CHECK ', result), '报告与原始字段重算不符')
            position += 1
            exchanges.append({'round': round_number, 'cpu': cpu, 'writer': writer, 'reader': reader,
                              'before': before, 'previous': previous, 'latest': latest, 'observed': observed,
                              'result': result})
    sealed = []
    for _ in range(nodes):
        demand(position < len(rows) and rows[position][0] == '', '缺少关闭屏障结果')
        row = rows[position][1]
        demand(set(row) == {'node', 'op', 'generation'} and row['op'] == 'sealed', '原生关闭未完成')
        sealed.append(row)
        position += 1
    demand(all(type(row['generation']) is int for row in sealed) and
           {row['node'] for row in sealed} == set(range(nodes)) and
           len({row['generation'] for row in sealed}) == 1 and
           type(sealed[0]['generation']) is int and 0 < sealed[0]['generation'] < 1 << 64, '关闭节点或代际不符')
    for node in reversed(range(nodes)):
        demand(take(node, 'closed') == {'node': node, 'op': 'closed'}, 'VM fd 没有关闭')
    failures = sum(not row['result']['pass'] for row in exchanges)
    demand(rows[position:] == [('PVCLOCK_RESULT ', {'checks': 8, 'failures': failures, 'errors': []})],
           '最终统计不符、存在错误或额外数据')
    return {'exchanges': exchanges, 'checks': 8, 'failures': failures,
            'generation': sealed[0]['generation'], 'page_updates_verified': failures == 0,
            'preemption_hint_verified': False, 'full_ssi_accepted': False}


def inspect_host(log, node, generation, nodes):
    demand(not re.search(r'WARNING:|BUG:|Oops:|Kernel panic|hung task|kvm-dsm:.*failed|'
                         r'exited server loop, error', log), '宿主包含错误')
    states = re.findall(r'DSM_CLOSE_RESULT node=(\d+) generation=(\d+) accepted=(\d+) closed=(\d+) eof=(\d+) result=(-?\d+)', log)
    expected = (node, generation, 2, 1, 2, 0) if nodes == 2 else (node, generation, 0, 0, 0, 0)
    demand([tuple(map(int, state)) for state in states] == [expected], '内核关闭连接集合不符')


def inspect_workspace_close(data, runtime):
    """复核 PF29 工作区的日志屏障与连接计数，不冒充未采集的原生函数跟踪。"""
    result = data['result']
    demand(result['qemu_sha256'] == runtime and result['qemu_ssh_exits'] == [0, 0], 'QEMU 身份或退出状态错误')
    demand(not any(result.get(name) for name in
                   ('harness_error', 'management_timeout', 'host_log_timeout', 'samples_errors')),
           '工作区采集不完整')
    logs, hosts = data['qemu_stderr'], data['host_logs']
    demand(len(logs) == len(hosts) == 2, '缺少双端记录')
    generation = close.inspect_barrier(logs, 'QUIESCE')
    close.inspect_barrier(logs, 'DRAIN')
    for node, (log, host) in enumerate(zip(logs, hosts)):
        demand(f'SSI_ROUTER_READY node={node} peers=1 version=6' in log, '没有协议六准入')
        demand(not re.search(r'SSI close failed|shutdown/flush failed|failed \(-|unpin failed|pin failed|'
                             r'SSI (?:invalid|duplicate|missing|router |local quiescence|drain |shutdown )|'
                             r'segfault|segmentation fault|dumped core|HARNESS_TIMEOUT|terminating on signal',
                             log, re.I), 'QEMU 清理失败')
        events = [line for line in log.splitlines() if line.startswith(('SSI_QUIESCE_COMPLETE',
                  'SSI_DEVICE_UNREALIZED', 'SSI_DRAIN_COMPLETE', 'SSI_CLOSE_PINS',
                  'SSI_KERNEL_CLOSE_', 'SSI_DEVICE_CLOSE_COMPLETE'))]
        demand(events == [f'SSI_QUIESCE_COMPLETE node={node} peers=1',
                          'SSI_DEVICE_UNREALIZED type=virtio-net-device',
                          f'SSI_DRAIN_COMPLETE node={node} peers=1',
                          'SSI_CLOSE_PINS ret=0 version=1 active=0 read=0 write=0 error=0 reserved=0',
                          f'SSI_KERNEL_CLOSE_BEGIN generation={generation} timeout_ms=15000',
                          f'SSI_KERNEL_CLOSE_RESULT generation={generation} ret=0',
                          'SSI_DEVICE_CLOSE_COMPLETE'], '设备与原生关闭顺序不完整')
        inspect_host(host, node, generation, 2)
    return {'generation': generation, 'close_logs_verified': True,
            'native_function_trace_verified': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--nodes', type=int, choices=[1, 2], required=True)
    args = parser.parse_args()
    result = inspect(args.log.read_text(), args.nodes)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['page_updates_verified'] else 1)
