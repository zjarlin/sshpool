#!/usr/bin/env python3
"""按宿主调用标记重放单条写指令的缺页，核对结果、读者进展与原生关闭。"""
import argparse
from collections import Counter
import gzip
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('guest', Path(__file__).with_name('check-guest-timers.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
demand = guest.demand
KERNELS = {'7.1.0-rc3-sshpool-gvm-pf29', '7.1.0-rc3-sshpool-gvm-pf30'}
FAULT = re.compile(r'vcpu (\d+) rip (0x[0-9a-f]+) address (0x[0-9a-f]+) error_code (0x[0-9a-f]+)')


def parse_trace(capture, pid):
    """只接受目标进程的完整全局时间域记录，逐 CPU 核对零丢失。"""
    before, after = capture['before'], capture['after']
    demand(before['pid'] == pid and before['comm'] == 'probe-grant' and before['kernel'] in KERNELS,
           '采集身份不符')
    for stat in (before['stat'], after['stat']):
        demand(stat.split(' ', 1)[0] == str(pid), 'stat PID 不符')
    demand(before['stat'].rsplit(')', 1)[1].split()[19] == after['stat'].rsplit(')', 1)[1].split()[19],
           'PID 被复用')
    demand(after['cleanup_complete'] and '[global]' in before['trace_clock'].split(), '清理或全局时钟不符')
    demand(before['filter'].strip() == f'common_pid == {pid}' and
           before['format'].startswith('name: kvm_page_fault\n'), '事件过滤器或格式不符')
    rows = []
    for line in after['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = guest.native.drain.safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '事件格式不符')
        comm, tid, cpu, stamp, name, detail = match.groups()
        sec, part = stamp.split('.')
        demand(int(tid) == pid and comm.strip() == 'probe-grant', '事件进程身份不符')
        demand(name in ('kvm_page_fault', 'tracing_mark_write'), '未声明事件')
        rows.append({'index': len(rows), 'cpu': int(cpu), 'ns': int(sec) * 1_000_000_000 + int(part.ljust(9, '0')),
                     'name': name, 'detail': detail})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', after['trace']) ==
           [(str(len(rows)), str(len(rows)))], '总事件计数不符')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(rows, rows[1:])), '事件时间倒退')
    demand(set(after['stats']) == {'cpu0', 'cpu1'}, 'CPU 统计缺失')
    counts = Counter(row['cpu'] for row in rows)
    demand(set(counts) <= {0, 1}, '未知 CPU')
    for cpu, stats in after['stats'].items():
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(counts[int(cpu[3:])])], '逐 CPU 计数不符')
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall('^' + key + r': (\d+)$', stats, re.M) == ['0'], '跟踪丢失')
    return rows


def invocations(rows, node):
    """仅在同一对 begin/end 之间累计缺页，不把相邻调用拼成一次停顿。"""
    calls, active = [], None
    for row in rows:
        if row['name'] == 'tracing_mark_write':
            match = re.fullmatch(r'grant_(begin|end) value=(\d+)', row['detail'])
            demand(match is not None, '未知调用标记')
            value = int(match[2])
            if match[1] == 'begin':
                demand(active is None, '调用重叠')
                active = {'value': value, 'begin': row, 'faults': []}
            else:
                demand(active is not None and active['value'] == value, '调用结束不匹配')
                active.update(end=row, span_ns=row['ns'] - active['begin']['ns'])
                calls.append(active)
                active = None
            continue
        demand(active is not None, '调用外缺页')
        match = FAULT.fullmatch(row['detail'])
        demand(match is not None, '缺页字段不符')
        vcpu = int(match[1])
        rip, address, error = (int(match[i], 16) for i in (2, 3, 4))
        demand(vcpu == node and rip in (0x1000, 0x1004) and address in (0x1000, 0x2000), '缺页超出固定客体')
        if address == 0x2000:
            demand(rip == 0x1000 and error & 2, '不是唯一写指令')
            active['faults'].append(row)
    demand(active is None, '调用缺少结束')
    return calls


def inspect(data):
    """核对两节点真实记录；成功只表示这个有限实验通过。"""
    demand(data['mode'] in ('control', 'pair'), '未知模式')
    demand(not data['errors'], '实验采集失败')
    demand(data['firewall_before'] == data['firewall_after'], '防火墙未恢复')
    count = 2 if data['mode'] == 'pair' else 1
    demand(set(data['traces']) == {str(n) for n in range(count)}, '跟踪节点缺失')
    demand({row['node'] for row in data['events']} == set(range(count)), '记录节点不符')
    validate_order(data['events'], count)
    kernels = {capture['before']['kernel'] for capture in data['traces'].values()}
    demand(len(kernels) == 1 and kernels <= KERNELS, '两端内核不符')
    if kernels == {'7.1.0-rc3-sshpool-gvm-pf30'}:
        demand(data['grace_before'] == data['grace_after'] == [0, 0], '参数未恢复')
        demand(data['grace_active'] in ([0, 0], [100, 100], [500, 500], [1000, 1000]), '参数不一致或越界')
    result, generations = {}, []
    for node in range(count):
        log = [row['record'] for row in data['events'] if row['node'] == node]
        ready = log[0]
        demand(ready['op'] == 'ready' and ready['node'] == node and ready['nodes'] == count and
               ready['rip'] == 0x1000 and ready['address'] == 0x2000, '探针身份不符')
        demand(log[-3]['op'] == 'trace_closed' and log[-2]['op'] == 'sealed' and log[-1] == {'op': 'closed'},
               '未先清理跟踪并原生关闭')
        seals = [row['generation'] for row in log if row['op'] == 'sealed']
        demand(len(seals) == 1 and seals[0] > 0, '关闭代际不符')
        generations.extend(seals)
        writes = [row for row in log if row['op'] == 'write']
        demand(len(writes) == (320 if count == 2 else 64), '写入数量不符')
        first = 1 if node == 0 else 321
        demand([row['value'] for row in writes] == list(range(first, first + len(writes))), '写入编号不符')
        demand(all(row['observed'] == row['value'] and row['exit_reason'] == 5 and row['rip'] == 0x1005 and
                   row['elapsed_ns'] >= 0 for row in writes), '写指令未完成')
        if count == 2:
            stopped = [row for row in log if row['op'] == 'reader_stopped']
            demand(len(stopped) == 1 and stopped[0]['reads'] > 0 and stopped[0]['regressions'] == 0,
                   '读者未前进或数据倒退')
            demand([row['value'] for row in log if row['op'] == 'read'] == [320, 640], '跨节点最终数据不符')
        calls = invocations(parse_trace(data['traces'][str(node)], ready['pid']), node)
        demand([row['value'] for row in calls] == [row['value'] for row in writes], '调用边界与写入编号不符')
        result[str(node)] = {
            'writes': len(calls), 'store_faults': sum(len(row['faults']) for row in calls),
            'repeated_stores': sum(len(row['faults']) > 1 for row in calls),
            'max_faults_per_store': max(len(row['faults']) for row in calls),
            'max_run_ns': max(row['elapsed_ns'] for row in writes),
            'longest_fault_sequences': sorted(calls, key=lambda row: -len(row['faults']))[:10],
        }
    demand(len(set(generations)) == 1, '双端关闭代际不一致')
    return result


def validate_order(events, count):
    """远端读者确认启动之后才允许竞争写入，双方解除跟踪后才允许关闭。"""
    expected = []
    for node in range(count):
        expected.extend([(node, 'ready'), (node, 'trace_ready')])
    for node in range(count):
        expected.extend([(node, 'write')] * 64 + [(node, 'writes_done')])
        if count == 1:
            continue
        expected.append((1 - node, 'reader_started'))
        expected.extend([(node, 'write')] * 256 + [(node, 'writes_done'), (1 - node, 'reader_stopped')])
        expected.extend([(peer, 'read') for peer in range(count)])
    expected.extend([(node, 'trace_closed') for node in range(count)])
    actual = [(row['node'], row['record']['op']) for row in events]
    demand(actual[:len(expected)] == expected, '竞争阶段或操作次序不符')
    tail = actual[len(expected):]
    demand(len(tail) == 2 * count and set(tail[:count]) == {(node, 'sealed') for node in range(count)} and
           tail[count:] == [(node, 'closed') for node in reversed(range(count))], '关闭操作次序不符')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    try:
        raw = args.capture.read_bytes()
        if args.capture.suffix == '.gz':
            raw = gzip.decompress(raw)
        print(json.dumps(inspect(json.loads(raw)), indent=2))
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
