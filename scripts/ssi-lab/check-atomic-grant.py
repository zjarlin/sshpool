#!/usr/bin/env python3
"""重放并发 LOCK XADD：每次返回值唯一、计数连续、哨兵一致且双方正常关闭。"""
import argparse
import gzip
import importlib.util
from itertools import groupby
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('grant', Path(__file__).with_name('check-write-grant.py'))
grant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grant)
demand = grant.demand
GUARD = 0x51a7c0de
KERNEL_SHA = 'bf3b1beec9bf65ec3a330b9773a527d1cff3e0539fa0a9f329bed3f0d8fe698a'


def inspect(data):
    """返回有限样本的原子性、线程进展与缺页统计，不推导任意负载公平性。"""
    demand(data['mode'] in ('control', 'pair'), '未知模式')
    count = 2 if data['mode'] == 'pair' else 1
    amount = data['amount']
    demand(type(amount) is int and 0 < amount <= 4096, '操作数量不符')
    demand(not data['errors'] and data['cleanup_verified'], '采集或清理失败')
    demand(data['firewall_before'] == data['firewall_after'], '防火墙未恢复')
    demand(data['grace_before'] == data['grace_after'] == [0, 0], '参数未恢复')
    demand(data['grace_active'] in ([0, 0], [1000, 1000]), '参数不一致或越界')
    demand(set(data['traces']) == {str(node) for node in range(count)}, '跟踪节点不全')
    demand(data['kernel_hashes'] == {str(node): KERNEL_SHA for node in range(count)}, '实验内核哈希不符')
    demand(re.fullmatch('[0-9a-f]{64}', data['binary_sha256']) is not None, '二进制摘要缺失')
    demand(data['worker_exits'] == [{'node': node, 'exit': 0} for node in reversed(range(count))], '探针退出失败')
    events = data['events']
    demand({event['node'] for event in events} == set(range(count)), '记录节点不符')
    demand(all(a['received_ns'] <= b['received_ns'] for a, b in zip(events, events[1:])), '控制端接收时间倒退')
    nodes, tickets, generations = {}, [], []
    for node in range(count):
        log = [event['record'] for event in events if event['node'] == node]
        expected = ['ready', 'trace_ready', 'read', 'armed', 'batch_started'] + ['atomic'] * amount
        expected += ['writes_done', 'read', 'trace_closed', 'sealed', 'closed']
        demand([row['op'] for row in log] == expected, '操作次序或数量不符')
        ready = log[0]
        demand(ready['node'] == node and ready['nodes'] == count and ready['rip'] == 0x1000 and
               ready['address'] == 0x2000, '探针身份不符')
        capture = data['traces'][str(node)]
        demand(capture['before']['kernel'] == '7.1.0-rc3-sshpool-gvm-pf30', '固定实验内核不符')
        demand([row for row in log if row['op'] == 'read'] == [
            {'op': 'read', 'value': 0, 'guard': GUARD},
            {'op': 'read', 'value': count * amount, 'guard': GUARD},
        ], '计数或相邻哨兵不符')
        for op in ('armed', 'batch_started'):
            demand(next(row for row in log if row['op'] == op) == {'op': op, 'amount': amount, 'base': 0},
                   '批次参数不符')
        operations = [row for row in log if row['op'] == 'atomic']
        demand([row['value'] for row in operations] == list(range(1, amount + 1)), '调用编号不连续')
        demand(all(row['exit_reason'] == 5 and row['rip'] == 0x1008 and type(row['elapsed_ns']) is int and
                   row['elapsed_ns'] >= 0 and type(row['previous']) is int and 0 <= row['previous'] < count * amount
                   for row in operations), '原子指令未完成或返回值越界')
        previous = [row['previous'] for row in operations]
        demand(all(a < b for a, b in zip(previous, previous[1:])), '本节点返回计数倒退或重复')
        tickets += [{'previous': row['previous'], 'node': node, 'value': row['value']} for row in operations]
        calls = grant.invocations(grant.parse_trace(capture, ready['pid']), node, hlt_rip=0x1007)
        demand([row['value'] for row in calls] == list(range(1, amount + 1)), '跟踪调用边界不符')
        generation = log[-2]['generation']
        demand(type(generation) is int and generation > 0, '关闭代际不符')
        generations.append(generation)
        nodes[str(node)] = {
            'operations': amount, 'first_ticket': previous[0], 'last_ticket': previous[-1],
            'max_peer_operations_between_successes': max((b - a - 1 for a, b in zip(previous, previous[1:])), default=0),
            'max_run_ns': max(row['elapsed_ns'] for row in operations),
            'store_faults': sum(len(row['faults']) for row in calls),
            'repeated_operations': sum(len(row['faults']) > 1 for row in calls),
            'max_faults_per_operation': max(len(row['faults']) for row in calls),
            'longest_fault_sequences': sorted(calls, key=lambda row: -len(row['faults']))[:5],
        }
    validate_concurrency(events, count)
    demand(len(set(generations)) == 1, '关闭代际不一致')
    tickets.sort(key=lambda row: row['previous'])
    demand([row['previous'] for row in tickets] == list(range(count * amount)), '跨节点原子计数重复或缺失')
    groups = []
    for node, group in groupby(tickets, key=lambda row: row['node']):
        segment = list(group)
        groups.append({'node': node, 'count': len(segment), 'first_ticket': segment[0]['previous'],
                       'last_ticket': segment[-1]['previous']})
    overlap_start = max(node['first_ticket'] for node in nodes.values())
    overlap_end = min(node['last_ticket'] for node in nodes.values())
    overlap_max = max(max(0, min(group['last_ticket'], overlap_end) -
                         max(group['first_ticket'], overlap_start) + 1) for group in groups)
    return {'nodes': nodes, 'total_operations': len(tickets), 'ticket_owner_switches': len(groups) - 1,
            'max_consecutive_tickets': max(group['count'] for group in groups),
            'overlap_ticket_range': [overlap_start, overlap_end] if overlap_start <= overlap_end else None,
            'max_consecutive_tickets_in_overlap': overlap_max,
            'longest_ticket_runs': sorted(groups, key=lambda group: -group['count'])[:10],
            'all_tickets_unique_and_contiguous': True, 'general_fairness_proven': False,
            'cross_host_clock_alignment_established': False, 'full_ssi_accepted': False}


def validate_concurrency(events, count):
    """两端先确认准备完毕再启动；完成与关闭均不能跨过另一个节点的屏障。"""
    indices = {}
    for op in ('armed', 'batch_started', 'writes_done', 'trace_closed', 'sealed', 'closed'):
        indices[op] = [index for index, event in enumerate(events) if event['record']['op'] == op]
        demand(len(indices[op]) == count, '双端屏障数量不符')
    demand(max(indices['armed']) < min(indices['batch_started']), '另一节点未准备就开始')
    demand(max(indices['batch_started']) < min(indices['writes_done']), '没有并发批次证据')
    demand(max(indices['writes_done']) < min(indices['trace_closed']), '另一节点尚在运行就关闭跟踪')
    demand(max(indices['trace_closed']) < min(indices['sealed']) and
           max(indices['sealed']) < min(indices['closed']), '另一节点未封闭就释放 VM')


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
