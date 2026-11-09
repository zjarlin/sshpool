#!/usr/bin/env python3
"""重放真实写授权等待、锁释放、信号和故障回收；错过窗口的尝试不算通过。"""
import argparse
from collections import Counter
from decimal import Decimal
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('safety', Path(__file__).with_name('check-request-safety.py'))
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)
demand = safety.demand
field = safety.field
PROBES = {'gc_sleep', 'gc_wake', 'gc_lock', 'gc_locked', 'gc_unlock', 'gc_srcu', 'gc_srcu_done',
          'gc_failure', 'gc_send', 'gc_sent', 'gc_handler_done', 'gc_root_done', 'gc_free', 'gc_freed'}
FILTERED = {'gc_sleep', 'gc_wake', 'gc_lock', 'gc_locked', 'gc_unlock', 'gc_srcu', 'gc_srcu_done'}


def parse(data):
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪格式损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        rows.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu),
                     'ns': int(Decimal(timestamp) * 1000000000), 'name': name, 'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', data['trace']) ==
           [(str(len(rows)), str(len(rows)))], '跟踪计数不符')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(rows, rows[1:])), '时钟倒退')
    counts = Counter(row['name'] for row in rows)
    per_cpu = Counter(row['cpu'] for row in rows)
    demand(bool(data['trace_stats']), '缺少 CPU 统计')
    for name, stats in data['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', name) is not None, 'CPU 名称非法')
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(per_cpu[int(name[3:])])], 'CPU 计数不符')
        for key in ('overrun', 'commit overrun', 'dropped events', 'read events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.M) == ['0'], '跟踪丢失或被消费')
    demand(set(per_cpu) <= {int(name[3:]) for name in data['trace_stats']}, '遗漏 CPU')
    profiles = {}
    for line in data['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0, '探针遗漏或重复')
        profiles[name] = int(hits)
    demand(set(profiles) == PROBES, '探针集合不符')
    demand(set(counts) <= PROBES | {'tracing_mark_write', 'signal_generate', 'sched_process_exit', 'tcp_send_reset'}, '未知事件')
    for name, hits in profiles.items():
        demand(hits >= counts[name] if name in FILTERED else hits == counts[name], '探针计数不符')
    markers = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in markers] == [row['phase'] for row in data['events']], '阶段记录不一致')
    demand(len(markers) == len({row['detail'] for row in markers}), '阶段重复')
    return rows, {row['detail']: row for row in markers}


def select(rows, name, pid=None):
    return [row for row in rows if row['name'] == name and (pid is None or row['pid'] == pid)]


def only(rows, name, pid=None):
    found = select(rows, name, pid)
    demand(len(found) == 1, '缺少唯一 ' + name)
    return found[0]


def sleep_intervals(rows, handlers):
    intervals = []
    # 同一处理线程的 printk 也会使用 SRCU；仅关联页锁前的 VM SRCU 实例。
    addresses = set()
    for row in select(rows, 'gc_lock'):
        previous = [item for item in rows[:row['index']] if item['pid'] == row['pid'] and item['name'] == 'gc_srcu']
        demand(bool(previous), '页锁缺少 SRCU 入口')
        addresses.add(field(previous[-1], 'srcu'))
    demand(len(addresses) == 1, 'VM SRCU 身份不唯一')
    address = addresses.pop()
    for pid in handlers:
        srcu = locked = pending = False
        sleeping = None
        finished = False
        for row in (item for item in rows if item['pid'] == pid):
            name = row['name']
            if name == 'gc_handler_done':
                demand(not (srcu or locked or pending or sleeping), '线程退出时仍持锁或 SRCU')
                finished = True
            if finished:
                continue
            if name == 'gc_srcu' and field(row, 'srcu') == address:
                demand(not srcu, 'SRCU 重复获取')
                srcu = True
            elif name == 'gc_lock':
                demand(srcu and not locked and not pending, '页面锁获取顺序错误')
                pending = True
            elif name == 'gc_locked':
                demand(pending, '页面锁返回缺少入口')
                pending = False
                locked = field(row, 'code') == '0'
            elif name == 'gc_unlock':
                demand(locked and '(ivy_kvm_dsm_handle_req+' in row['detail'], '页面锁释放不属于请求')
                locked = False
            elif name == 'gc_srcu_done' and '(ivy_kvm_dsm_handle_req+' in row['detail']:
                demand(srcu and not locked and not pending and '(ivy_kvm_dsm_handle_req+' in row['detail'], 'SRCU 释放顺序错误')
                srcu = False
            elif name == 'gc_sleep':
                demand(not (srcu or locked or pending or sleeping), '等待时仍持锁或 SRCU')
                demand(0 < int(field(row, 'delay')) <= 100000 and field(row, 'mode') == '1', '睡眠时长或模式错误')
                sleeping = row
            elif name == 'gc_wake':
                demand(sleeping is not None and '(ivy_kvm_dsm_handle_req+' in row['detail'], '等待返回缺少同线程入口')
                intervals.append((sleeping, row))
                sleeping = None
        demand(finished, '处理线程未退出')
    return sorted(intervals, key=lambda pair: pair[0]['index'])


def inspect(data):
    demand(data['kernel'] == '7.1.0-rc3-sshpool-gvm-pf30', '不是 PF30')
    demand(not data['errors'] and data['grace_restored'] and data['trace_cleanup_complete']
           and not data['final_tasks'] and not data['remaining_tasks'], '实验或清理未完成')
    demand(data['worker_sha256'] == '19379170276a834e53eeb7e934e8e67f03112d2659f8cccf9c3a41543d561864', '工作进程不匹配')
    request = (struct.pack('<QHHH', 38, 0, 0, 42) + struct.pack('<BB6xQBBH4x', 1, 1, 2, 1, 0, 0)).ljust(4110, b'\0')
    demand(bytes.fromhex(data['request_hex']) == request, '请求不匹配')
    ready, write, done = data['worker_records']
    demand(ready == {'op': 'ready', 'node': 0, 'nodes': 2, 'pid': data['worker_pid'], 'rip': 4096, 'address': 8192}, '工作进程身份错误')
    demand(write == {**write, 'op': 'write', 'value': 1, 'observed': 1, 'exit_reason': 5, 'rip': 4101}
           and write['elapsed_ns'] > 0 and done == {'op': 'writes_done'}, '真实客体写入未完成')
    ids = {int(pid): task['name'] for pid, task in data['initial_tasks'].items()}
    demand(len(ids) == 9 and set(ids.values()) == {'kvm-dsm/0'} | {f'dsm-conn/0:{i}' for i in range(8)}, '线程集合错误')
    handlers = {pid for pid, name in ids.items() if name.startswith('dsm-conn/')}
    root_pid = data['root_pid']
    demand(ids.get(root_pid) == 'kvm-dsm/0', '根线程身份错误')
    rows, marks = parse(data)
    demand({'write_begin', 'request_sent', 'cleanup_begin', 'cleanup_done'} <= marks.keys(), '缺少实验阶段')
    cleanup = marks['cleanup_begin']['index']
    completions = select(rows, 'gc_handler_done')
    demand(len(completions) == 8 and {row['pid'] for row in completions} == handlers, '处理线程退出不完整')
    root = only(rows, 'gc_root_done', root_pid)
    freed = only(rows, 'gc_free')
    demand(max(row['index'] for row in completions) < root['index'] < freed['index'] < only(rows, 'gc_freed')['index'] < marks['cleanup_done']['index'], '回收顺序错误')
    exits = select(rows, 'sched_process_exit')
    demand(len(exits) == 9 and {row['pid']: row['comm'] for row in exits} == ids, '线程退出身份错误')
    for row in exits:
        demand(field(row, 'comm') == ids[row['pid']] and int(field(row, 'pid')) == row['pid'], '调度退出身份错误')
        returned = only(rows, 'gc_root_done' if row['pid'] == root_pid else 'gc_handler_done', row['pid'])
        demand(returned['index'] < row['index'] < freed['index'], '线程未在释放前退出')
    intervals = sleep_intervals(rows, handlers)
    grace = data['grace_us']
    demand(grace in (0, 1000), '授权参数错误')
    demand(bool(intervals) == bool(grace), '未观察到授权等待或零开关仍等待')
    sends = select(rows, 'gc_send')
    failures = [row for row in select(rows, 'gc_failure') if row['index'] < cleanup]
    mode = data['mode']
    summary = {'mode': mode, 'grace_us': grace, 'sleep_count': len(intervals),
               'max_sleep_ns': max((b['ns'] - a['ns'] for a, b in intervals), default=0),
               'full_ssi_accepted': False, 'native_close_accepted': False}
    if mode == 'control':
        demand(not failures and len(sends) == 1 and field(sends[0], 'length') == '4096', '对照响应错误')
        response = data['response']
        raw = bytes.fromhex(response['hex'])
        demand(len(raw) == 4110 and struct.unpack_from('<QHHH', raw) == (4110, 1, 0, 42)
               and raw[14:] == struct.pack('<I', 1) + bytes(4092), '对照页面内容错误')
        demand(response['payload_sha256'] == hashlib.sha256(raw[14:]).hexdigest(), '对照摘要错误')
        sent = only(rows, 'gc_sent', sends[0]['pid'])
        demand(field(sent, 'code') == '4110' and sends[0]['index'] < sent['index'] < marks['response_received']['index'] < cleanup, '对照响应未完成')
        demand(data['worker_exit'] == 1 and 'operation=close_not_sealed errno=22' in data['worker_stderr'], '对照退出方式变化')
        return summary
    demand(mode in ('handler', 'root', 'reset') and grace == 1000, '故障场景错误')
    demand(not data.get('missed_window') and 'notification' in data, '没有等待通知')
    pid = data['sleep_pid']
    demand(pid in handlers, '被通知者不是处理线程')
    notification = safety.teardown.EVENT.fullmatch(data['notification'])
    demand(notification is not None and int(notification[2]) == pid and notification[5] == 'gc_sleep', '通知身份错误')
    stamp = int(Decimal(notification[4]) * 1000000000)
    demand(any(a['pid'] == pid and a['ns'] <= stamp < b['ns'] and a['detail'] == notification[6] for a, b in intervals), '通知不属于归档等待')
    begin, end = marks['action_begin'], marks['action_done']
    demand(begin['index'] < end['index'] < cleanup, '注入阶段错误')
    if mode in ('handler', 'root'):
        target = pid if mode == 'handler' else root_pid
        demand(data['signal_target'] == target, '信号目标错误')
        actions = [row for row in select(rows, 'signal_generate') if int(field(row, 'pid')) == target
                   and field(row, 'sig') == '9' and field(row, 'grp') == '0' and field(row, 'res') == '0'
                   and field(row, 'code') == '-6' and row['pid'] == begin['pid']
                   and begin['index'] < row['index'] < end['index']]
        demand(len(actions) == 1, '缺少唯一线程定向信号')
        action = actions[0]
    else:
        action = only(rows, 'tcp_send_reset')
        connection = data['connection']
        demand(action['pid'] == data['observer_tid'] == begin['pid'] and
               field(action, 'src') == ':'.join(map(str, connection['local'])) and
               field(action, 'dest') == '127.0.0.1:37710' and connection['remote'] == ['127.0.0.1', 37710]
               and field(action, 'state') == 'TCP_CLOSE' and field(action, 'reason') == 'TCP_STATE'
               and begin['index'] < action['index'] < end['index'], '复位不属于受控连接')
    hit = [(a, b) for a, b in intervals if a['pid'] == pid and a['ns'] < action['ns'] < b['ns']]
    demand(len(hit) == 1, '取消或故障未落在已观察到的等待内')
    demand(not data.get('after_action_data'), '故障请求仍返回页面')
    if mode == 'reset':
        for sent in sends:
            demand(sent['pid'] == pid and field(sent, 'length') == '4096' and action['index'] < sent['index'] < cleanup, '复位后的发送尝试不匹配')
            returned = only(rows, 'gc_sent', pid)
            demand(returned['index'] > sent['index'] and int(field(returned, 'code')) < 0, '复位后的发送伪装成功')
    else:
        demand(not sends, '取消请求仍发送页面')
    demand(not data['tasks_after_action'] and root['index'] < cleanup and max(row['index'] for row in exits) < cleanup,
           '缺少清理前已退出的完整快照与跟踪')
    demand(failures and failures[0]['index'] < root['index'], '故障未锁存')
    expected = int(field(failures[0], 'code'))
    demand(expected in (-104, -32) if mode == 'reset' else expected == -4, '故障类型错误')
    demand(int(field(failures[0], 'code')) == expected and int(field(root, 'code')) == expected, '首个故障被覆盖')
    demand(data.get('management_probe') == 'read_after_failure' and data['worker_exit'] == 1
           and 'operation=ioctl errno=5' in data['worker_stderr'], '缺少故障后的管理调用拒绝')
    summary.update({'in_wait': True, 'first_error': expected,
                    'injection_to_root_exit_ns': root['ns'] - action['ns'],
                    'wait_return_code': int(field(hit[0][1], 'code')),
                    'failed_send_attempts': len(sends),
                    'error_latched_during_wait': hit[0][0]['ns'] < failures[0]['ns'] < hit[0][1]['ns']})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    raw = args.capture.read_bytes()
    if args.capture.suffix == '.gz':
        raw = gzip.decompress(raw)
    data = json.loads(raw)
    print(json.dumps(inspect(data.get('probe', data)), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
