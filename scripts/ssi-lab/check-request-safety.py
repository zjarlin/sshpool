#!/usr/bin/env python3
"""检查真实分配/释放、异常请求拒绝和页面锁取消顺序，不接受摘要布尔值替代事件。"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('teardown', Path(__file__).with_name('check-teardown.py'))
teardown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(teardown)
HEADER = struct.Struct('<QHHH')
PAGE = bytes((i * 17 + 3) % 256 for i in range(4096))


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def field(event, name):
    match = re.search(r'(?:^|\s)' + name + r'=(\S+)', event['detail'])
    demand(match is not None, f'事件缺少 {name}')
    return match.group(1)


def parse(result):
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪格式损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        events.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu),
                       'time': float(timestamp), 'name': name, 'detail': detail, 'index': len(events)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace']) ==
           [(str(len(events)), str(len(events)))], '跟踪事件缺失')
    demand(all(a['time'] <= b['time'] for a, b in zip(events, events[1:])), '全局时间倒退')
    demand(bool(result['trace_stats']), '缺少跟踪丢失计数')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪丢失')
    counts = Counter(e['name'] for e in events)
    profiles = {}
    for line in result['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0, 'kprobe 重复或遗漏')
        profiles[name] = int(hits)
    wanted = {'safe_enter', 'safe_done', 'safe_receive', 'safe_received', 'safe_lock',
              'safe_locked', 'safe_unlock', 'safe_srcu', 'safe_srcu_done', 'safe_register', 'safe_stop'}
    demand(set(profiles) == wanted, 'kprobe 集合缺失')
    for name, hits in profiles.items():
        # SRCU 是系统共用函数，PID 过滤前的命中数允许高于保存的实验事件数。
        demand(hits >= counts[name] if name in ('safe_srcu', 'safe_srcu_done') else hits == counts[name],
               'kprobe 与保存事件计数不一致')
    markers = [e for e in events if e['name'] == 'tracing_mark_write']
    demand([e['detail'] for e in markers] == [e['phase'] for e in result['events']], '阶段记录不一致')
    demand(len({e['detail'] for e in markers}) == len(markers), '阶段重复')
    return events, {e['detail']: e for e in markers}


def select(events, name, pid=None):
    return [e for e in events if e['name'] == name and (pid is None or e['pid'] == pid)]


def one(events, name, pid=None):
    found = select(events, name, pid)
    demand(len(found) == 1, f'{name} 不是唯一事件')
    return found[0]


def between(event, start, end):
    return start['index'] < event['index'] < end['index']


def check_response(value, txid, payload, copyset):
    raw = bytes.fromhex(value['hex'])
    demand(len(raw) == 4110 and HEADER.unpack_from(raw) == (14 + len(payload), copyset, 0, txid),
           '响应长度或事务元数据不符')
    demand(raw[14:14 + len(payload)] == payload and not any(raw[14 + len(payload):]),
           '响应内容错误或固定帧尾部未清零')
    demand((value['length'], value['copyset'], value['version'], value['txid'], value['payload_sha256']) ==
           (14 + len(payload), copyset, 0, txid, hashlib.sha256(payload).hexdigest()), '响应摘要与原始帧不符')


def check_snapshot(snapshot, root_pid, expected_workers):
    demand(snapshot.get(str(root_pid), {}).get('name') == 'kvm-dsm/0', '根线程身份改变')
    workers = {int(pid) for pid, task in snapshot.items() if task['name'].startswith('dsm-conn/')}
    demand(len(workers) == expected_workers and len(snapshot) == expected_workers + 1, '线程快照不完整')
    return workers


def validate(result):
    demand(not result['errors'] and result['exit'] == 0 and result['remaining_tasks'] == {}
           and result['trace_cleanup_complete'], '实验或清理未完成')
    events, marks = parse(result)
    mode = result['mode']
    demand(mode in ('malformed', 'lock-cancel'), '未知实验模式')
    normal = result['normal_tasks']
    roots = [int(pid) for pid, task in normal.items() if task['name'] == 'kvm-dsm/0']
    demand(len(roots) == 1, '根线程不唯一')
    root_pid = roots[0]
    normal_pids = check_snapshot(normal, root_pid, 8)
    starts = select(events, 'safe_enter')
    pids = {e['pid'] for e in starts}
    expected_threads = 128 if mode == 'malformed' else 8
    demand(len(starts) == len(pids) == expected_threads, '处理线程入口缺失或重复')
    demand({e['pid'] for e in select(events, 'safe_done')} == pids and
           len(select(events, 'safe_done')) == len(pids), '处理器退出缺失或重复')
    exits = select(events, 'sched_process_exit')
    demand(len(exits) == len(pids) + 1 and {e['pid'] for e in exits} == pids | {root_pid}
           and exits[-1]['pid'] == root_pid, '线程退出集合或根线程退出顺序错误')
    first_lock = select(events, 'safe_lock')[0]
    outstanding = Counter()
    for event in events[:first_lock['index']]:
        if event['pid'] == first_lock['pid'] and event['name'] in ('safe_srcu', 'safe_srcu_done'):
            outstanding[field(event, 'srcu')] += 1 if event['name'] == 'safe_srcu' else -1
    active = {address: count for address, count in outstanding.items() if count}
    demand(len(active) == 1 and list(active.values()) == [1], '无法唯一识别取页锁时持有的 KVM SRCU')
    vm_srcu = next(iter(active))
    for pid in pids:
        start = one(events, 'safe_enter', pid)
        done = one(events, 'safe_done', pid)
        exited = one(events, 'sched_process_exit', pid)
        allocations = [e for e in select(events, 'kmalloc', pid)
                       if 'call_site=ivy_kvm_dsm_handle_req+' in e['detail']]
        demand(len(allocations) == 1 and between(allocations[0], start, done), '临时页面分配不唯一')
        pointer = field(allocations[0], 'ptr')
        demand(int(pointer, 16) != 0 and field(allocations[0], 'bytes_req') == '4096', '页面分配无效')
        frees = [e for e in select(events, 'kfree', pid) if field(e, 'ptr') == pointer
                 and 'call_site=ivy_kvm_dsm_handle_req+' in e['detail']]
        demand(len(frees) == 1 and between(frees[0], allocations[0], done)
               and done['index'] < exited['index'], '临时页面没有在返回前恰好释放一次')
        entries = select(events, 'safe_receive', pid)
        returns = select(events, 'safe_received', pid)
        demand(len(entries) == len(returns) and bool(entries), '接收调用没有完整返回')
        for enter, leave in zip(entries, returns):
            demand(enter['index'] < leave['index'] < done['index']
                   and int(field(enter, 'capacity')) in (24, 4096), '接收容量或返回顺序错误')
        depth = 0
        for event in events[:done['index']]:
            if event['pid'] != pid or event['name'] not in ('safe_srcu', 'safe_srcu_done'):
                continue
            if field(event, 'srcu') == vm_srcu:
                depth += 1 if event['name'] == 'safe_srcu' else -1
                demand(depth in (0, 1), 'SRCU 解锁无对应持有或重复获取')
        demand(depth == 0, '处理器返回前未释放 KVM SRCU')
    stop = select(events, 'safe_stop')
    demand(len(stop) == 2 and all(e['pid'] == result['worker_pid'] for e in stop), 'VM 停止边界不完整')
    demand(marks['quit_begin']['index'] < stop[0]['index'] < exits[-1]['index'] <
           stop[1]['index'] < marks['quit_done']['index'], 'VM 停止和线程退出顺序错误')
    quit_ms = (marks['quit_done']['time'] - marks['quit_begin']['time']) * 1000
    demand(0 <= quit_ms < 2000, 'VM 关闭超过两秒门槛')
    registration = one(events, 'safe_register')
    demand(registration['pid'] == result['worker_pid'] and
           between(registration, marks['register'], marks['normal_read']), '注册边界错误')
    check_response(result['normal_response'], 42, PAGE, 1)
    outcome = {'mode': mode, 'events': len(events), 'thread_exits': len(exits),
               'temporary_pages_freed': len(pids), 'quit_ms': quit_ms}
    if mode == 'malformed':
        outcome.update(check_malformed(result, events, marks, root_pid, normal_pids, vm_srcu))
    else:
        outcome.update(check_lock(result, events, marks, normal_pids, vm_srcu))
    return outcome


def check_malformed(result, events, marks, root_pid, normal_pids, vm_srcu):
    labels = [f'payload_{size}' for size in (0, 1, 23, 25, 4096)]
    labels += ['kind_3', 'kind_255', 'smm_2', 'requester_2', 'requester_255', 'requester_0',
               'sender_2', 'sender_255', 'length_13', 'length_4111']
    demand([case['label'] for case in result['cases']] == labels, '异常用例缺失或重复')
    expected_phases = [f'{label}_{phase}' for label in labels for phase in ('begin', 'send', 'rejected', 'done')]
    expected_phases += ['register', 'normal_read', 'normal_invalidate', 'quit_begin', 'quit_done']
    demand(list(marks) == expected_phases, '异常用例执行阶段错误')
    all_pids = set(normal_pids)
    for case in result['cases']:
        label = case['label']
        key, value = label.split('_')
        value = int(value)
        raw = bytes.fromhex(case['frame_hex'])
        fields = [1, 1, 2, 1, 0, 0]
        if key in ('kind', 'smm', 'requester', 'sender'):
            fields[{'requester': 0, 'sender': 1, 'kind': 3, 'smm': 4}[key]] = value
        payload = bytes(value) if key == 'payload' else struct.pack('<BB6xQBBH4x', *fields)
        if key == 'length':
            payload = b''
        length = value if key == 'length' else 14 + len(payload)
        expected = (HEADER.pack(length, 0, 0, 42) + payload).ljust(4110, b'\0')
        demand(raw == expected, '发送的异常帧与指定用例不符')
        code = -90 if key == 'payload' and value > 24 else -71
        receive_code = code if key == 'length' or code == -90 else len(payload)
        demand(case['expected_code'] == code, '预期错误码被修改')
        pids = check_snapshot(case['initial_tasks'], root_pid, 8)
        remaining = check_snapshot(case['after_reject'], root_pid, 7)
        demand(remaining < pids and not (pids & all_pids), '拒绝前后线程身份错误')
        for pid in remaining:
            before, after = [snapshot[str(pid)] for snapshot in (case['initial_tasks'], case['after_reject'])]
            demand(before['name'] == after['name'] == one(events, 'safe_enter', pid)['comm'] and
                   before['stat'].rsplit(')', 1)[1].split()[19] == after['stat'].rsplit(')', 1)[1].split()[19],
                   '拒绝前后 PID 被复用')
        all_pids.update(pids)
        check_snapshot(case['after_close'], root_pid, 0)
        rejected = next(iter(pids - remaining))
        done = one(events, 'safe_done', rejected)
        received = one(events, 'safe_received', rejected)
        demand(int(field(done, 'code')) == code and int(field(received, 'code')) == receive_code,
               '异常请求未保留预期错误')
        demand(between(received, marks[label + '_send'], done)
               and between(done, marks[label + '_send'], marks[label + '_rejected']), '异常请求拒绝顺序错误')
        for pid in pids:
            demand(not select(events, 'safe_lock', pid), '非法请求触达页锁')
            demand(not [e for e in select(events, 'safe_srcu', pid) if field(e, 'srcu') == vm_srcu],
                   '非法请求触达 KVM SRCU')
            if pid in remaining:
                finished = one(events, 'safe_done', pid)
                demand(int(field(finished, 'code')) == -104 and
                       between(finished, marks[label + '_rejected'], marks[label + '_done']), 'EOF 关闭未正确回收')
        demand(all(int(field(e, 'capacity')) == 24 for pid in pids
                   for e in select(events, 'safe_receive', pid)), '请求接收容量不是 24 字节')
    demand(all_pids == {e['pid'] for e in select(events, 'safe_enter')}, '用例线程集合覆盖不完整')
    check_response(result['invalidate_response'], 43, b'\0', 0)
    return {'rejected_cases': len(labels), 'normal_page_sha256': hashlib.sha256(PAGE).hexdigest(),
            'invalidation_ack_and_tail_zero': True}


def check_lock(result, events, marks, pids, vm_srcu):
    demand(list(marks) == ['register', 'normal_read', 'holder_send', 'holder_waiting', 'cancel_waiter',
                          'cancel_observed', 'release_holder', 'holder_complete', 'quit_begin', 'quit_done'],
           '页面锁实验阶段错误')
    demand(result['cancel_method'] == 'tgkill' and result['waiter_selection'] == 'unreturned_kprobe',
           '取消或等待者识别方法错误')
    waiter = result['waiter_pid']
    demand(waiter in pids and set(result['waiting_tasks']) == set(result['normal_tasks'])
           and set(result['after_cancel']) == set(result['normal_tasks']) - {str(waiter)},
           '取消影响了等待者以外的线程')
    for snapshot in (result['waiting_tasks'], result['after_cancel']):
        for pid, task in snapshot.items():
            before = result['normal_tasks'][pid]
            demand(task['name'] == before['name'] and task['stat'].rsplit(')', 1)[1].split()[19] ==
                   before['stat'].rsplit(')', 1)[1].split()[19], '页面锁等待期间 PID 被复用')
    lock = one(events, 'safe_lock', waiter)
    returned = one(events, 'safe_locked', waiter)
    done = one(events, 'safe_done', waiter)
    exited = one(events, 'sched_process_exit', waiter)
    demand(between(lock, marks['holder_waiting'], marks['cancel_waiter']) and
           between(returned, marks['cancel_waiter'], done) and
           between(exited, done, marks['cancel_observed']), '等待者未在持锁者释放前退出')
    demand(int(field(returned, 'code')) == int(field(done, 'code')) == -4
           and not select(events, 'safe_unlock', waiter), '等待者错误码或未持锁解锁错误')
    demand(len([e for e in select(events, 'safe_srcu_done', waiter) if field(e, 'srcu') == vm_srcu]) == 1,
           '等待者没有恰好释放一次 KVM SRCU')
    holders = [e for e in select(events, 'safe_lock') if between(e, marks['holder_send'], marks['holder_waiting'])]
    demand(len(holders) == 1, '持锁者不唯一')
    holder = holders[0]
    demand(holder['pid'] != waiter and all(field(holder, key) == field(lock, key) for key in ('slot', 'vfn')),
           '两个请求未竞争同一页面锁')
    holder_return = [e for e in select(events, 'safe_locked', holder['pid'])
                     if between(e, holder, marks['holder_waiting'])]
    demand(len(holder_return) == 1 and int(field(holder_return[0], 'code')) == 0, '持锁者未成功取锁')
    unlocks = [e for e in select(events, 'safe_unlock', holder['pid']) if e['index'] > holder['index']]
    demand(len(unlocks) == 1 and between(unlocks[0], marks['release_holder'], marks['holder_complete']),
           '持锁者过早释放页面锁')
    signals = [e for e in select(events, 'signal_generate') if between(e, marks['cancel_waiter'], marks['cancel_observed'])]
    demand(len(signals) == 1 and signals[0]['pid'] == marks['cancel_waiter']['pid'] and
           re.fullmatch(r'sig=9 errno=0 code=-6 comm=\S+ pid=' + str(waiter) + r' grp=0 res=0', signals[0]['detail']),
           '没有向唯一等待者定向投递 SIGKILL')
    forwarded = bytes.fromhex(result['forwarded_request'])
    demand(len(forwarded) == 4110 and HEADER.unpack_from(forwarded)[0] == 38 and
           struct.unpack_from('<BB6xQBBH4x', forwarded, 14) == (0, 1, 2, 1, 0, 0)
           and not any(forwarded[38:]), '未发送正确转发请求或尾部未清零')
    check_response(result['holder_response'], 43, PAGE, 1)
    cancel_ms = (exited['time'] - marks['cancel_waiter']['time']) * 1000
    demand(0 <= cancel_ms < 500, '页面锁取消超过五百毫秒门槛')
    return {'cancel_ms': cancel_ms, 'waiter_exited_before_holder_release': True,
            'holder_page_sha256': hashlib.sha256(PAGE).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result', type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(json.loads(args.result.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
