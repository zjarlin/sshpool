#!/usr/bin/env python3
"""核对完整页面请求、取消边界和真实内核退出事件；基线失败也保留。"""
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


def inspect(result):
    if result['errors'] or result['exit'] != 0 or result['remaining_tasks'] or not result['trace_cleanup_complete']:
        raise ValueError('实验或清理失败')
    frame = bytes.fromhex(result['request_hex'])
    if (len(frame) != 4110 or struct.unpack_from('<QHHH', frame) != (38, 0, 0, 42)
            or frame[14:38] != struct.pack('<BB6xQBBH4x', 1, 1, 2, 1, 0, 0)
            or any(frame[38:])):
        raise ValueError('并非固定 ABI 的完整正常读页请求')
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = teardown.EVENT.fullmatch(line)
        if not match:
            raise ValueError('跟踪格式损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        events.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu),
                       'time': float(timestamp), 'name': name, 'detail': detail})
    if re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace']) != [
            (str(len(events)), str(len(events)))]:
        raise ValueError('跟踪记录缺失')
    if any(a['time'] > b['time'] for a, b in zip(events, events[1:])):
        raise ValueError('全局时间倒退')
    if not result['trace_stats']:
        raise ValueError('缺少丢失计数')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            if re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) != ['0']:
                raise ValueError('跟踪存在丢失')
    mode = result['mode']
    phases = {
        'late-register': ['request_sent', 'late_register', 'quit_begin', 'quit_done'],
        'cancel-root': ['request_sent', 'cancel_begin', 'cancel_observed', 'late_register',
                        'quit_begin', 'quit_done'],
        'close-vm': ['request_sent', 'quit_begin', 'quit_done'],
    }[mode]
    markers = [e for e in events if e['name'] == 'tracing_mark_write']
    if [e['detail'] for e in markers] != phases or [e['phase'] for e in result['events']] != phases:
        raise ValueError('实验阶段缺失或乱序')
    counts = Counter(e['name'] for e in events)
    expected = {'req_receive': 9 if mode == 'late-register' else 8,
                'req_handler_done': 8, 'req_stop': 2, 'sched_process_exit': 9,
                'tracing_mark_write': len(phases)}
    if mode != 'close-vm':
        expected['req_register'] = 1
    if mode == 'cancel-root':
        expected['signal_generate'] = 9
    if counts != expected:
        raise ValueError('请求、处理器退出、销毁或注册事件不完整')
    profiles = {}
    for line in result['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        if name in profiles or int(missed):
            raise ValueError('kprobe 重复或遗漏')
        profiles[name] = int(hits)
    if profiles != {name: counts[name] for name in
                    ('req_receive', 'req_handler_done', 'req_register', 'req_stop')}:
        raise ValueError('kprobe 计数不匹配')

    initial = result['initial_tasks']
    wanted = {'kvm-dsm/0'} | {f'dsm-conn/0:{index}' for index in range(8)}
    if len(initial) != 9 or {task['name'] for task in initial.values()} != wanted:
        raise ValueError('初始线程集合不完整')
    if initial.keys() != result['waiting_tasks'].keys():
        raise ValueError('取消前线程集合改变')
    for pid, task in initial.items():
        waiting = result['waiting_tasks'][pid]
        if (task['name'] != waiting['name'] or task['stat'].rsplit(')', 1)[1].split()[19]
                != waiting['stat'].rsplit(')', 1)[1].split()[19]):
            raise ValueError('等待阶段线程身份改变')
    exits = [e for e in events if e['name'] == 'sched_process_exit']
    if len({e['pid'] for e in exits}) != 9 or {str(e['pid']) for e in exits} != set(initial):
        raise ValueError('退出事件的 PID 不匹配')
    handlers = [e for e in events if e['name'] == 'req_handler_done']
    if {e['pid'] for e in handlers} != {e['pid'] for e in exits if e['comm'].startswith('dsm-conn/')}:
        raise ValueError('处理器退出身份不匹配')
    for event in exits:
        if (event['comm'] != initial[str(event['pid'])]['name'] or
                f"comm={event['comm']} pid={event['pid']} " not in event['detail']):
            raise ValueError('线程名或调度退出身份不匹配')
        if event['comm'].startswith('dsm-conn/'):
            returned = [e for e in handlers if e['pid'] == event['pid']]
            if len(returned) != 1 or events.index(returned[0]) >= events.index(event):
                raise ValueError('处理器尚未返回便报告线程退出')
    root_exit = next(e for e in exits if e['comm'] == 'kvm-dsm/0')
    if root_exit != exits[-1]:
        raise ValueError('根线程早于接收线程退出')
    complete = [e for e in events if e['name'] == 'req_receive' and e['detail'].endswith('len=24')]
    if len(complete) != 1 or str(complete[0]['pid']) not in initial:
        raise ValueError('未观察到唯一完整请求进入处理器')
    positions = {e['detail']: events.index(e) for e in markers}
    action = {'late-register': 'late_register', 'cancel-root': 'cancel_begin', 'close-vm': 'quit_begin'}[mode]
    if not positions['request_sent'] < events.index(complete[0]) < positions[action]:
        raise ValueError('操作发生前完整请求尚未进入重试阶段')
    stop = [e for e in events if e['name'] == 'req_stop']
    if any(e['pid'] != result['worker_pid'] for e in stop):
        raise ValueError('销毁来自其他进程')
    if not positions['quit_begin'] < events.index(stop[0]) < events.index(stop[1]) < positions['quit_done']:
        raise ValueError('VM 关闭边界不完整')
    quit_ms = (markers[-1]['time'] - next(e['time'] for e in markers if e['detail'] == 'quit_begin')) * 1000
    if not 0 <= quit_ms < 2000:
        raise ValueError('VM 关闭超过两秒门槛')
    if mode != 'close-vm':
        registration = next(e for e in events if e['name'] == 'req_register')
        if (registration['pid'] != result['worker_pid'] or
                not positions['late_register'] < events.index(registration) < positions['quit_begin']):
            raise ValueError('延迟注册边界不正确')
    outcome = {'mode': mode, 'complete_requests': 1, 'thread_exits': 9,
               'events': len(events), 'quit_ms': quit_ms}
    if mode == 'cancel-root':
        if result.get('cancel_method') != 'tgkill':
            raise ValueError('没有使用线程定向取消')
        signals = [e for e in events if e['name'] == 'signal_generate']
        targets = []
        for event in signals:
            match = re.fullmatch(r'sig=9 errno=0 code=(-?\d+) comm=(\S+) pid=(\d+) grp=0 res=0',
                                 event['detail'])
            if not match:
                raise ValueError('取消信号没有成功定向投递')
            code, comm, target = match.groups()
            if target not in initial or initial[target]['name'] != comm:
                raise ValueError('信号发给了其他线程')
            sender = markers[1]['pid'] if comm == 'kvm-dsm/0' else root_exit['pid']
            if event['pid'] != sender or int(code) != (-6 if comm == 'kvm-dsm/0' else 128):
                raise ValueError('信号不是由探针和 DSM 根线程逐级发出')
            if not positions['cancel_begin'] < events.index(event) < positions['cancel_observed']:
                raise ValueError('信号投递发生在取消窗口之外')
            targets.append(target)
        if len(set(targets)) != 9:
            raise ValueError('取消信号目标缺失或重复')
        if any(not e['detail'].endswith('code=-4') for e in handlers):
            raise ValueError('故障取消没有保留 EINTR 错误')
        if result['tasks_after_registration']:
            raise ValueError('补注册后仍未完成清理')
        cancelled = events.index(root_exit) < positions['late_register']
        if cancelled != (result['tasks_before_registration'] == {}):
            raise ValueError('跟踪与线程快照的取消结果不一致')
        if not positions['cancel_begin'] < events.index(root_exit) < positions['quit_begin']:
            raise ValueError('根线程没有在故障取消阶段退出')
        if not cancelled and events.index(root_exit) <= events.index(registration):
            raise ValueError('基线恢复顺序不完整')
        outcome['cancelled_without_registration'] = cancelled
        outcome['cancel_ms'] = (root_exit['time'] - next(
            e['time'] for e in markers if e['detail'] == 'cancel_begin')) * 1000
    elif mode == 'late-register':
        response = result['response']
        expected_hash = hashlib.sha256(bytes((i * 17 + 3) % 256 for i in range(4096))).hexdigest()
        if (response['length'], response['copyset'], response['version'], response['txid'],
                response['sha256'], response['matches']) != (4110, 1, 0, 42, expected_hash, True):
            raise ValueError('页面内容或事务元数据不匹配')
        outcome['page_sha256'] = expected_hash
    elif not events.index(stop[0]) < events.index(root_exit) < events.index(stop[1]):
        raise ValueError('完整请求没有在 VM 停止阶段退出')
    return outcome


def validate(result):
    outcome = inspect(result)
    if outcome.get('cancelled_without_registration') is False:
        raise ValueError('取消后仍依赖补注册内存槽才能退出')
    if outcome.get('cancel_ms', 0) >= 500:
        raise ValueError('取消超过五百毫秒门槛')
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result', type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(json.loads(args.result.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
