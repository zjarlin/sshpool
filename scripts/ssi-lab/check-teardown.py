#!/usr/bin/env python3
"""从真实内核事件顺序核查 DSM 线程是否在 vCPU/MMU 销毁前退出。"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


EVENT = re.compile(r'^\s*(.+)-(\d+)\s+\[(\d+)\]\s+\S+\s+(\d+\.\d+): (\w+): (.+)$')


def inspect(result):
    if result['errors'] or result['probe_exit'] != 0 or not result['trace_cleanup_complete']:
        raise ValueError('探针或跟踪清理未完成')
    receive = result['receive']
    if receive['errors'] or not receive['closed'] or receive['exit'] != 0 or receive['remaining_threads']:
        raise ValueError('真实 VM 关闭未完成')
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = EVENT.fullmatch(line)
        if not match:
            raise ValueError('跟踪记录格式损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        events.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu),
                       'time': float(timestamp), 'name': name, 'detail': detail})
    counts = Counter(event['name'] for event in events)
    expected = {'pre': 1, 'pre_done': 1, 'vcpu': 2, 'mmu': 1,
                'free': 1, 'free_done': 1, 'sched_process_exit': 9}
    if result['has_stop_function']:
        expected.update({'stop': 2, 'stop_done': 2})
    if counts != expected:
        raise ValueError('销毁函数或九个 DSM 线程退出事件缺失、重复或混入其他实例')
    headers = re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace'])
    if headers != [(str(len(events)), str(len(events)))]:
        raise ValueError('跟踪缓冲区记录不完整')
    if any(a['time'] > b['time'] for a, b in zip(events, events[1:])):
        raise ValueError('跨 CPU 全局时间顺序倒退')
    if not result['trace_stats']:
        raise ValueError('缺少每 CPU 丢失计数')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            if re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) != ['0']:
                raise ValueError('跟踪事件有丢失或缺少丢失计数')
    profiles = {}
    for line in result['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        if name in profiles or int(missed):
            raise ValueError('kprobe 计数重复或存在未捕获调用')
        profiles[name] = int(hits)
    if profiles != {key: value for key, value in expected.items() if key != 'sched_process_exit'}:
        raise ValueError('kprobe 命中计数与事件记录不一致')

    exits = [event for event in events if event['name'] == 'sched_process_exit']
    wanted_names = {'kvm-dsm/0'} | {f'dsm-conn/0:{i}' for i in range(8)}
    if {event['comm'] for event in exits} != wanted_names or len({event['pid'] for event in exits}) != 9:
        raise ValueError('退出的线程集合不完整或身份重复')
    phase_threads = receive['phases'][-1]['after']
    for event in exits:
        if f"comm={event['comm']} pid={event['pid']} " not in event['detail']:
            raise ValueError('调度事件的线程身份不一致')
        if event['comm'].startswith('dsm-conn/'):
            task = phase_threads.get(str(event['pid']))
            if task is None or task['name'] != event['comm']:
                raise ValueError('退出线程不是半帧测量时的接收线程')
    callers = {event['pid'] for event in events if event['name'] != 'sched_process_exit'}
    if len(callers) != 1 or callers.intersection(event['pid'] for event in exits):
        raise ValueError('销毁调用不属于同一个探针进程')

    positions = {name: [i for i, event in enumerate(events) if event['name'] == name]
                 for name in counts}
    pre, pre_done = positions['pre'][0], positions['pre_done'][0]
    first_cpu, last_cpu = positions['vcpu']
    mmu, free, free_done = positions['mmu'][0], positions['free'][0], positions['free_done'][0]
    if not pre < pre_done < first_cpu < last_cpu < mmu < free < free_done:
        raise ValueError('KVM 销毁调用链不完整或乱序')
    if result['has_stop_function']:
        stop0, stop1 = positions['stop']
        done0, done1 = positions['stop_done']
        if not pre < stop0 < done0 < pre_done < free < stop1 < done1 < free_done:
            raise ValueError('预销毁停止与最终幂等清理的顺序不正确')
        if max(positions['sched_process_exit']) >= done0:
            raise ValueError('停止函数返回时仍有 DSM 线程尚未退出')
    return {'vcpu_destroys': 2, 'dsm_thread_exits': 9,
            'workers_stopped_before_destroy': max(positions['sched_process_exit']) < first_cpu,
            'events': len(events)}


def validate(result):
    observed = inspect(result)
    if not observed['workers_stopped_before_destroy']:
        raise ValueError('DSM 线程晚于 vCPU/MMU 销毁才退出')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result', type=Path)
    args = parser.parse_args()
    try:
        result = validate(json.loads(args.result.read_text()))
    except (ValueError, KeyError) as error:
        raise SystemExit(f'失败：{error}') from error
    print(f"关闭顺序通过：{result['dsm_thread_exits']} 个 DSM 线程在 vCPU/MMU 销毁前退出。")


if __name__ == '__main__':
    main()
