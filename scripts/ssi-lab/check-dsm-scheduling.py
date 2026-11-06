#!/usr/bin/env python3
"""核查调度跟踪并把函数等待分解为已调度、可运行及睡眠时间，保留边界未知区间。"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('latency', Path(__file__).with_name('check-dsm-latency.py'))
latency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(latency)
demand = latency.demand
PAIRS = {'sc_access_done': 'sc_access', 'sc_flush_done': 'sc_flush', 'sc_tcp_done': 'sc_tcp'}


def parse(result):
    demand(result['exit'] == 0 and not result['errors'] and result['trace_cleanup_complete'], '采样或清理失败')
    before, after = result['tasks_before'], result['tasks_after']
    demand(bool(before) and before.keys() == after.keys(), '测量期间线程集合改变')
    for pid, task in before.items():
        demand(task['comm'] == after[pid]['comm'], '线程身份改变')
        demand(int(pid) > 0 and all(snapshot['stat'].split(' ', 1)[0] == pid
                                   for snapshot in (task, after[pid])), '线程 stat 身份错误')
        # stat 的第 22 项是进程启动 tick；命令名内可能有空格和括号。
        demand(task['stat'].rsplit(')', 1)[1].split()[19] ==
               after[pid]['stat'].rsplit(')', 1)[1].split()[19], '线程 PID 被复用')
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = latency.EVENT.fullmatch(line)
        demand(match is not None, '跟踪格式损坏')
        comm, pid, cpu, stamp, name, detail = match.groups()
        seconds, fraction = stamp.split('.')
        events.append({'pid': int(pid), 'cpu': int(cpu), 'comm': comm.strip(), 'name': name,
                       'ns': int(seconds) * 1000000000 + int(fraction.ljust(9, '0')), 'detail': detail})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace']) ==
           [(str(len(events)), str(len(events)))], '事件计数不完整')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(events, events[1:])), '全局时间倒退')
    demand(bool(result['trace_stats']), '缺少丢失计数')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪丢失')
    counts = Counter(e['name'] for e in events)
    profiles = {}
    for row in result['kprobe_profile'].splitlines():
        name, hits, missed = row.split()
        demand(name not in profiles and int(missed) == 0, '探针重复或遗漏')
        demand(int(hits) >= counts[name], '探针命中少于保存记录')
        profiles[name] = int(hits)
    demand(set(profiles) == set(PAIRS) | set(PAIRS.values()), '函数探针集合错误')
    demand(set(counts) <= set(profiles) | {'sched_switch', 'sched_wakeup', 'sched_migrate_task'}, '未知事件')
    demand(all(str(e['pid']) in before for e in events if e['name'] in profiles), '函数事件不属于目标线程')
    beats = result['heartbeats']
    demand(len(beats) >= 2 and all(a['monotonic_ns'] < b['monotonic_ns'] for a, b in zip(beats, beats[1:])),
           '心跳时间不完整或倒退')
    demand(0 < result['capture_started_ns'] <= beats[0]['monotonic_ns'] < result['capture_stopped_ns'],
           '采样窗口无效')
    demand(beats[-1]['monotonic_ns'] <= result['capture_stopped_ns'], '心跳超过采样窗口')
    if 'trace_clock' in result:
        demand('[global]' in result['trace_clock'].split(), '需要跨 CPU 全局跟踪时钟')
    return events


def timeline(events, tids):
    states = defaultdict(list)

    def transition(pid, stamp, state):
        changes = states[pid]
        if not changes or changes[-1][1] != state:
            changes.append((stamp, state))

    for event in events:
        name = event['name']
        if name == 'sched_switch':
            previous, next_pid = [latency.field(event, key) for key in ('prev_pid', 'next_pid')]
            demand(previous in tids or next_pid in tids, '切换事件不属于目标线程')
            match = re.search(r'prev_state=(\S+)', event['detail'])
            demand(match is not None, '缺少切出状态')
            state = match.group(1)
            if previous in tids:
                transition(previous, event['ns'], 'runnable' if state.startswith('R') else 'sleep:' + state)
            if next_pid in tids:
                transition(next_pid, event['ns'], 'scheduled')
        elif name == 'sched_wakeup':
            pid = latency.field(event, 'pid')
            demand(pid in tids, '唤醒事件不属于目标线程')
            transition(pid, event['ns'], 'runnable')
        elif name == 'sched_migrate_task':
            demand(latency.field(event, 'pid') in tids, '迁移事件不属于目标线程')
    # 两个独立跟踪实例的边界可能不同，不能把最后状态外推到没有采样的未来。
    demand(bool(events), '没有可用于分解的事件')
    for pid in tids:
        transition(pid, events[-1]['ns'], 'unknown')
    return states


def partition(states, begin, end):
    """按调度事件切分区间；已调度时间包含中断和虚拟化停顿，不等于有效 CPU 计算。"""
    state, cursor = 'unknown', begin
    totals = Counter()
    for stamp, following in states:
        if stamp <= begin:
            state = following
            continue
        if stamp >= end:
            break
        totals[state] += stamp - cursor
        cursor, state = stamp, following
    totals[state] += end - cursor
    demand(sum(totals.values()) == end - begin and all(value >= 0 for value in totals.values()), '区间分解错误')
    return dict(totals)


def inspect(result):
    events = parse(result)
    tids = {int(pid) for pid in result['tasks_before']}
    states = timeline(events, tids)
    pending, seen, censored, calls = {}, set(), [], []
    for event in events:
        name = event['name']
        if name in PAIRS.values():
            key = (event['pid'], name)
            demand(key not in pending, '函数入口重复或返回缺失')
            pending[key] = event
            seen.add(key)
        elif name in PAIRS:
            key = (event['pid'], PAIRS[name])
            start = pending.pop(key, None)
            if start is None:
                demand(key not in seen, '窗口内部返回缺少入口')
                seen.add(key)
                censored.append(event)
                continue
            calls.append({'start': start, 'end': event, 'duration_ns': event['ns'] - start['ns']})
    grouped = defaultdict(list)
    for call in calls:
        grouped[call['start']['name']].append(call['duration_ns'])
    longest = []
    for call in sorted(calls, key=lambda c: -c['duration_ns'])[:30]:
        start, end = call['start'], call['end']
        longest.append({**call, 'scheduling_ns': partition(states[start['pid']], start['ns'], end['ns'])})
    runnable = []
    for pid, changes in states.items():
        for (begin, state), (end, following) in zip(changes, changes[1:]):
            if state == 'runnable' and following == 'scheduled':
                runnable.append({'pid': pid, 'comm': result['tasks_before'][str(pid)]['comm'],
                                 'begin_ns': begin, 'end_ns': end, 'duration_ns': end - begin})
    heartbeat_gaps = [b['monotonic_ns'] - a['monotonic_ns'] for a, b in zip(result['heartbeats'], result['heartbeats'][1:])]
    return {'events': len(events), 'boundary_censored_calls': len(censored) + len(pending),
            'functions': {name: latency.distribution(values) for name, values in grouped.items()},
            'longest_calls': longest, 'runnable_waits': latency.distribution([r['duration_ns'] for r in runnable]),
            'longest_runnable_waits': sorted(runnable, key=lambda r: -r['duration_ns'])[:20],
            'heartbeat_intervals': latency.distribution(heartbeat_gaps)}, calls, states


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--latency-trace', type=Path)
    args = parser.parse_args()
    result = json.loads(args.trace.read_text())
    report, _, states = inspect(result)
    if args.latency_trace:
        other = json.loads(args.latency_trace.read_text())
        demand((other['node'], other['kernel'], other['qemu_pid']) ==
               (result['node'], result['kernel'], result['qemu_pid']), '两个窗口来自不同实例')
        calls, _ = latency.inspect_trace(other)
        selected = [call for call in calls if call['start']['name'] == 'lat_receive'
                    and latency.field(call['start'], 'txid') != 255]
        report['longest_responses'] = []
        for call in sorted(selected, key=lambda c: -c['duration_ns'])[:20]:
            start, end = call['start'], call['end']
            report['longest_responses'].append({**call, 'scheduling_ns': partition(states[start['pid']], start['ns'], end['ns'])})
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
