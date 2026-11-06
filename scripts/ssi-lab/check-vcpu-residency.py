#!/usr/bin/env python3
"""核查 KVM 进入退出区间、LAPIC 等待及宿主定时器间隔，不把区间当作有效计算时间。"""
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('scheduling', Path(__file__).with_name('check-dsm-scheduling.py'))
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)
latency = scheduling.latency
demand = latency.demand


def parse(result):
    demand(result.get('exit') == 0 and not result['errors'] and result['trace_cleanup_complete'], '采样或清理未完成')
    demand('[global]' in result['trace_clock'].split(), '需要跨 CPU 全局时钟')
    before, after = result['tasks_before'], result['tasks_after']
    demand(bool(before) and before.keys() == after.keys(), '线程集合改变')
    for pid, task in before.items():
        demand(task['comm'] == after[pid]['comm'], '线程名称改变')
        demand(all(snapshot['stat'].split(' ', 1)[0] == pid for snapshot in (task, after[pid])), '线程 stat 身份错误')
        demand(task['stat'].rsplit(')', 1)[1].split()[19] == after[pid]['stat'].rsplit(')', 1)[1].split()[19], '线程 PID 被复用')
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = latency.EVENT.fullmatch(line)
        demand(match is not None, '跟踪格式错误')
        comm, pid, cpu, stamp, name, detail = match.groups()
        seconds, fraction = stamp.split('.')
        events.append({'pid': int(pid), 'cpu': int(cpu), 'comm': comm.strip(), 'name': name,
                       'ns': int(seconds) * 1000000000 + int(fraction.ljust(9, '0')), 'detail': detail,
                       'flags': line.split(']', 1)[1].split()[0]})
    demand(bool(events), '跟踪为空')
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace']) ==
           [(str(len(events)), str(len(events)))], '跟踪事件计数不完整')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(events, events[1:])), '跟踪时间倒退')
    demand(bool(result['trace_stats']), '缺少缓冲区计数')
    demand({f"cpu{event['cpu']}" for event in events} <= result['trace_stats'].keys(), 'CPU 丢失计数不完整')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪丢失')
    for event in events:
        if event['name'] in {'kvm_entry', 'kvm_exit', 'kvm_wait_lapic_expire'}:
            demand(str(event['pid']) in before and before[str(event['pid'])]['comm'].startswith('CPU '), '事件不属于目标 vCPU')
            identity = re.match(r'CPU (\d+)/KVM$', before[str(event['pid'])]['comm'])
            observed = re.match(r'vcpu (\d+)\b', event['detail'])
            demand(identity is not None and observed is not None and identity.group(1) == observed.group(1),
                   'vCPU 编号与线程身份不符')
    beats = result['heartbeats']
    demand(len(beats) >= 2, '缺少心跳')
    for clock in ('monotonic_ns', 'raw_ns'):
        demand(all(a[clock] < b[clock] for a, b in zip(beats, beats[1:])), '宿主时钟倒退')
    demand(0 < result['capture_started_ns'] <= beats[0]['monotonic_ns'] <
           beats[-1]['monotonic_ns'] <= result['capture_stopped_ns'], '采样窗口错误')
    return events


def pair(events, entry_name, exit_name):
    pending, seen, complete, censored = {}, set(), [], []
    for event in events:
        pid = event['pid']
        if event['name'] == entry_name:
            demand(pid not in pending, '重复入口或缺少返回')
            pending[pid] = event
            seen.add(pid)
        elif event['name'] == exit_name:
            start = pending.pop(pid, None)
            if start is None:
                demand(pid not in seen, '窗口内部返回缺少入口')
                seen.add(pid)
                censored.append(event)
                continue
            demand(start['cpu'] == event['cpu'], '不可抢占区间发生 CPU 迁移')
            if entry_name == 'kvm_entry':
                identity = [re.match(r'vcpu (\d+)', e['detail']) for e in (start, event)]
                demand(all(identity) and identity[0].group(1) == identity[1].group(1), 'vCPU 编号不匹配')
            complete.append({'start': start, 'end': event, 'duration_ns': event['ns'] - start['ns']})
    return complete, len(censored) + len(pending)


def runnable_waits(events, tasks):
    """复用调度状态机，仅保留目标线程事件；窗口尾仍以全量跟踪边界截断。"""
    tids = {int(pid) for pid in tasks}
    selected = []
    for event in events:
        name = event['name']
        if name == 'sched_switch' and any(latency.field(event, key) in tids for key in ('prev_pid', 'next_pid')):
            selected.append(event)
        elif name in {'sched_wakeup', 'sched_migrate_task'} and latency.field(event, 'pid') in tids:
            selected.append(event)
    selected.append({**events[-1], 'name': 'capture_boundary'})
    states = scheduling.timeline(selected, tids)
    waits = []
    for pid, changes in states.items():
        for (begin, state), (end, following) in zip(changes, changes[1:]):
            if state == 'runnable' and following == 'scheduled':
                waits.append({'pid': pid, 'comm': tasks[str(pid)]['comm'], 'begin_ns': begin,
                              'end_ns': end, 'duration_ns': end - begin})
    return waits


def inspect(result):
    events = parse(result)
    runs, incomplete_runs = pair(events, 'kvm_entry', 'kvm_exit')
    timers = defaultdict(list)
    for event in events:
        if event['name'] == 'local_timer_entry':
            timers[event['cpu']].append(event)
    gaps = [{'cpu': cpu, 'start': a, 'end': b, 'duration_ns': b['ns'] - a['ns']}
            for cpu, values in timers.items() for a, b in zip(values, values[1:])]
    longest = []
    stamps = [event['ns'] for event in events]
    for run in sorted(runs, key=lambda r: -r['duration_ns'])[:20]:
        start, end = run['start'], run['end']
        window = events[bisect_left(stamps, start['ns']):bisect_right(stamps, end['ns'])]
        lapic = [event for event in window if event['name'] == 'kvm_wait_lapic_expire' and event['pid'] == start['pid']]
        selected = [event for event in window if event['cpu'] == start['cpu'] and
                    (event['name'] == 'sched_switch' or
                     (event['name'].endswith('_entry') and event['name'] != 'kvm_entry'))]
        # sched_wakeup 的 CPU 编号按十进制补零，不能使用自动进制解析。
        wakes = []
        for event in window:
            if event['name'] != 'sched_wakeup':
                continue
            target = re.search(r'\btarget_cpu=(\d+)\b', event['detail'])
            demand(target is not None, '唤醒事件缺少目标 CPU')
            if int(target.group(1)) == start['cpu']:
                wakes.append(event)
        longest.append({**run, 'lapic_events': lapic,
                        'cpu_events': selected, 'targeted_wakeups': wakes})
    waits = runnable_waits(events, result['tasks_before'])
    exit_reasons = Counter()
    for event in events:
        if event['name'] == 'kvm_exit':
            reason = re.search(r'\breason (\S+)', event['detail'])
            demand(reason is not None, '缺少 VM 退出原因')
            exit_reasons[reason.group(1)] += 1
    return {'events': len(events), 'boundary_censored_runs': incomplete_runs,
            'kvm_intervals': latency.distribution([run['duration_ns'] for run in runs]),
            'exit_reasons': dict(exit_reasons),
            'event_counts': dict(Counter(event['name'] for event in events)),
            'runnable_waits': latency.distribution([wait['duration_ns'] for wait in waits]),
            'longest_runnable_waits': sorted(waits, key=lambda wait: -wait['duration_ns'])[:20],
            'heartbeat_intervals': {clock: latency.distribution([b[clock] - a[clock] for a, b in
                                                                zip(result['heartbeats'], result['heartbeats'][1:])])
                                    for clock in ('monotonic_ns', 'raw_ns')},
            'timer_intervals': {str(cpu): latency.distribution([gap['duration_ns'] for gap in gaps if gap['cpu'] == cpu])
                                for cpu in timers},
            'longest_kvm_intervals': longest,
            'longest_timer_intervals': sorted(gaps, key=lambda g: -g['duration_ns'])[:20]}, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    report, _ = inspect(json.loads(args.trace.read_text()))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
