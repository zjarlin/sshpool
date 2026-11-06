#!/usr/bin/env python3
"""核查宿主定时器空档内的实际事件，区分频繁 VM 退出与调度进度。"""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('check-vcpu-residency.py'))
residency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residency)


def summarize_window(events, first, last):
    """两个真实定时器入口限定窗口；仅统计同一 CPU，边界不外推。"""
    begin, end = events[first], events[last]
    interior = events[first + 1:last]
    counts = Counter(event['name'] for event in interior)
    reasons, flags = Counter(), Counter()
    for event in interior:
        if event['name'] in {'kvm_entry', 'kvm_exit'}:
            flags[event['flags']] += 1
        if event['name'] == 'kvm_exit':
            reason = re.search(r'\breason (\S+)', event['detail'])
            residency.demand(reason is not None, '缺少 VM 退出原因')
            reasons[reason.group(1)] += 1
    gap = max(range(first, last), key=lambda index: events[index + 1]['ns'] - events[index]['ns'])
    return {
        'cpu': begin['cpu'], 'duration_ns': end['ns'] - begin['ns'],
        'timer_start': begin, 'timer_end': end,
        'interior_events': len(interior), 'event_counts': dict(counts),
        'exit_reasons': dict(reasons), 'kvm_tracepoint_flags': dict(flags),
        'first_interior_event': interior[0] if interior else None,
        'last_interior_event': interior[-1] if interior else None,
        'max_observed_event_gap_ns': events[gap + 1]['ns'] - events[gap]['ns'],
        'max_gap_start': events[gap], 'max_gap_end': events[gap + 1],
    }


def inspect(result, limit=10):
    """复用完整性和身份检查；保留每 CPU 最长窗口，不判断未记录的 IRQ 状态。"""
    residency.demand(limit > 0, '窗口数量必须为正')
    events = residency.parse(result)
    # 计数前仍检查 KVM 配对，不能把乱序或重复进入变成正常退出洪流。
    residency.pair(events, 'kvm_entry', 'kvm_exit')
    by_cpu = defaultdict(list)
    for event in events:
        by_cpu[event['cpu']].append(event)
    windows = []
    for cpu, rows in sorted(by_cpu.items()):
        timers = [index for index, event in enumerate(rows) if event['name'] == 'local_timer_entry']
        gaps = list(zip(timers, timers[1:]))
        gaps.sort(key=lambda pair: rows[pair[1]]['ns'] - rows[pair[0]]['ns'], reverse=True)
        for first, last in gaps[:limit]:
            windows.append(summarize_window(rows, first, last))
    return {
        'events': len(events), 'cpus': sorted(by_cpu),
        'interpretation': 'Recorded events only; timer silence does not prove CPU descheduling or continuously disabled interrupts. KVM exits do not prove DSM or guest progress.',
        'timer_windows': windows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--limit', type=int, default=10)
    args = parser.parse_args()
    raw = args.trace.read_bytes()
    report = inspect(json.loads(raw), args.limit)
    report['raw_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
