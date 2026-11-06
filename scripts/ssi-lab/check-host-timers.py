#!/usr/bin/env python3
"""核查宿主定时器中断退出到首次重装的间隔，不混用 trace 时钟与期限时钟。"""
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('check-vcpu-residency.py'))
residency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residency)
demand = residency.demand
PROBES = {'ht_program', 'ht_lapic', 'ht_deferred'}


def interrupts(rows):
    """每 CPU 配对本地定时器中断；只允许测量窗口两端缺少另一半。"""
    pending, seen, pairs, censored = None, False, [], 0
    for index, event in enumerate(rows):
        if event['name'] == 'local_timer_entry':
            demand(pending is None, '定时器入口重复')
            pending, seen = index, True
        elif event['name'] == 'local_timer_exit':
            if pending is None:
                demand(not seen, '窗口内部定时器退出缺少入口')
                seen, censored = True, censored + 1
                continue
            demand(rows[pending]['pid'] == event['pid'], '中断内线程身份改变')
            pairs.append((pending, index))
            pending = None
    return pairs, censored + int(pending is not None)


def analyze_cpu(rows):
    pairs, boundary_interrupts = interrupts(rows)
    indexes = {name: [i for i, event in enumerate(rows) if event['name'] == name]
               for name in ('hrtimer_rearm', 'local_timer_entry', 'ht_program', 'ht_lapic')}
    observations, counts = [], Counter()
    for begin, end in pairs:
        rearm_index = bisect_right(indexes['hrtimer_rearm'], begin)
        next_irq = bisect_right(indexes['local_timer_entry'], begin)
        boundary = indexes['local_timer_entry'][next_irq] if next_irq < len(indexes['local_timer_entry']) else len(rows)
        if rearm_index == len(indexes['hrtimer_rearm']) or indexes['hrtimer_rearm'][rearm_index] >= boundary:
            counts['no_rearm_before_next_interrupt_or_boundary'] += 1
            continue
        rearm = indexes['hrtimer_rearm'][rearm_index]
        if rearm <= end:
            counts['rearmed_inside_interrupt'] += 1
            continue
        observations.append((rows[rearm]['ns'] - rows[end]['ns'], begin, end, rearm, boundary))
    longest = []
    for delay, begin, end, rearm, boundary in sorted(observations, reverse=True)[:20]:
        following = bisect_right(indexes['hrtimer_rearm'], rearm)
        if following < len(indexes['hrtimer_rearm']):
            boundary = min(boundary, indexes['hrtimer_rearm'][following])
        program_pos = bisect_right(indexes['ht_program'], rearm)
        lapic_pos = bisect_right(indexes['ht_lapic'], rearm)
        program = indexes['ht_program'][program_pos] if program_pos < len(indexes['ht_program']) else len(rows)
        lapic = indexes['ht_lapic'][lapic_pos] if lapic_pos < len(indexes['ht_lapic']) else len(rows)
        matched = program < lapic < boundary
        if matched:
            matched = (residency.latency.field(rows[program], 'expires') ==
                       residency.latency.field(rows[rearm], 'next_event') and
                       residency.latency.field(rows[program], 'dev') == residency.latency.field(rows[lapic], 'dev'))
        last = lapic if matched else rearm
        window = rows[begin:last + 1]
        # 短窗口保存全部同 CPU 事件，较长窗口明确标注省略，不能冒充完整摘录。
        excerpt = window if len(window) <= 200 else window[:100] + window[-100:]
        longest.append({
            'cpu': rows[end]['cpu'], 'after_irq_delay_ns': delay,
            'irq_entry': rows[begin], 'irq_exit': rows[end], 'rearm': rows[rearm],
            'program': rows[program] if matched else None,
            'lapic_programming_entry': rows[lapic] if matched else None,
            'window_event_counts': dict(Counter(event['name'] for event in window)),
            'window_events': excerpt, 'window_omitted_events': len(window) - len(excerpt),
        })
    return {
        'complete_interrupts': len(pairs), 'boundary_interrupts': boundary_interrupts,
        'unpaired_rearm': dict(counts),
        'after_irq_delay': residency.latency.distribution([item[0] for item in observations]),
        'longest_rearms': longest,
    }


def inspect(result):
    events = residency.parse(result)
    counts = Counter(event['name'] for event in events)
    profiles = {}
    for row in result['kprobe_profile'].splitlines():
        name, hits, missed = row.split()
        demand(name not in profiles and int(missed) == 0, '函数探针重复或遗漏')
        demand(int(hits) >= counts[name], '函数命中少于实际记录')
        profiles[name] = int(hits)
    demand(set(profiles) == PROBES, '函数探针集合不符')
    by_cpu = defaultdict(list)
    for event in events:
        by_cpu[event['cpu']].append(event)
    return {
        'events': len(events), 'event_counts': dict(counts),
        'cpus': {str(cpu): analyze_cpu(rows) for cpu, rows in sorted(by_cpu.items())},
        'scope': 'Intervals use trace timestamps only. LAPIC function entry records a programming attempt, not hardware delivery. Window excerpts do not replace the complete trace.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.trace.read_bytes())), indent=2))


if __name__ == '__main__':
    main()
