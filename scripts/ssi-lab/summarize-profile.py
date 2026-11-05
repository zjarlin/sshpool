#!/usr/bin/env python3
"""汇总完整线程采样；CPU 时间与有偏的调用栈快照分开报告。"""
import argparse
from collections import Counter
import json
from pathlib import Path


def summarize(records):
    if len(records) < 4 or records[0].get('op') != 'start' or records[-1].get('op') != 'complete':
        raise ValueError('采样没有完整开始和结束，不能报告成功')
    samples = records[1:-1]
    if any(record.get('op') != 'sample' for record in samples):
        raise ValueError('采样中有错误或未知记录')
    if records[-1]['samples'] != len(samples):
        raise ValueError('结束标记与实际采样数量不一致')
    previous_time = -1
    previous_tasks = {}
    for record in samples:
        if record['monotonic_ns'] <= previous_time:
            raise ValueError('宿主采样时间未递增')
        previous_time = record['monotonic_ns']
        tasks = {task['tid']: task for task in record['tasks']}
        if len(tasks) != len(record['tasks']):
            raise ValueError('同次采样存在重复 TID')
        for tid, task in tasks.items():
            previous = previous_tasks.get(tid)
            if previous is None or previous['start_ticks'] != task['start_ticks']:
                continue
            if task['runtime_ns'] < previous['runtime_ns']:
                raise ValueError('同一线程 CPU 累计时间倒退')
        previous_tasks = tasks
    first = {task['tid']: task for task in samples[0]['tasks']}
    elapsed = (samples[-1]['monotonic_ns'] - samples[0]['monotonic_ns']) / 1e9
    groups = {}
    for name, prefix in [('vcpu', 'CPU '), ('dsm', 'dsm-conn/')]:
        tasks = [task for task in samples[-1]['tasks']
                 if task['comm'].startswith(prefix) and task['tid'] in first
                 and task['start_ticks'] == first[task['tid']]['start_ticks']]
        runtime = sum(task['runtime_ns'] - first[task['tid']]['runtime_ns']
                      for task in tasks) / 1e9
        groups[name] = {'matched_threads': len(tasks), 'cpu_seconds': runtime,
                        'cpu_equivalents': runtime / elapsed}
    # 这些是低频且非原子的栈快照比例，不是每个函数的精确累计耗时。
    stacks = Counter()
    for record in samples:
        for task in record['tasks']:
            if task['comm'].startswith('CPU '):
                for stack in task['stack']:
                    if 'ktcp_receive+' in stack:
                        stacks['vcpu_samples_in_ktcp_receive'] += 1
                        break
    return {'kernel': records[0]['kernel'], 'samples': len(samples),
            'elapsed_seconds': elapsed, 'groups': groups,
            'stack_observations': dict(stacks),
            'disappeared_observations': sum(len(s['disappeared']) for s in samples),
            'schedstats_at_start': records[0]['schedstats']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    records = [json.loads(line) for line in args.log.read_text().splitlines()]
    try:
        result = summarize(records)
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f'采样不完整或损坏：{error}') from error
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
