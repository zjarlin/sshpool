#!/usr/bin/env python3
"""核对宿主完整缺页记录，统计同一 vCPU 连续相同缺页的跨度，不推断单次调用耗时。"""
import argparse
from collections import Counter
import gzip
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('residency', Path(__file__).with_name('check-vcpu-residency.py'))
residency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residency)
demand = residency.demand
FAULT = re.compile(r'vcpu (\d+) rip (0x[0-9a-f]+) address (0x[0-9a-f]+) error_code (0x[0-9a-f]+)')


def consecutive_faults(events):
    """任何不同指令、地址或错误码都会截断本线程序列，其他线程事件不影响它。"""
    current, complete = {}, []
    for event in events:
        pid = event['pid']
        signature = tuple(event[key] for key in ('vcpu', 'rip', 'address', 'error_code'))
        prior = current.get(pid)
        if prior is not None and prior['signature'] == signature:
            prior['last'] = event
            prior['count'] += 1
            continue
        if prior is not None:
            complete.append(prior)
        current[pid] = {'signature': signature, 'first': event, 'last': event, 'count': 1}
    complete.extend(current.values())
    return [{'first': group['first'], 'last': group['last'], 'count': group['count'],
             'span_ns': group['last']['ns'] - group['first']['ns']}
            for group in complete if group['count'] > 1]


def inspect(result):
    demand(result['kernel'] == '7.1.0-rc3-sshpool-gvm-pf29' and result['node'] in (0, 1), '固定实验内核或节点不符')
    events = residency.parse(result)
    formats = result['event_formats']
    demand(set(formats) == {'kvm/kvm_page_fault'} and
           formats['kvm/kvm_page_fault'].startswith('name: kvm_page_fault\n'), '缺页事件格式不符')
    expected_filter = ' || '.join(f'common_pid == {pid}' for pid in sorted(result['tasks_before'], key=int))
    demand(result['task_filter'] == expected_filter, '目标线程过滤器不完整')
    cpu_count = re.findall(r'entries-in-buffer/entries-written: \d+/\d+\s+#P:(\d+)', result['trace'])
    demand(len(cpu_count) == 1 and set(result['trace_stats']) == {f'cpu{cpu}' for cpu in range(int(cpu_count[0]))},
           '逐 CPU 统计不完整')
    counts = Counter(event['cpu'] for event in events)
    for cpu, stats in result['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', cpu) is not None, 'CPU 统计名称错误')
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(counts[int(cpu[3:])])], '逐 CPU 事件数不符')
    for index, event in enumerate(events):
        demand(event['name'] == 'kvm_page_fault', '缺页采集包含未声明事件')
        match = FAULT.fullmatch(event['detail'])
        demand(match is not None, '缺页事件字段不完整')
        vcpu, rip, address, error = match.groups()
        task = result['tasks_before'].get(str(event['pid']))
        demand(task is not None and task['comm'] == event['comm'] == f'CPU {int(vcpu)}/KVM', '缺页不属于目标 vCPU')
        event.update(index=index, vcpu=int(vcpu), rip=int(rip, 16), address=int(address, 16), error_code=int(error, 16))
        demand(event['vcpu'] < 4 and all(event[key] < 2 ** 64 for key in ('rip', 'address', 'error_code')),
               '缺页字段超出固定实验范围')
    # 此 GFN 仅对应证据中固定 ELF 的 tk_core 与 shadow_timekeeper 共用页。
    selected = [event for event in events if event['address'] >> 12 == 0x401b]
    groups = [group for group in consecutive_faults(events) if group['first']['address'] >> 12 == 0x401b]
    demand(bool(selected) and bool(groups), '没有 timekeeper 页的重复缺页证据')
    return {'events': len(events), 'timekeeper_page_faults': len(selected),
            'faults_by_rip': dict(Counter(hex(event['rip']) for event in selected)),
            'repeated_sequences': len(groups),
            'longest_sequences': sorted(groups, key=lambda group: -group['span_ns'])[:20],
            'span_semantics': 'first_to_last_fault_on_same_vcpu',
            'single_invocation_proven': False, 'cross_clock_alignment_established': False,
            'stall_cause_established': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    opener = gzip.open if args.capture.suffix == '.gz' else open
    with opener(args.capture, 'rt') as source:
        result = inspect(json.load(source))
    print(json.dumps(result, indent=2))
