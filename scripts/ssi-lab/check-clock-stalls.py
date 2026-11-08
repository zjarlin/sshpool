#!/usr/bin/env python3
"""核对活动 KVM 的时钟与取页跟踪，明确报告边界调用，不推断停顿根因。"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load('check-native-trace')
latency = load('check-dsm-latency')
probe = load('trace-clock-stalls')
demand = native.demand
PAIRS = {'cs_update': 'cs_updated', 'cs_acquire': 'cs_acquired'}
SYMBOLS = {'cs_update': 'kvm_guest_time_update', 'cs_acquire': 'kvm_dsm_vcpu_acquire_page'}


def parse(data):
    """入口要求精确计数；已停用的返回回调只允许对应窗口尾尚未返回的调用。"""
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = native.drain.safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪行损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        seconds, fraction = timestamp.split('.')
        rows.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu), 'name': name,
                     'ns': int(seconds) * 1_000_000_000 + int(fraction.ljust(9, '0')),
                     'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', data['trace']) ==
           [(str(len(rows)), str(len(rows)))], '跟踪头部计数不符')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(rows, rows[1:])), '全局时间倒退')
    per_cpu = Counter(row['cpu'] for row in rows)
    demand(bool(data['trace_stats']), '缺少逐 CPU 统计')
    for name, stats in data['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', name) is not None, 'CPU 名称非法')
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(per_cpu[int(name[3:])])], '逐 CPU 计数不符')
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.M) == ['0'], '跟踪丢失')
    demand(set(per_cpu) <= {int(name[3:]) for name in data['trace_stats']}, '遗漏 CPU')
    profiles = {}
    for line in data['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0 and int(hits) >= 0, '探针重复或漏采')
        profiles[name] = int(hits)
    expected = {name for _, name, _ in probe.PROBES}
    counts = Counter(row['name'] for row in rows)
    demand(set(profiles) == expected and set(counts) <= expected | {'tracing_mark_write'}, '探针集合错误')
    marks = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in marks] == [row['phase'] for row in data['events']] ==
           ['capture_begin', 'capture_end'], '窗口标记错误')
    demand(marks[0]['ns'] < marks[1]['ns'] and
           data['events'][0]['time_ns'] < data['events'][1]['time_ns'], '窗口时间错误')
    return rows, marks, counts, profiles


def pair_calls(rows, entry, leave):
    pending, seen, complete, prefix = {}, set(), [], []
    for row in rows:
        pid = row['pid']
        if row['name'] == entry:
            demand(pid not in pending, '重复入口或返回缺失')
            pending[pid] = row
            seen.add(pid)
        elif row['name'] == leave:
            start = pending.pop(pid, None)
            if start is None:
                demand(pid not in seen, '窗口内部返回缺少入口')
                seen.add(pid)
                prefix.append(row)
                continue
            complete.append({'start': start, 'end': row, 'duration_ns': row['ns'] - start['ns']})
    return complete, prefix, list(pending.values())


def inspect(data):
    demand(data['kernel'] == '7.1.0-rc3-sshpool-gvm-pf28' and data['node'] in (0, 1), '节点或内核错误')
    demand(not data['errors'] and data['trace_cleanup_complete'] and data['qemu_present_after'], '活动跟踪或清理未完成')
    demand('[global]' in data['trace_clock'].split(), '需要全局时钟')
    demand(data['profile_boundary_policy'] == 'disabled-returns-may-complete', '采集器边界协议不匹配')
    demand(data['qemu_identity_before'] == data['qemu_identity_after'] and
           data['qemu_identity_before']['start_ticks'] > 0, 'QEMU 身份改变')
    before, after = data['qemu_tasks_before'], data['qemu_tasks_after']
    demand(before == after and bool(before), 'QEMU 线程集合或身份改变')
    rows, marks, counts, profiles = parse(data)
    vcpus = {}
    for row in rows:
        if row['name'] == 'tracing_mark_write':
            continue
        task = before.get(str(row['pid']))
        demand(task is not None and task['comm'] == row['comm'] and
               re.fullmatch(r'CPU \d+/KVM', row['comm']) is not None, '调用不属于目标 vCPU')
        entry = next((key for key, value in PAIRS.items() if row['name'] in (key, value)), None)
        symbol = SYMBOLS[entry]
        if row['name'] == entry:
            match = re.fullmatch(r'\(' + symbol + r'\+0x[0-9a-f]+/0x[0-9a-f]+\) vcpu=(0x[0-9a-f]+)' +
                                 (r' gfn=(0x[0-9a-f]+) write=([01])' if entry == 'cs_acquire' else ''), row['detail'])
            demand(match is not None and int(match[1], 16) != 0, '入口字段错误')
            vcpus.setdefault(row['pid'], match[1])
            demand(vcpus[row['pid']] == match[1], '同线程 vCPU 指针改变')
        else:
            demand(re.fullmatch(r'\(\S+ <- ' + symbol + r'\) code=-?\d+', row['detail']) is not None, '返回字段错误')
    functions = {}
    for entry, leave in PAIRS.items():
        calls, prefix, suffix = pair_calls(rows, entry, leave)
        demand(profiles[entry] == counts[entry], '入口探针计数不符')
        excess = profiles[leave] - counts[leave]
        demand(0 <= excess <= len(suffix), '返回计数差超出末尾未完成调用')
        measured = [call for call in calls if marks[0]['index'] < call['start']['index'] and
                    call['end']['index'] < marks[1]['index']]
        by_caller = defaultdict(list)
        for call in measured:
            caller = call['end']['detail'].split(' <- ', 1)[0][1:].split('+', 1)[0]
            by_caller[caller].append(call['duration_ns'])
        functions[entry] = {
            'all_complete_calls': len(calls), 'measurement': latency.distribution([call['duration_ns'] for call in measured]),
            'prefix_returns': prefix, 'suffix_entries': suffix, 'disabled_return_hits': excess,
            'outside_measurement_calls': len(calls) - len(measured),
            'return_codes': dict(Counter(re.search(r'code=(-?\d+)$', call['end']['detail'])[1] for call in measured)),
            'by_caller': {caller: latency.distribution(values) for caller, values in sorted(by_caller.items())},
            'longest': sorted(measured, key=lambda call: -call['duration_ns'])[:10],
        }
    return {'node': data['node'], 'events': len(rows), 'window_ns': marks[1]['ns'] - marks[0]['ns'],
            'functions': functions, 'stall_cause_established': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.trace.read_text())), indent=2))
