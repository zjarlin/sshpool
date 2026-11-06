#!/usr/bin/env python3
"""重算页面内容、线程内计时和真实内核调用，窗口边缘的不完整调用单独报告。"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re
import statistics


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load('probe-dsm-latency')
EVENT = load('check-teardown').EVENT
PAIRS = {'lat_sent': 'lat_send', 'lat_received': 'lat_receive', 'lat_locked': 'lat_lock',
         'lat_killable_done': 'lat_killable', 'lat_ioctl_done': 'lat_ioctl',
         'lat_clock_updated': 'lat_clock_update', 'lat_acquired': 'lat_acquire',
         'lat_faulted': 'lat_fault'}


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def distribution(values):
    ordered = sorted(values)
    if not ordered:
        return {'count': 0}
    return {'count': len(ordered), 'median_ns': statistics.median(ordered),
            'p95_ns': ordered[int((len(ordered) - 1) * .95)], 'max_ns': ordered[-1]}


def validate_log(log):
    rows = []
    for line in log.splitlines():
        if line.startswith('{'):
            rows.append(('record', json.loads(line)))
        else:
            kind, payload = line.split(' ', 1)
            demand(kind in ('LATENCY_SAMPLE', 'LATENCY_BURST', 'LATENCY_RESULT'), '未知日志类型')
            rows.append((kind, json.loads(payload)))
    demand(rows and rows[-1][0] == 'LATENCY_RESULT', '缺少唯一结束记录')
    result = rows[-1][1]
    nodes, rounds = result['nodes'], result['rounds']
    demand(nodes in (1, 2) and 4 <= rounds <= 128 and not result['errors'], '实验不完整')
    position = 0

    def take(kind, expected=None):
        nonlocal position
        demand(position < len(rows) and rows[position][0] == kind, '记录类型或顺序错误')
        record = rows[position][1]
        position += 1
        if expected is not None:
            demand(record == expected, '记录身份或顺序错误')
        return record

    pids = {}
    for node in range(nodes):
        ready = take('record')
        demand(ready['op'] == 'ready' and ready['node'] == node and ready['nodes'] == nodes
               and ready['pid'] > 0, '节点启动身份不一致')
        pids[node] = ready['pid']
    operations = []
    previous = {}

    def operation(node, name, seed, thread, observed=None):
        record = take('record')
        observed = seed if observed is None else observed
        demand((record['node'], record['op'], record['seed'], record['thread']) ==
               (node, name, seed, thread), '操作身份不一致')
        demand(record['observed_seed'] == observed and record['checksum'] == probe.page_checksum(observed),
               '整页内容校验失败')
        probe.validate_timing(record, node)
        key = (node, record['tid'])
        demand(record['begin_ns'] >= previous.get(key, 0), '同一线程操作重叠或倒退')
        previous[key] = record['end_ns']
        if thread == -1:
            demand(record['tid'] == pids[node], '主线程身份改变')
        operations.append(record)
        return record

    for round_number in range(rounds):
        writer = round_number % nodes
        reader = (1 - writer) % nodes
        for step, (node, name) in enumerate(((writer, 'write'), (writer, 'read'),
                                            (reader, 'read'), (reader, 'read'), (writer, 'read'))):
            operation(node, name, round_number + 1, -1)
            take('LATENCY_SAMPLE', {'round': round_number, 'step': step, 'node': node, 'operation': name})
    demand(result['samples'] == rounds * 5, '顺序操作计数错误')
    writes = result['burst_writes']
    final_seed = None
    if writes:
        demand(writes % (nodes * 2) == 0, '并发计数错误')
        count = writes // (nodes * 2)
        demand(1 <= count <= 512, '并发轮次越界')
        sequence, tids, done = Counter(), {}, set()
        for _ in range(writes + nodes):
            record = rows[position][1]
            node = record['node']
            demand(node in pids and node not in done, '并发节点已经结束或未知')
            base = (node + 1) * 1000000
            if record['op'] == 'burst_done':
                demand(all(sequence[node, thread] == count for thread in (0, 1)), '工作线程提前结束')
                take('record', {'op': 'burst_done', 'node': node, 'count': count, 'base': base})
                done.add(node)
                continue
            thread = record['thread']
            demand(thread in (0, 1) and sequence[node, thread] < count, '并发线程或次数错误')
            sequence[node, thread] += 1
            operation(node, 'write', base + thread * count + sequence[node, thread], thread)
            tids.setdefault((node, thread), record['tid'])
            demand(tids[node, thread] == record['tid'] != pids[node], '并发线程身份改变')
        for node in range(nodes):
            demand(tids[node, 0] != tids[node, 1], '两个线程使用相同身份')
        endpoints = {(node + 1) * 1000000 + count * multiple for node in range(nodes) for multiple in (1, 2)}
        for node in range(nodes):
            observed = rows[position][1]['observed_seed']
            demand(observed in endpoints and (final_seed is None or final_seed == observed), '最终页面不一致')
            final_seed = observed
            operation(node, 'read', 0, -1, observed)
        take('LATENCY_BURST', {'count': count, 'nodes': nodes, 'final_seed': final_seed,
                               'checksum': probe.page_checksum(final_seed)})
    for node in reversed(range(nodes)):
        take('record', {'op': 'closed', 'node': node})
    take('LATENCY_RESULT', result)
    demand(position == len(rows), '结束后有额外记录')
    return operations, {'nodes': nodes, 'serial_operations': rounds * 5, 'burst_writes': writes,
                        'final_seed': final_seed, 'ioctl_times': distribution([r['elapsed_ns'] for r in operations])}


def field(event, key):
    match = re.search(r'(?:^|\s)' + key + r'=(\S+)', event['detail'])
    demand(match is not None, '缺少跟踪字段 ' + key)
    return int(match.group(1), 0)


def inspect_trace(result):
    demand(not result['errors'] and result['exit'] == 0 and result['trace_cleanup_complete'], '跟踪或清理失败')
    window = 'qemu_pid' in result
    demand(0 < result['capture_started_ns'] < result['capture_stopped_ns'], '跟踪窗口时间错误')
    events = []
    for line in result['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = EVENT.fullmatch(line)
        demand(match is not None, '跟踪格式损坏')
        comm, pid, cpu, stamp, name, detail = match.groups()
        seconds, fraction = stamp.split('.')
        events.append({'pid': int(pid), 'cpu': int(cpu), 'comm': comm.strip(), 'name': name,
                       'ns': int(seconds) * 1000000000 + int(fraction.ljust(9, '0')), 'detail': detail})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', result['trace']) ==
           [(str(len(events)), str(len(events)))], '跟踪事件计数不完整')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(events, events[1:])), '跟踪时间倒退')
    demand(bool(result['trace_stats']), '缺少缓冲区计数')
    for stats in result['trace_stats'].values():
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪丢失')
    profiles = {}
    counts = Counter(e['name'] for e in events)
    for line in result['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0, '探针重复或遗漏')
        profiles[name] = int(hits)
        # 附加窗口停止之后、移除探针之前仍可能命中，不能冒充保存下来的事件。
        demand(int(hits) >= counts[name] if window else int(hits) == counts[name], '探针与保存计数不符')
    pairs = PAIRS if window else {k: v for k, v in PAIRS.items() if v not in ('lat_clock_update', 'lat_acquire', 'lat_fault')}
    demand(set(profiles) == set(pairs) | set(pairs.values()) | {'lat_unlock'}, '探针集合错误')
    demand(set(counts) <= set(profiles) | ({'kvm_page_fault'} if window else set()), '未知事件')
    pending, seen, censored, calls = {}, set(), [], []
    for event in events:
        name = event['name']
        if name in pairs.values():
            key = (event['pid'], name)
            demand(key not in pending, '函数入口重复或中间返回缺失')
            pending[key] = event
            seen.add(key)
        elif name in pairs:
            key = (event['pid'], pairs[name])
            start = pending.pop(key, None)
            if start is None:
                demand(window and key not in seen, '窗口内部返回缺少入口')
                censored.append({'edge': 'start', **event})
                seen.add(key)
                continue
            calls.append({'start': start, 'end': event, 'duration_ns': event['ns'] - start['ns']})
    demand(window or not pending, '工作进程结束后仍有未返回调用')
    censored.extend({'edge': 'end', **event} for event in pending.values())
    grouped = defaultdict(list)
    pages = defaultdict(list)
    for call in calls:
        start = call['start']
        name = start['name']
        if name == 'lat_receive':
            name += ':listener' if field(start, 'txid') == 255 else ':response'
        grouped[name].append(call['duration_ns'])
        if name == 'lat_acquire':
            pages[hex(field(start, 'gfn'))].append(call['duration_ns'])
    return calls, {'events': len(events), 'boundary_censored_calls': len(censored),
                   'window_ns': result['capture_stopped_ns'] - result['capture_started_ns'],
                   'functions': {key: distribution(values) for key, values in grouped.items()},
                   'hot_pages': sorted(({'gfn': key, 'inclusive_ns': sum(values), **distribution(values)}
                                        for key, values in pages.items()), key=lambda row: -row['inclusive_ns'])[:10]}


def validate_probe(log, traces):
    operations, summary = validate_log(log)
    demand([r['node'] for r in traces] == list(range(summary['nodes'])), '节点跟踪缺失或重复')
    summary['traces'] = []
    for result in traces:
        demand('worker_pid' in result and 'qemu_pid' not in result, '需要完整工作进程跟踪')
        calls, report = inspect_trace(result)
        ioctls = [c for c in calls if c['start']['name'] == 'lat_ioctl']
        enable = [c for c in ioctls if field(c['start'], 'command') == 0x4010aef0]
        demand(len(enable) == 1 and enable[0]['start']['pid'] == result['worker_pid']
               and field(enable[0]['end'], 'code') == 0, 'DSM 启用证据错误')
        copies = [c for c in ioctls if field(c['start'], 'command') == 0x4020aef1]
        expected = [r for r in operations if r['node'] == result['node']]
        demand(len(ioctls) == len(expected) + 1 == len(copies) + 1, 'ioctl 调用数不一致')
        by_tid = defaultdict(list)
        for call in sorted(copies, key=lambda c: c['start']['ns']):
            by_tid[call['start']['pid']].append(call)
        for record in expected:
            demand(bool(by_tid[record['tid']]), '线程 ioctl 配对缺失')
            call = by_tid[record['tid']].pop(0)
            demand(field(call['end'], 'code') == record['ioctl_result'] == 0, 'ioctl 返回值不一致')
            # trace 时间精度为微秒；两时钟频率可能略有差异，只检查内层耗时没有越过外层。
            demand(call['duration_ns'] <= record['elapsed_ns'] * 1.01 + 2000, '内核耗时超出 ioctl 计时')
        summary['traces'].append(report)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path)
    parser.add_argument('--trace', type=Path, action='append', required=True)
    args = parser.parse_args()
    traces = [json.loads(path.read_text()) for path in args.trace]
    result = validate_probe(args.log.read_text(), traces) if args.log else [inspect_trace(r)[1] for r in traces]
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
