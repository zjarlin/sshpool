#!/usr/bin/env python3
"""核对客体函数探针计数，并将完整调用与实际定时器中断关联。"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('guest', Path(__file__).with_name('check-guest-timers.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
latency = guest.load('check-dsm-latency')
demand = guest.demand
SYMBOLS = ('ktime_get_update_offsets_now', 'tick_sched_do_timer', 'tick_sched_handle')
FUNCTION_EVENTS = {f'{symbol}_{side}' for symbol in SYMBOLS for side in ('enter', 'exit')}
STAGES = ('ktime_seq_even', 'ktime_clock_done', 'ktime_seq_check')
STAGE_PROBES = (
    'p:ssi_guest_irq/ktime_seq_even ktime_get_update_offsets_now+56 seq=%r13:u32',
    'p:ssi_guest_irq/ktime_clock_done ktime_get_update_offsets_now+78',
    'p:ssi_guest_irq/ktime_seq_check ktime_get_update_offsets_now+218 before=%r13:u32 after=%dx:u32',
)


def profile(text, events):
    values = {}
    for line in text.splitlines():
        fields = line.split()
        demand(len(fields) == 3, '探针计数行损坏')
        name, hits, missed = fields
        demand(name in events and name not in values, '探针计数身份重复或未知')
        demand(hits.isdecimal() and missed == '0', '探针漏采或计数无效')
        values[name] = int(hits)
    demand(set(values) == events, '探针计数不完整')
    return values


def capture_events(files):
    stage_mode = any('ktime_seq_even' in line for line in files['probes'].splitlines())
    events = FUNCTION_EVENTS | (set(STAGES) if stage_mode else set())
    definitions = []
    for symbol in SYMBOLS:
        definitions += [f'p:ssi_guest_irq/{symbol}_enter {symbol}',
                        f'r128:ssi_guest_irq/{symbol}_exit {symbol}']
    if stage_mode:
        definitions += list(STAGE_PROBES)
        demand('ffffffff81213bc0 T ktime_get_update_offsets_now' in files['kallsyms'].splitlines(),
               '分段偏移的符号地址不符')
    demand(files['probes'].splitlines() == definitions, '探针定义或偏移不符')
    for key, value in [('kprobes-before', '1'), ('kprobes-disabled', '0'), ('kprobes-restored', '1')]:
        demand(files.get(key, '').strip() == value, '探针停用同步或恢复证据缺失')
    demand(all(hits == 0 for hits in profile(files['profile-before'], events).values()), '初始计数不为零')
    return events


def sequence_value(row, key):
    value = int(guest.field(row, key), 0)
    demand(0 <= value < 2 ** 32, '序列值超出 u32')
    return value


def split_stages(call, rows):
    """只分割完整调用；入口到偶数序列包含页访问与等待，不冒称纯自旋。"""
    demand(len(rows) >= 3 and len(rows) % 3 == 0, '函数分段缺失')
    attempts, previous = [], call['start']
    for offset in range(0, len(rows), 3):
        even, clock, check = rows[offset:offset + 3]
        demand(tuple(row['name'] for row in (even, clock, check)) == STAGES, '函数分段顺序不符')
        first, before, after = sequence_value(even, 'seq'), sequence_value(check, 'before'), sequence_value(check, 'after')
        demand(first % 2 == 0 and first == before, '初始序列不是相同偶数')
        final = offset + 3 == len(rows)
        demand((before == after) == final, '重试序列与控制流不符')
        attempts.append({'start': previous, 'even': even, 'clock': clock, 'check': check,
                         'to_even_ns': even['ns'] - previous['ns'],
                         'clock_read_ns': clock['ns'] - even['ns'],
                         'body_ns': check['ns'] - clock['ns'], 'retried': not final})
        previous = check
    tail = call['end']['ns'] - previous['ns']
    demand(sum(part[key] for part in attempts for key in ('to_even_ns', 'clock_read_ns', 'body_ns')) + tail
           == call['duration_ns'], '函数分段时间不守恒')
    return {**call, 'attempts': attempts, 'return_ns': tail}


def attach_stages(calls, rows, marks):
    # 通过同 CPU 的入口/返回栈归属，窗口外孤立阶段不参与耗时统计。
    staged, stack = defaultdict(list), defaultdict(list)
    for row in rows:
        cpu, name = row['cpu'], row['name']
        if name == 'ktime_get_update_offsets_now_enter':
            stack[cpu].append(row)
        elif name == 'ktime_get_update_offsets_now_exit':
            if stack[cpu]:
                stack[cpu].pop()
        elif name in STAGES:
            if not stack[cpu]:
                demand(not marks[0]['index'] < row['index'] < marks[1]['index'], '窗口内分段缺少函数入口')
                continue
            start = stack[cpu][-1]
            demand(start['pid'] == row['pid'], '函数分段线程不符')
            staged[start['index']].append(row)
    return [split_stages(call, staged[call['start']['index']]) for call in calls]


def inspect(files, log):
    events = capture_events(files)
    rows, marks = guest.parse(files, events)
    hits, counts = profile(files['profile-after'], events), Counter(row['name'] for row in rows)
    for row in rows:
        name = row['name']
        if name not in events:
            continue
        if name in STAGES:
            offset, fields = {
                'ktime_seq_even': ('38', r' seq=\d+'),
                'ktime_clock_done': ('4e', ''),
                'ktime_seq_check': ('da', r' before=\d+ after=\d+'),
            }[name]
            pattern = r'\(ktime_get_update_offsets_now\+0x' + offset + r'/0x120\)' + fields
        else:
            symbol, side = name.rsplit('_', 1)
            pattern = (r'\(' + symbol + r'\+0x0/0x[0-9a-f]+\)' if side == 'enter'
                       else r'\(\S+ <- ' + symbol + r'\)')
        demand(re.fullmatch(pattern, row['detail']) is not None, '函数事件地址或字段不符')
    for name in events - {symbol + '_exit' for symbol in SYMBOLS}:
        demand(hits[name] == counts[name], f'探针命中与事件数不符：{name}')
    functions, measured_calls = {}, []
    for symbol in SYMBOLS:
        entry, leave = symbol + '_enter', symbol + '_exit'
        calls, boundaries = guest.pair_nested(rows, entry, leave, lambda row: row['pid'])
        demand(all(row['index'] < marks[0]['index'] for row in boundaries['prefix']), '窗口内存在孤立返回')
        demand(all(row['index'] > marks[1]['index'] for row in boundaries['suffix']), '窗口内存在未完成函数')
        excess = hits[leave] - counts[leave]
        demand(0 <= excess <= len(boundaries['suffix']), '返回探针命中差额无边界解释')
        measured = [call for call in calls if marks[0]['index'] < call['start']['index'] <
                    call['end']['index'] < marks[1]['index']]
        demand(bool(measured), '测量窗口内没有完整函数')
        if symbol == SYMBOLS[0] and set(STAGES) <= events:
            measured = attach_stages(measured, rows, marks)
        functions[symbol] = {'distribution': latency.distribution([call['duration_ns'] for call in measured]),
                             'boundaries': boundaries, 'extra_return_hits': excess,
                             'longest': sorted(measured, key=lambda call: -call['duration_ns'])[:10]}
        measured_calls += [{'function': symbol, **call} for call in measured]
    timer_analysis = guest.inspect(files, log, events)
    for timer in timer_analysis['timers']:
        irq = timer['irq']
        timer['irq_functions'] = [call for call in measured_calls if call['start']['cpu'] == timer['cpu'] and
                                  irq['start']['index'] < call['start']['index'] < call['end']['index'] < irq['end']['index']]
    return {'timer_analysis': timer_analysis, 'functions': functions, 'profile_counts_match': True,
            'stage_mode': set(STAGES) <= events, 'stall_cause_established': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('clock_log', type=Path)
    args = parser.parse_args()
    result = inspect(guest.read_archive(args.archive), args.clock_log.read_text())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['timer_analysis']['timer_gate_passed'] else 1)
