#!/usr/bin/env python3
"""核对客体函数探针计数，并将完整调用与实际定时器中断关联。"""
import argparse
from bisect import bisect_left, bisect_right
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
WRITER_STAGES = ('tk_write_begin', 'tk_update_done', 'tk_write_end')
WRITER_OFFSETS = ('2e3', '2f2', '30f')
WRITER_PROBES = tuple(f'p:ssi_guest_irq/{name} timekeeping_advance+{int(offset, 16)} '
                      'seq=@0xffffffff8401b4c0:u32' for name, offset in zip(WRITER_STAGES, WRITER_OFFSETS))


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
    writer_mode = any('tk_write_begin' in line for line in files['probes'].splitlines())
    events = FUNCTION_EVENTS | (set(STAGES) if stage_mode else set())
    definitions = []
    for symbol in SYMBOLS:
        definitions += [f'p:ssi_guest_irq/{symbol}_enter {symbol}',
                        f'r128:ssi_guest_irq/{symbol}_exit {symbol}']
    if stage_mode:
        definitions += list(STAGE_PROBES)
        demand('ffffffff81213bc0 T ktime_get_update_offsets_now' in files['kallsyms'].splitlines(),
               '分段偏移的符号地址不符')
    if writer_mode:
        demand(stage_mode, '写入者观测需要完整读者分段')
        demand({'ffffffff81212a30 t timekeeping_advance', 'ffffffff8401b4c0 b tk_core'} <=
               set(files['kallsyms'].splitlines()), '写入者或序列地址不符')
        events |= set(WRITER_STAGES)
        definitions += list(WRITER_PROBES)
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


def inspect_writers(rows, marks, readers):
    """核对每段奇数序列的唯一更新与发布，只报告读写区间的实际重叠。"""
    calls, boundaries = guest.pair_nested(rows, 'tk_write_begin', 'tk_write_end', lambda row: row['pid'])
    demand(all(row['index'] < marks[0]['index'] for row in boundaries['prefix']), '窗口内写入者缺少起点')
    demand(all(row['index'] > marks[1]['index'] for row in boundaries['suffix']), '窗口内写入者未完成')
    measured = [call for call in calls if marks[0]['index'] < call['start']['index'] <
                call['end']['index'] < marks[1]['index']]
    demand(bool(measured), '窗口内没有完整写入者')
    # 启停会依次切换探针；只验证与测量窗口相交的调用，跨标记调用不计入分布。
    relevant = [call for call in calls if call['start']['index'] < marks[1]['index'] and
                marks[0]['index'] < call['end']['index']]
    stages = [row for row in rows if row['name'] == 'tk_update_done']
    indices = [row['index'] for row in stages]
    used = set()
    for call in relevant:
        start, end = call['start'], call['end']
        inside = stages[bisect_right(indices, start['index']):bisect_left(indices, end['index'])]
        demand(len(inside) == 1, '写入者更新阶段缺失或重复')
        middle = inside[0]
        demand((middle['pid'], middle['cpu']) == (start['pid'], start['cpu']), '写入者更新阶段身份不符')
        begin_seq, middle_seq, end_seq = (sequence_value(row, 'seq') for row in (start, middle, end))
        demand(begin_seq % 2 == 1 and middle_seq == begin_seq and end_seq == (begin_seq + 1) % 2 ** 32,
               '写入者序列未按奇数到下一偶数发布')
        used.add(middle['index'])
        call.update(update_done=middle, update_ns=middle['ns'] - start['ns'], publish_ns=end['ns'] - middle['ns'])
    demand(all(row['index'] in used for row in stages if marks[0]['index'] < row['index'] < marks[1]['index']),
           '窗口内更新阶段缺少完整写入者')
    ordered = sorted(relevant, key=lambda call: call['start']['index'])
    demand(all(a['end']['index'] < b['start']['index'] for a, b in zip(ordered, ordered[1:])), '写入临界区重叠')
    overlaps = []
    for reader in sorted(readers, key=lambda call: -call['duration_ns'])[:20]:
        writers = [call for call in relevant if call['start']['ns'] < reader['end']['ns'] and
                   reader['start']['ns'] < call['end']['ns']]
        overlaps.append({'reader': reader, 'writers': writers})
    return {'distribution': latency.distribution([call['duration_ns'] for call in measured]),
            'boundaries': boundaries, 'longest': sorted(measured, key=lambda call: -call['duration_ns'])[:20],
            'reader_overlap': overlaps}


def inspect(files, log):
    events = capture_events(files)
    rows, marks = guest.parse(files, events)
    hits, counts = profile(files['profile-after'], events), Counter(row['name'] for row in rows)
    for row in rows:
        name = row['name']
        if name not in events:
            continue
        if name in WRITER_STAGES:
            offset = WRITER_OFFSETS[WRITER_STAGES.index(name)]
            pattern = r'\(timekeeping_advance\+0x' + offset + r'/0x4a0\) seq=\d+'
        elif name in STAGES:
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
    result = {'timer_analysis': timer_analysis, 'functions': functions, 'profile_counts_match': True,
              'stage_mode': set(STAGES) <= events, 'stall_cause_established': False, 'full_ssi_accepted': False}
    if set(WRITER_STAGES) <= events:
        readers = [call for call in measured_calls if call['function'] == SYMBOLS[0]]
        result['writers'] = inspect_writers(rows, marks, readers)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('clock_log', type=Path)
    args = parser.parse_args()
    result = inspect(guest.read_archive(args.archive), args.clock_log.read_text())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['timer_analysis']['timer_gate_passed'] else 1)
