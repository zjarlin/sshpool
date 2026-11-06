#!/usr/bin/env python3
"""核对解除操作是否先于远端取页响应完成，并防止把暂存引用误当作可解除引用。"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('pins', Path(__file__).with_name('check-pins.py'))
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)
drain, demand, field = pins.drain, pins.demand, pins.field
PROBES = {'pr_enter', 'pr_entered', 'pr_leave', 'pr_left', 'pr_dsm', 'pr_done', 'pr_slots', 'pr_busy'}


def parse(data):
    expected_probes = PROBES
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = drain.safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪行损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        rows.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu), 'time': float(timestamp),
                     'name': name, 'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', data['trace']) ==
           [(str(len(rows)), str(len(rows)))], '跟踪头部计数不符')
    demand(all(a['time'] <= b['time'] for a, b in zip(rows, rows[1:])), '全局时间倒退')
    per_cpu = Counter(row['cpu'] for row in rows)
    demand(bool(data['trace_stats']), '缺少逐 CPU 统计')
    for name, stats in data['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', name) is not None, 'CPU 名称非法')
        demand(re.findall(r'^entries: (\d+)$', stats, re.MULTILINE) == [str(per_cpu[int(name[3:])])], '逐 CPU 计数不符')
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪丢失')
    demand(set(per_cpu) <= {int(name[3:]) for name in data['trace_stats']}, '遗漏 CPU')
    profiles = {}
    counts = Counter(row['name'] for row in rows)
    for line in data['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0, '探针重复或漏采')
        profiles[name] = int(hits)
    demand(set(profiles) == expected_probes and set(counts) <= expected_probes | {'tracing_mark_write'}, '探针集合错误')
    for name, hits in profiles.items():
        demand(hits == counts[name], '探针计数不符')
    marks = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in marks] == [row['phase'] for row in data['events']], '双重阶段记录不一致')
    demand(len(marks) == len({row['detail'] for row in marks}), '阶段重复')
    demand(all(a['time_ns'] < b['time_ns'] for a, b in zip(data['events'], data['events'][1:])), '阶段时间倒退')
    return rows, {row['detail']: row for row in marks}


def inspect(data):
    mode, baseline = data['mode'], data['baseline']
    demand(type(baseline) is bool and data['kernel'] == '7.1.0-rc3-sshpool-gvm-' + ('pf23' if baseline else 'pf24'), '内核与对照身份不符')
    demand(mode in ('dependency', 'pending', 'pending-write', 'empty', 'rollback', 'duplicate') and (not baseline or mode == 'dependency'), '场景错误')
    demand(not data['errors'] and not data['remaining_tasks'] and not data['live_workers'] and data['trace_cleanup_complete'], '实验或清理失败')
    demand(not data.get('cleanup_rescue') and data['pin_alive_before_response'], '取页没有真实等待或依赖清理才能返回')
    rows, marks = parse(data)
    middle = {'dependency': 'baseline_blocked' if baseline else 'callback_complete', 'pending': 'pending_protected', 'pending-write': 'pending_protected',
              'empty': 'slot_protected', 'rollback': 'pending_protected', 'duplicate': 'duplicates_completed'}[mode]
    demand(list(marks) == ['case_begin', 'waiting_observed', middle, 'release_response', 'observation_complete', 'cleanup_begin', 'cleanup_complete'], '观察阶段不完整')
    # 沿用冻结的准入配对逻辑，只转换这份记录的事件命名，历史检查器保持不变。
    canonical = [dict(row, name=row['name'].replace('pr_', 'pp_')) for row in rows]
    ops = pins.operations(canonical, False)
    times = {event['phase']: event['time_ns'] for event in data['events']}
    calls = {row['name']: row for row in data['calls']}
    demand(len(calls) == len(data['calls']), '调用名重复')
    across = mode in ('pending', 'pending-write', 'rollback')
    write = not across or mode == 'pending-write'
    offset = 0 if across else 4096
    size = 12288 if mode == 'rollback' else 8192 if across else 4096
    expected, wanted_args = {}, {}

    def pin(name, offset, length, write=False, unpin=False, error=0):
        expected[name] = error
        wanted_args[name] = (write, unpin, data['address'] + offset, length)

    def region(name, slot, gfn, size, offset, error=0):
        expected[name] = error
        row = calls[name]
        demand(row['ioctl'] == pins.REGION and struct.unpack('=IIQQQ', bytes.fromhex(row['hex'])) ==
               (slot, 0, gfn * 4096, size, data['address'] + offset), '槽参数错误')

    region('setup', 0, 2, 8192, 0)
    region('setup_last', 1, 4, 4096, 8192)
    if mode == 'rollback':
        region('remove_last', 1, 4, 0, 8192)
    if mode != 'empty':
        pin('preexisting', 0, 4096, write=mode == 'pending-write')
    pin('waiting_pin', offset, size, write=write, error=14 if mode == 'rollback' else 0)
    if mode in ('dependency', 'pending', 'pending-write', 'rollback'):
        pin('release_old', 0, 4096, write=mode == 'pending-write', unpin=True)
    if across:
        pin('cannot_release_pending', 0, 4096, write=write, unpin=True, error=22)
        pin('cannot_release_partial', 0, 8192, write=write, unpin=True, error=22)
    if mode == 'empty':
        region('delete_active', 0, 2, 0, 0, 16)
    if mode == 'duplicate':
        demand(sorted(calls[f'release_{i}']['errno'] for i in range(2)) == [0, 22], '并发解除必须恰好一个成功')
        for i in range(2):
            pin(f'release_{i}', 0, 4096, unpin=True, error=calls[f'release_{i}']['errno'])
    if mode == 'rollback':
        pin('nothing_left', 0, 4096, unpin=True, error=22)
    else:
        pin('release_new', offset, size, write=write, unpin=True)
    expected['drain'] = 0
    demand(set(calls) == set(expected), '调用集合不符')
    demand(calls['drain']['ioctl'] == pins.SEAL and struct.unpack('=IIQII', bytes.fromhex(calls['drain']['hex'])) == (1, 0, pins.GENERATION, 1000, 0), '封闭请求错误')
    demand(struct.unpack('=IIQIiII', bytes.fromhex(data['admission_status'])) == (1, 1, pins.GENERATION, 0, 0, 0, 0), '最终引用或入口没有排空')
    matched, used = {}, set()
    for name, row in calls.items():
        demand(row['errno'] == expected[name] and row['start_ns'] < row['end_ns'], '调用错误码或时间不符: ' + name)
        if name in wanted_args:
            demand(row['ioctl'] == pins.PIN and struct.unpack('=??6xQQ', bytes.fromhex(row['hex'])) == wanted_args[name], '固定参数错误: ' + name)
        candidates = [op for op in ops if op['ioctl'] == row['ioctl'] and op['enter']['pid'] == row['tid'] and op['enter']['index'] not in used]
        demand(bool(candidates), '缺少真实准入事件')
        op = candidates[0]
        used.add(op['enter']['index'])
        matched[name] = op
        if row['ioctl'] != pins.REGION:
            demand(op.get('result') == -row['errno'], '内核返回值与用户态不符')
        else:
            demand(len(op['slots']) == 1 and op['slots'][0][2] == int(row['errno'] == 16), '槽保护事件不符')
        if name not in ('setup', 'setup_last', 'remove_last'):
            demand(marks['case_begin']['index'] < op['enter']['index'] < op['left']['index'] < marks['observation_complete']['index'], '调用不在观察窗口')
    worker = calls['waiting_pin']
    demand(data['jobs']['pin']['call'] == worker and data['jobs']['pin']['tid'] == worker['tid'], '取页线程身份不符')
    op = matched['waiting_pin']
    demand(op['token'] == 2 and op['enter']['index'] < marks['waiting_observed']['index'] < marks['release_response']['index'] < op['left']['index'], '未覆盖真实在途固定')
    demand(worker['start_ns'] < times['waiting_observed'] < times['release_response'] < worker['end_ns'], '取页等待窗口不符')
    release_names = ['release_old'] if mode != 'empty' and mode != 'duplicate' else ['release_0', 'release_1'] if mode == 'duplicate' else ['delete_active']
    for name in release_names:
        row = calls[name]
        demand(times['waiting_observed'] < row['start_ns'], '释放或槽检查在取页等待之前')
        if baseline:
            demand(row['start_ns'] + 140000000 < times[middle] < times['release_response'] < row['end_ns'], '对照未持续阻塞或未由响应救援')
        else:
            demand(row['end_ns'] < times[middle] < times['release_response'], '取页响应之前未完成释放或槽检查')
            demand(row['end_ns'] - row['start_ns'] < 500000000, '释放或拒绝耗时超过 500 ms')
        demand(matched[name]['token'] == (1 if mode == 'empty' else 2), '解除或槽操作准入错误')
        if baseline:
            demand(matched[name]['enter']['index'] < marks[middle]['index'] < marks['release_response']['index'] < matched[name]['left']['index'], '内核解除事件没有复现响应依赖')
        else:
            demand(marks['waiting_observed']['index'] < matched[name]['enter']['index'] < matched[name]['left']['index'] < marks[middle]['index'], '内核解除事件晚于远端响应')
    if baseline:
        demand(data['release_blocked'] and 'kvm_vm_ioctl_dsm+' in data['release_stack'] and 'kvm_dsm_fetch+' in data['pin_stack'] and 'ktcp_receive+' in data['pin_stack'], '没有真实阻塞线程栈')
    expected_jobs = {'pin'} | ({'release'} if mode == 'dependency' else {'release_0', 'release_1'} if mode == 'duplicate' else set())
    demand(set(data['jobs']) == expected_jobs, '工作线程集合不符')
    for key in expected_jobs - {'pin'}:
        name = 'release_old' if key == 'release' else key
        demand(data['jobs'][key] == {'tid': calls[name]['tid'], 'call': calls[name]}, '解除线程记录不符')

    expected_status = {'initial': (0, 0, 0), 'waiting': (1, 0 if mode in ('empty', 'pending-write') else 2 if across else 1, 2 if mode == 'pending-write' else 0)}
    expected_status.update({'dependency': {'blocked': (2, 1, 0)} if baseline else {'old_released': (1, 0, 0)},
                            'pending': {'only_pending': (1, 1, 0)}, 'pending-write': {'only_pending': (1, 0, 1)}, 'rollback': {'only_pending': (1, 1, 0)},
                            'empty': {'still_waiting': (1, 0, 0)}, 'duplicate': {'one_released': (1, 0, 0)}}[mode])
    expected_status.update(completed=(0, 2 if mode == 'pending' else 0, 2 if mode == 'pending-write' else 1 if write else 0), released=(0, 0, 0))
    demand([s['name'] for s in data['statuses']] == list(expected_status), '状态序列不符')
    statuses = {s['name']: s for s in data['statuses']}
    for index, status in enumerate(data['statuses']):
        wanted = (1, *expected_status[status['name']], 0, 0)
        demand(struct.unpack('=IIQQiI', bytes.fromhex(status['hex'])) == wanted and tuple(status['values']) == wanted, '原始 ABI 或状态摘要错误')
        if index:
            demand(data['statuses'][index - 1]['time_ns'] < status['time_ns'] < times['observation_complete'], '快照时间错误')
    demand(statuses['initial']['time_ns'] < times['case_begin'], '初始快照错误')
    demand(worker['start_ns'] < statuses['waiting']['time_ns'] < times['waiting_observed'], '在途快照不在等待中')
    pending_name = list(expected_status)[2]
    demand(times['waiting_observed'] < statuses[pending_name]['time_ns'] < times[middle], '中间状态不在对应阶段')
    demand(worker['end_ns'] < statuses['completed']['time_ns'] < calls['nothing_left' if mode == 'rollback' else 'release_new']['start_ns'], '完成快照没有等待完整返回')
    demand(calls['nothing_left' if mode == 'rollback' else 'release_new']['end_ns'] < statuses['released']['time_ns'] < calls['drain']['start_ns'], '释放快照时序错误')

    expected_requests = [(42, 3, 2)] + ([(44, 2, 1)] if mode == 'dependency' else [])
    demand(len(data['requests']) == len(data['responses']) == len(expected_requests), '请求或响应缺失')
    for request, response, (txid, gfn, kind) in zip(data['requests'], data['responses'], expected_requests):
        raw = bytes.fromhex(request['hex'])
        demand(len(raw) == 4110 and drain.HEADER.unpack_from(raw) == (38, 0, 0, txid) and
               drain.REQUEST.unpack(raw[14:38]) == (1, 1, gfn, kind, 0, 0) and not any(raw[38:]), '合成请求字段错误')
        drain.safety.check_response(response, txid, drain.safety.PAGE, 0 if kind == 2 else 1)
        demand(request['time_ns'] < response['time_ns'], '响应时间错误')
    demand(data['responses'][0]['time_ns'] < times['case_begin'], '没有先转移远端写所有权')
    if mode == 'dependency':
        demand(not data['before_release_readable'], '旧引用没有阻塞回调请求')
        demand(data['requests'][1]['time_ns'] < calls['release_old']['start_ns'] < data['responses'][1]['time_ns'], '回调与解除顺序错误')
        if baseline:
            demand(times['release_response'] < data['responses'][1]['time_ns'], '旧版没有复现环形等待')
        else:
            demand(data['responses'][1]['time_ns'] < times['callback_complete'] < data['injected']['time_ns'], '未先完成回调再交付取页响应')
    raw = bytes.fromhex(data['outgoing_request']['hex'])
    header = drain.HEADER.unpack_from(raw)
    demand(len(raw) == 4110 and header[:3] == (38, 0, 0) and header[3] != 255 and
           drain.REQUEST.unpack(raw[14:38]) == (0, 0, 3, 2 if write else 1, 0, 0) and not any(raw[38:]), '实际出站取页错误')
    injected = bytes.fromhex(data['injected']['hex'])
    demand(drain.HEADER.unpack_from(injected) == (4110, 0 if write else 2, 0, header[3]) and injected[14:] == drain.safety.PAGE, '取页响应错误')
    demand(times['release_response'] < data['injected']['time_ns'] < worker['end_ns'], '注入时间不在工作线程返回之前')
    demand(data['page_sha256'] == hashlib.sha256(drain.safety.PAGE * 2).hexdigest(), '页面内容错误')
    return {'mode': mode, 'baseline': baseline, 'calls': len(calls), 'trace_events': len(rows),
            'reverse_dependency_reproduced': baseline,
            'unpin_progress_verified': not baseline and mode != 'empty',
            'active_pin_slot_protection_verified': mode == 'empty',
            'whole_vm_shutdown_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
    except (ValueError, KeyError, TypeError, struct.error) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
