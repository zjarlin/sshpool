#!/usr/bin/env python3
"""复核固定页面的真实 ioctl、引用变化和释放通路，不据此宣称整机关闭。"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('check-ioctl-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
drain = admission.drain
demand, field = admission.demand, admission.field
PIN, STATUS, SEAL, ADMISSION = 0x4018AEF2, 0x8020AEF9, 0x4018AEF6, 0x8020AEF7
REGION = 0x4020AE46
GENERATION = 0x534449002020
PROBES = {'pp_enter', 'pp_entered', 'pp_leave', 'pp_left', 'pp_dsm', 'pp_done', 'pp_seal', 'pp_sealed'}
NEW_PROBES = {'pp_change', 'pp_changed', 'pp_slots', 'pp_busy'}


def parse(data):
    expected_probes = PROBES | (set() if data['baseline'] else NEW_PROBES)
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



def operations(rows, baseline):
    pending, done = {}, []
    for row in rows:
        pid, name = row['pid'], row['name']
        if name == 'pp_enter':
            demand(pid not in pending, '嵌套准入')
            pending[pid] = {'ioctl': int(field(row, 'ioctl'), 16), 'enter': row, 'changes': [], 'slots': []}
            demand(int(field(row, 'vm')) == 1, '预期 VM 调用')
        elif name == 'pp_entered':
            demand(pid in pending and 'token' not in pending[pid], '准入缺失或重复')
            item = pending[pid]
            token = int(field(row, 'code'))
            wanted = 0 if item['ioctl'] in (STATUS, SEAL, ADMISSION) else 2 if item['ioctl'] == PIN and not baseline else 1
            demand(token == wanted or token == -108, '错误准入令牌')
            item['token'] = token
            if token < 0:
                item['left'] = row
                done.append(pending.pop(pid))
        elif name in ('pp_dsm', 'pp_seal', 'pp_change', 'pp_slots'):
            demand(pid in pending, '操作缺少准入')
            item = pending[pid]
            if name == 'pp_dsm':
                demand(int(field(row, 'ioctl'), 16) == item['ioctl'] and 'dsm' not in item, 'DSM 调用不匹配')
                item['dsm'] = row
            else:
                demand(name not in item, '重复内部调用')
                item[name] = row
        elif name in ('pp_done', 'pp_sealed', 'pp_changed', 'pp_busy'):
            demand(pid in pending, '返回缺少准入')
            item = pending[pid]
            start = {'pp_done': 'dsm', 'pp_sealed': 'pp_seal', 'pp_changed': 'pp_change', 'pp_busy': 'pp_slots'}[name]
            demand(start in item, '内部返回缺少入口')
            if name == 'pp_done':
                demand('result' not in item, '重复 DSM 返回')
                item['result'] = int(field(row, 'code'))
                item['dsm_done'] = row
            elif name == 'pp_sealed':
                item['seal_result'] = int(field(row, 'code'))
                item['seal_done'] = row
                item.pop(start)
            else:
                key = 'changes' if name == 'pp_changed' else 'slots'
                item[key].append((item.pop(start), row, int(field(row, 'code'))))
        elif name == 'pp_leave':
            demand(pid in pending and 'leave' not in pending[pid], '释放令牌缺少准入')
            item = pending[pid]
            demand(int(field(row, 'token')) == item['token'], '释放错误令牌')
            demand(not any(key in item for key in ('pp_change', 'pp_seal', 'pp_slots')), '内部调用未结束')
            demand('dsm' not in item or 'result' in item, 'DSM 未返回就释放令牌')
            item['leave'] = row
        elif name == 'pp_left':
            demand(pid in pending and 'leave' in pending[pid], '缺少释放入口')
            item = pending.pop(pid)
            item['left'] = row
            done.append(item)
    demand(not pending, '准入未完整回收')
    return sorted(done, key=lambda item: item['enter']['index'])


def inspect(data):
    baseline = data['baseline']
    mode = data['mode']
    demand(type(baseline) is bool and data['kernel'] == '7.1.0-rc3-sshpool-gvm-' + ('pf22' if baseline else 'pf23'), '内核与对照标记不符')
    demand(mode in ('service', 'lifecycle', 'active', 'rollback') and (not baseline or mode == 'service'), '场景错误')
    demand(not data['errors'] and not data['remaining_tasks'] and data['trace_cleanup_complete'], '实验或清理失败')
    rows, marks = parse(data)
    phases = ['case_begin'] + (['blocked_observed'] if mode == 'service' else ['pending_observed'] if mode == 'active' else [])
    demand(list(marks) == phases + ['observation_complete', 'cleanup_begin', 'cleanup_complete'], '阶段错误')
    ops = operations(rows, baseline)
    calls = {row['name']: row for row in data['calls']}
    demand(len(calls) == len(data['calls']), '调用名重复')
    expected, pin_args, changes, slots = {}, {}, {}, {}

    def pin(name, offset, size, write=False, unpin=False, error=0, count=None):
        expected[name] = error
        pin_args[name] = (write, unpin, data['address'] + offset, size)
        if count is not None:
            changes[name] = count

    def region(name, error=0, slot=0, gfn=2, size=12288, offset=0, flags=0, busy=None):
        expected[name] = error
        demand(calls[name]['ioctl'] == REGION and struct.unpack('=IIQQQ', bytes.fromhex(calls[name]['hex'])) ==
               (slot, flags, gfn * 4096, size, data['address'] + offset), '内存槽参数错误: ' + name)
        if busy is not None:
            slots[name] = busy

    def seal(name, error=0, active=0):
        expected[name] = error
        row = calls[name]
        demand(row['ioctl'] == SEAL and struct.unpack('=IIQII', bytes.fromhex(row['hex'])) == (1, 0, GENERATION, 1000, 0), '封闭参数错误')
        demand(struct.unpack('=IIQIiII', bytes.fromhex(row['admission_status'])) ==
               (1, int(error == 0), GENERATION if error == 0 else 0, active, 0, 0, 0), '错误改变封闭状态或普通计数')

    if mode == 'rollback':
        region('setup_first', size=4096)
        region('setup_second', slot=1, gfn=3, size=4096, offset=4096)
    else:
        region('setup')
    if mode == 'service':
        pin('hold_read', 0, 4096, count=1)
        seal('drain_pinned', 0 if baseline else 16)
        pin('release_read', 0, 4096, unpin=True, error=108 if baseline else 0, count=0 if baseline else 1)
        if not baseline:
            seal('drain_released')
        demand(not data['blocked_readable'] and data['blocked_wait_ns'] >= 140000000, '未观察到真实阻塞窗口')
        tasks = data['blocked_tasks']
        demand(len(tasks) == 9 and sum(v['name'].startswith('dsm-conn/') for v in tasks.values()) == 8, '缺少真实请求线程')
        if baseline:
            demand(data['still_blocked'] and not data['responses'], '对照故障被伪装成释放成功')
    elif mode == 'lifecycle':
        pin('unmatched', 0, 4096, unpin=True, error=22, count=0)
        pin('zero_length', 0, 0, count=0)
        pin('read_cross_page', 4080, 32, count=2)
        pin('write_overlap', 0, 1, write=True, count=1)
        pin('wrong_kind', 4096, 4096, write=True, unpin=True, error=22, count=0)
        pin('partly_unmatched', 0, 12288, unpin=True, error=22, count=0)
        pin('read_overlap', 0, 1, count=1)
        region('delete_pinned', 16, size=0, busy=1)
        region('move_pinned', 16, gfn=6, busy=1)
        region('flags_pinned', 16, flags=1, busy=1)
        region('alias_pinned', 16, slot=1, gfn=8, size=4096, busy=1)
        seal('drain_pinned', 16)
        pin('release_overlap', 0, 1, unpin=True, count=1)
        pin('release_cross_page', 4080, 32, unpin=True, count=2)
        pin('release_write', 0, 1, write=True, unpin=True, count=1)
        pin('duplicate_release', 0, 1, write=True, unpin=True, error=22, count=0)
        region('delete_released', size=0, busy=0)
        region('restore_released', busy=0)
        seal('drain_released')
        pin('new_after_seal', 0, 4096, error=108, count=0)
    elif mode == 'rollback':
        region('remove_second', slot=1, gfn=3, size=0, offset=4096)
        pin('preexisting_read', 0, 4096, count=1)
        pin('failed_range', 0, 8192, error=14, count=2)
        pin('first_still_usable', 0, 4096, count=1)
        pin('release_first', 0, 4096, unpin=True, count=1)
        pin('release_preexisting', 0, 4096, unpin=True, count=1)
        region('restore_second', slot=1, gfn=3, size=4096, offset=4096)
        pin('range_repaired', 0, 8192, count=2)
        pin('release_repaired', 0, 8192, unpin=True, count=2)
        seal('drain_released')
    else:
        pin('active_pin', 0, 8192, write=True, count=2)
        seal('drain_active_pin', 16, active=1)
        seal('drain_pinned', 16)
        pin('release_completed', 0, 8192, write=True, unpin=True, count=2)
        seal('drain_released')
        worker = calls['active_pin']
        demand(data['worker'] == worker, '工作线程摘要不符')
        seal_call = calls['drain_active_pin']
        demand(worker['start_ns'] < seal_call['start_ns'] < seal_call['end_ns'] < worker['end_ns'], '未覆盖在途固定操作')
    demand(set(calls) == set(expected), '调用集合缺失或多余')
    matched, used = {}, set()
    for name, row in calls.items():
        demand(row['errno'] == expected[name] and row['end_ns'] > row['start_ns'], '调用错误码或时间异常: ' + name)
        if name in pin_args:
            demand(row['ioctl'] == PIN and struct.unpack('=??6xQQ', bytes.fromhex(row['hex'])) == pin_args[name], '固定参数错误: ' + name)
        candidates = [op for op in ops if op['enter']['pid'] == row['tid'] and op['ioctl'] == row['ioctl'] and op['enter']['index'] not in used]
        demand(bool(candidates), '缺少真实内核调用: ' + name)
        op = candidates[0]
        used.add(op['enter']['index'])
        matched[name] = op
        if row['errno'] == 108:
            demand(op['token'] == -108 and 'dsm' not in op, '封闭后调用进入实现')
        elif row['ioctl'] != REGION:
            demand('result' in op and (op['result'] >= 0 if baseline and row['errno'] == 0 else op['result'] == -row['errno']), '内核返回值与用户态不符')
        if row['ioctl'] == SEAL:
            demand(op['seal_result'] == -row['errno'] and op['seal_done']['index'] < op['leave']['index'], '缺少真实封闭结果')
        if name in changes and not baseline:
            demand(len(op['changes']) == changes[name] and all(value[2] == 0 for value in op['changes']), '页面引用变更次数或返回错误: ' + name)
        if name in slots:
            demand(len(op['slots']) == 1 and op['slots'][0][2] == slots[name], '槽保护未执行')
        if not name.startswith('setup'):
            demand(marks['case_begin']['index'] < op['enter']['index'] < op['left']['index'] < marks['observation_complete']['index'], '调用超出观察窗口')
    if mode == 'active':
        op = matched['active_pin']
        demand(op['token'] == 2 and op['enter']['index'] < marks['pending_observed']['index'] < matched['drain_active_pin']['enter']['index'] < op['left']['index'], '在途令牌不覆盖封闭检查')
    if mode == 'service':
        demand(matched['hold_read']['left']['index'] < marks['blocked_observed']['index'] < matched['drain_pinned']['enter']['index'] < matched['release_read']['enter']['index'], '固定阻塞与释放顺序错误')

    wanted_status = {} if baseline else {'initial': (0, 0, 0)}
    wanted_status.update({
        'service': {} if baseline else {'held': (0, 1, 0), 'released': (0, 0, 0)},
        'lifecycle': {'read_two': (0, 2, 0), 'mixed': (0, 2, 1), 'unchanged_after_invalid': (0, 2, 1), 'overlap_refs': (0, 3, 1), 'released': (0, 0, 0)},
        'active': {'pending': (1, 0, 1), 'completed': (0, 0, 2), 'released': (0, 0, 0)},
        'rollback': {'preexisting': (0, 1, 0), 'rolled_back': (0, 1, 0), 'first_held': (0, 2, 0), 'repaired': (0, 2, 0), 'released': (0, 0, 0)}
    }[mode])
    demand([s['name'] for s in data['statuses']] == list(wanted_status), '快照顺序错误')
    phase_times = {e['phase']: e['time_ns'] for e in data['events']}
    for index, status in enumerate(data['statuses']):
        demand(struct.unpack('=IIQQiI', bytes.fromhex(status['hex'])) == (1, *wanted_status[status['name']], 0, 0), '真实 ABI 计数错误')
        demand((status['version'], status['active'], status['read'], status['write'], status['error'], status['reserved']) == (1, *wanted_status[status['name']], 0, 0), '快照摘要不符')
        if index == 0:
            demand(status['time_ns'] < phase_times['case_begin'], '初始快照在操作之后')
        else:
            demand(data['statuses'][index-1]['time_ns'] < status['time_ns'] < phase_times['observation_complete'], '快照时间错误')
        if status['name'] == 'pending':
            demand(calls['active_pin']['start_ns'] < status['time_ns'] < calls['drain_active_pin']['start_ns'], '在途快照不在操作期间')
    snapshots = {s['name']: s for s in data['statuses']}
    boundaries = {
        'service': [('held', 'hold_read', 'drain_pinned'), ('released', 'release_read', 'drain_released')],
        'lifecycle': [('read_two', 'read_cross_page', 'write_overlap'), ('mixed', 'write_overlap', 'wrong_kind'),
                      ('unchanged_after_invalid', 'partly_unmatched', 'read_overlap'), ('overlap_refs', 'read_overlap', 'delete_pinned'),
                      ('released', 'duplicate_release', 'delete_released')],
        'active': [('completed', 'active_pin', 'drain_pinned'), ('released', 'release_completed', 'drain_released')],
        'rollback': [('preexisting', 'preexisting_read', 'failed_range'), ('rolled_back', 'failed_range', 'first_still_usable'),
                     ('first_held', 'first_still_usable', 'release_first'), ('repaired', 'range_repaired', 'release_repaired'),
                     ('released', 'release_repaired', 'drain_released')]
    }
    if not baseline:
        for snapshot, before, after in boundaries[mode]:
            demand(calls[before]['end_ns'] < snapshots[snapshot]['time_ns'] < calls[after]['start_ns'], '快照没有落在对应调用之间')
    if mode in ('service', 'active'):
        gfn = 2 if mode == 'service' else 3
        raw = bytes.fromhex(data['requests'][0])
        demand(len(data['requests']) == 1 and len(raw) == 4110 and drain.HEADER.unpack_from(raw) == (38, 0, 0, 42) and
               drain.REQUEST.unpack(raw[14:38]) == (1, 1, gfn, 1, 0, 0) and not any(raw[38:]), '请求报文错误')
        demand(len(data['responses']) == (0 if baseline else 1), '响应数量错误')
        if not baseline:
            drain.safety.check_response(data['responses'][0], 42, drain.safety.PAGE, 1)
    else:
        demand(not data['requests'] and not data['responses'], '无网络场景混入请求')
    if mode == 'active':
        raw = bytes.fromhex(data['outgoing_request'])
        header = drain.HEADER.unpack_from(raw)
        demand(len(raw) == 4110 and header[0:3] == (38, 0, 0) and header[3] != 255 and
               drain.REQUEST.unpack(raw[14:38]) == (0, 0, 3, 2, 0, 0) and not any(raw[38:]), '出站取页错误')
        injected = bytes.fromhex(data['injected'])
        demand(drain.HEADER.unpack_from(injected) == (4110, 1, 0, header[3]) and injected[14:] == drain.safety.PAGE, '注入响应不匹配')
    demand(data['page_sha256'] == hashlib.sha256(drain.safety.PAGE).hexdigest(), '页面内容错误')
    return {'mode': mode, 'baseline': baseline, 'calls': len(calls), 'trace_events': len(rows),
            'pin_operations': sum(op['ioctl'] == PIN for op in ops), 'regression_reproduced': baseline,
            'pin_lifecycle_verified': not baseline, 'whole_vm_shutdown_verified': False}


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
