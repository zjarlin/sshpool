#!/usr/bin/env python3
"""核对真实 ioctl 准入令牌、SRCU 释放、控制返回和封闭期间的页面内容。"""
import argparse
from collections import Counter
import re
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('drain', Path(__file__).with_name('check-kernel-drain.py'))
drain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drain)
demand, field = drain.demand, drain.field
PROBES = {'ia_enter', 'ia_entered', 'ia_leave', 'ia_left', 'ia_dsm', 'ia_dsm_done',
          'ia_run', 'ia_run_done', 'ia_srcu_done', 'ia_failure'}
DRAIN, STATUS = 0x4018AEF6, 0x8020AEF7

# 记录来自 Linux，离线检查可能在 macOS 上运行，不能使用本机 errno 编号。
LINUX_EINVAL = 22
LINUX_EFAULT = 14
LINUX_ESHUTDOWN = 108
LINUX_ESTALE = 116
LINUX_EINTR = 4
LINUX_EPROTO = 71
LINUX_ETIMEDOUT = 110
LINUX_EIO = 5


def parse(data):
    expected_probes = PROBES
    filtered_probes = {'ia_srcu_done'}
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
        # 被过滤探针的原始命中数包含过滤前的其他调用。
        demand(hits >= counts[name] if name in filtered_probes else hits == counts[name], '探针计数不符')
    marks = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in marks] == [row['phase'] for row in data['events']], '双重阶段记录不一致')
    demand(len(marks) == len({row['detail'] for row in marks}), '阶段重复')
    demand(all(a['time_ns'] < b['time_ns'] for a, b in zip(data['events'], data['events'][1:])), '阶段时间倒退')
    return rows, {row['detail']: row for row in marks}


def inspect(data):
    demand(data['kernel'] == '7.1.0-rc3-sshpool-gvm-pf20', '错误内核')
    demand(not data['errors'] and not data['remaining_tasks'] and data['trace_cleanup_complete'], '实验或清理失败')
    rows, marks = parse(data)
    mode = data['mode']
    demand(mode in ('validation', 'active', 'timeout', 'fault', 'vcpu'), '未知场景')
    phases = ['case_begin', 'sealed']
    if mode != 'validation':
        phases.append('release_vcpu' if mode == 'vcpu' else 'inject_fault' if mode == 'fault' else 'release_response')
    phases += ['observation_complete', 'cleanup_begin', 'cleanup_complete']
    demand(list(marks) == phases, '阶段记录不完整')
    calls = {row['name']: row for row in data['calls']}
    demand(len(calls) == len(data['calls']), '重复调用名')
    demand(calls['not_enabled']['errno'] == LINUX_EINVAL, '未启用 DSM 就封闭入口')
    demand(data['not_enabled_errno'] == LINUX_EINVAL, '未启用结果不一致')
    for name in ('new_vm', 'new_vcpu', 'new_run', 'new_copy'):
        demand(calls[name]['errno'] == LINUX_ESHUTDOWN, '封闭后新调用未拒绝')
    for row in data['calls']:
        demand(row['end_ns'] > row['start_ns'], '调用时间倒退')
    for status in data['statuses']:
        expected = (1, status['state'], status['generation'], status['active'], status['error'], 0, 0)
        demand(struct.unpack('=IIQIiII', bytes.fromhex(status['hex'])) == expected, '状态原始字节不一致')
        demand(status['reserved'] == [0, 0] and status['version'] == 1 and status['error'] == 0, '状态元数据非法')
        demand(status['state'] in (0, 1), '状态超界')
        demand(status['generation'] == (data['generation'] if status['state'] else 0), '关联序号不符')
    statuses = {row['name']: row for row in data['statuses']}
    demand(statuses['initial']['active'] == statuses['initial']['state'] == 0, '初始入口非空闲')
    # 每个成功准入必须有唯一退出；控制调用不得参与它所等待的普通调用计数。
    pending, completed, rejected = {}, [], []
    for row in rows:
        pid, name = row['pid'], row['name']
        if name == 'ia_enter':
            demand(pid not in pending, '嵌套或泄漏的准入')
            pending[pid] = {'ioctl': int(field(row, 'ioctl'), 16), 'vm': int(field(row, 'vm')), 'enter': row}
        elif name == 'ia_entered':
            demand(pid in pending and 'token' not in pending[pid], '缺少准入入口')
            current = pending[pid]
            current['token'] = int(field(row, 'code'))
            control = current['vm'] and current['ioctl'] in (DRAIN, STATUS)
            demand(current['token'] < 0 or current['token'] == int(not control), '控制调用计入等待者或普通调用漏计')
            if current['token'] < 0:
                rejected.append(pending.pop(pid))
        elif name == 'ia_leave':
            demand(pid in pending and 'token' in pending[pid] and 'leave' not in pending[pid], '退出没有准入或重复退出')
            demand(int(field(row, 'token')) == pending[pid]['token'], '退出令牌不匹配')
            pending[pid]['leave'] = row
        elif name == 'ia_left':
            demand(pid in pending and 'leave' in pending[pid], '退出没有完成')
            pending[pid]['left'] = row
            completed.append(pending.pop(pid))
    demand(not pending, '准入计数没有配对回收')
    for name in ('new_vm', 'new_vcpu', 'new_run', 'new_copy'):
        demand(any(item['ioctl'] == calls[name]['ioctl'] and item['enter']['pid'] == calls[name]['tid']
                   and item['token'] == -LINUX_ESHUTDOWN and
                   marks['sealed']['index'] < item['enter']['index'] < marks['observation_complete']['index']
                   for item in rejected), '缺少新调用被拒绝的内核证据')
    if mode == 'validation':
        for name in ('version', 'flags', 'generation', 'zero_timeout', 'large_timeout', 'reserved'):
            demand(calls[name]['errno'] == LINUX_EINVAL and statuses['after_' + name]['state'] == 0, '参数错误改变入口状态')
        demand(calls['bad_pointer']['errno'] == LINUX_EFAULT and statuses['after_pointer']['state'] == 0, '坏指针改变状态')
        demand(calls['idle']['errno'] == 0, '空闲屏障失败')
    else:
        worker = data['worker']
        demand(worker == calls['running_vcpu' if mode == 'vcpu' else 'write_page'], '工作线程摘要不一致')
        demand(worker['errno'] == (LINUX_EPROTO if mode == 'fault' else LINUX_EINTR if mode == 'vcpu' else 0), '原操作返回错误')
        admitted = [item for item in completed if item['enter']['pid'] == worker['tid'] and item['token'] == 1]
        demand(len(admitted) == 1, '工作线程准入不唯一')
        operation = admitted[0]
        demand(operation['enter']['index'] < marks['sealed']['index'] < operation['leave']['index'], '屏障没有覆盖在途操作')
        sealed = [row for row in data['statuses'] if row['name'] == 'poll_seal' and row['state'] == 1]
        demand(sealed and sealed[-1]['active'] == 1, '封闭时没有计入正在运行的操作')
        completion_name = 'ia_run_done' if mode == 'vcpu' else 'ia_dsm_done'
        returns = [row for row in rows if row['name'] == completion_name and row['pid'] == worker['tid']]
        demand(len(returns) == 1 and int(field(returns[0], 'code')) == -worker['errno'], '工作线程缺少真实返回')
        demand(returns[0]['index'] < operation['leave']['index'], '操作未返回就释放准入计数')
        if mode == 'vcpu':
            demand('kvm_vcpu_block' in data['blocked_stack'], '没有真实 HLT 等待')
            demand(len([row for row in rows if row['name'] == 'ia_run' and row['pid'] == worker['tid']]) == 1, '缺少真实 KVM_RUN')
        else:
            demand(data['before_release'] == {'worker_alive': True, 'waiters_finished': 0}, '旧操作未完成却提前排空')
            demand(statuses['pending']['active'] == 1 and statuses['pending']['state'] == 0, '开放时在途计数错误')
            demand(calls['wrong_generation']['errno'] == LINUX_ESTALE, '不同关联序号未拒绝')
            drain.safety.check_response(data['initial_response'], 42, drain.safety.PAGE, 1)
            drain.safety.check_response(data['server_response_while_sealed'], 55, drain.safety.PAGE, 1)
            srcu = [row for row in rows if row['name'] == 'ia_srcu_done' and row['pid'] == worker['tid']
                    and row['detail'].startswith('(kvm_vm_ioctl_dsm+')]
            demand(len(srcu) == 1 and srcu[0]['index'] < returns[0]['index'], 'SRCU 尚未释放')
            raw = bytes.fromhex(data['outgoing_request_hex'])
            demand(len(raw) == 4110 and drain.HEADER.unpack_from(raw)[0] == 38, '缺少真实出站请求')
            request = drain.REQUEST.unpack(raw[14:38])
            demand(request == (0, 0, 2, 2, 0, 0) and not any(raw[38:]), '出站写页请求字段不符')
            if mode != 'fault':
                expected_page = bytes((i * 7 + 11) % 256 for i in range(4096))
                demand(data['page_sha256'] == hashlib.sha256(expected_page).hexdigest(), '已准入写入内容错误')
        if mode == 'timeout':
            timeout = calls['timeout']
            demand(timeout['errno'] == LINUX_ETIMEDOUT and data['worker_alive_after_timeout'], '超时取消了原操作')
            demand(80000000 <= timeout['end_ns'] - timeout['start_ns'] <= 1000000000, '等待期限异常')
        expected_waiters = 2 if mode in ('active', 'fault') else 1
        demand(len(data['waiters']) == expected_waiters, '控制等待线程缺失')
        for waiter in data['waiters']:
            demand(waiter == calls[waiter['name']], '等待摘要不一致')
            demand(waiter['errno'] == (LINUX_EPROTO if mode == 'fault' else 0), '控制等待错误')
            done = [row for row in rows if row['pid'] == waiter['tid'] and row['name'] == 'ia_dsm_done']
            demand(len(done) == 1 and int(field(done[0], 'code')) == -waiter['errno'], '缺少控制调用真实返回')
            if mode != 'fault':
                demand(operation['leave']['index'] < done[0]['index'], '计数尚未释放就确认排空')
    if mode == 'fault':
        demand(data['after_fault_errno'] == calls['after_fault']['errno'] == LINUX_EIO, '故障后仍接受管理操作')
        failures = [row for row in rows if row['name'] == 'ia_failure' and int(field(row, 'code')) == -LINUX_EPROTO]
        demand(failures and marks['inject_fault']['index'] < failures[0]['index'] < marks['observation_complete']['index'], '首次故障证据缺失')
        for waiter in data['waiters']:
            done = next(row for row in rows if row['pid'] == waiter['tid'] and row['name'] == 'ia_dsm_done')
            demand(failures[0]['index'] < done['index'], '故障等待返回早于故障')
    else:
        demand(statuses['final']['active'] == 0 and statuses['final']['state'] == 1, '完成后仍在途或错误重开')
        demand(data['repeat_errno'] == calls['repeat']['errno'] == 0, '相同关联序号无法复核')
    return {'mode': mode, 'completed_entries': len(completed), 'rejected_entries': len(rejected),
            'ioctl_admission_verified': True, 'whole_vm_drain_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.probe.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
