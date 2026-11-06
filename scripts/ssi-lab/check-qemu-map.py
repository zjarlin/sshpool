#!/usr/bin/env python3
"""核对真实 QEMU 映射调用、KVM 返回与进程退出，不把失败停止当作完整关闭。"""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('pins', Path(__file__).with_name('check-pins.py'))
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)
demand, field = pins.demand, pins.field
PIN, STATUS, SEAL = pins.PIN, pins.STATUS, pins.SEAL


def inspect(data):
    run, record = data['run'], data['record']
    node, mode = run['node'], run['mode']
    baseline = run['variant'] == 'baseline-fixed'
    demand(node in (0, 1) and mode in range(5), '场景错误')
    demand(run['variant'] in ('baseline-fixed', 'candidate-probe'), '未知运行时')
    demand(record['kernel'] == '7.1.0-rc3-sshpool-gvm-pf24', '内核错误')
    demand(run['qemu_sha256'] == record['qemu_sha256'] and run['pid'] == record['pid'] and record['mode'] == mode, '运行身份不一致')
    demand(not run['errors'] and run['probe_exit'] == 0 and not record['errors'] and
           not record['qemu_remaining'] and record['trace_cleanup_complete'], '执行或清理不完整')
    demand(record['status'] == {'status': 'prelaunch', 'running': False} or
           record['status'] == {'status': 'paused', 'running': False}, '不是暂停实例')
    demand(record['command_return'] is None and record['command_transport'] in
           ({'kind': 'eof'}, {'kind': 'reset', 'errno': 104}), '没有诊断退出造成的 QMP 关闭')
    expected_exit = 0 if baseline or mode == 0 else 1
    demand(run['qemu_ssh_exits'][node] == expected_exit and
           len(run['qemu_ssh_exits']) == 2 and all(type(code) is int and code in (0, 1)
                                                for code in run['qemu_ssh_exits']), '进程退出不符')

    rows = []
    for line in record['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = pins.drain.safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪行损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        rows.append({'pid': int(pid), 'cpu': int(cpu), 'time': float(timestamp), 'name': name, 'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', record['trace']) == [(str(len(rows)), str(len(rows)))], '跟踪计数不符')
    demand(all(a['time'] <= b['time'] for a, b in zip(rows, rows[1:])), '跟踪时间倒退')
    per_cpu, counts = Counter(r['cpu'] for r in rows), Counter(r['name'] for r in rows)
    demand(bool(record['trace_stats']), '缺少 CPU 统计')
    for name, stats in record['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', name) is not None, 'CPU 统计名错误')
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(per_cpu[int(name[3:])])], 'CPU 记录计数错误')
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.M) == ['0'], '跟踪丢失')
    demand(set(per_cpu) <= {int(name[3:]) for name in record['trace_stats']}, '遗漏 CPU 统计')
    profiles = {}
    for line in record['kprobe_profile'].splitlines():
        name, hit, missed = line.split()
        demand(name not in profiles and int(missed) == 0, '探针重复或漏采')
        profiles[name] = int(hit)
    demand(set(profiles) == {'qm_enter', 'qm_return'} and
           all(counts[n] == count for n, count in profiles.items()), '探针计数不符')
    marks = [r for r in rows if r['name'] == 'tracing_mark_write']
    phases = ['case_begin', 'command_ended', 'process_ended']
    demand([r['detail'] for r in marks] == phases == [r['phase'] for r in record['events']], '阶段不完整')
    demand(all(a['time_ns'] < b['time_ns'] for a, b in zip(record['events'], record['events'][1:])), '用户态时间倒退')
    active, calls = None, []
    for row in rows:
        if row['name'] == 'tracing_mark_write':
            continue
        demand(row['pid'] == record['pid'] and marks[0]['index'] < row['index'] < marks[1]['index'], '非本次真实主线程调用')
        if row['name'] == 'qm_enter':
            demand(active is None, '入口嵌套')
            active = {'ioctl': int(field(row, 'ioctl'), 16), 'enter': row}
        elif row['name'] == 'qm_return':
            demand(active is not None, '缺少入口')
            active['ret'] = int(field(row, 'code'))
            calls.append(active)
            active = None
        else:
            demand(False, '未知事件')
    demand(active is None, '调用没有完整返回')
    expected = [(STATUS, 0)]
    if mode in (1, 2):
        expected += [(SEAL, 0), (PIN, -108)]
    else:
        expected += [(PIN, 0), (STATUS, 0)]
        if mode in (3, 4):
            expected += [(PIN, 0), (STATUS, 0)]
        expected += [(PIN, -22 if mode in (3, 4) else 0)]
    if baseline or mode == 0:
        expected += [(STATUS, 0)]
    demand([(c['ioctl'], c['ret']) for c in calls] == expected, '真实 ioctl 顺序或返回错误')
    pin_calls = [c for c in calls if c['ioctl'] == PIN]
    write, length = mode in (2, 4), 8192 if mode in (2, 4) else 4096
    addresses = set()
    for index, call in enumerate(pin_calls):
        row = call['enter']
        demand(int(field(row, 'write')) == write and int(field(row, 'unpin')) == (index > 0) and
               int(field(row, 'length')) == length, '内核采集的固定参数错误')
        addresses.add(int(field(row, 'hva'), 16))
    demand(len(addresses) == 1 and next(iter(addresses)) > 0 and next(iter(addresses)) % 4096 == 0, '固定与解除地址不一致')

    log = data['qemu_stderr'][node]
    emitted = [json.loads(line.removeprefix('SSI_MAP ')) for line in log.splitlines() if line.startswith('SSI_MAP ')]
    names = ['begin', 'initial_status']
    if mode in (1, 2):
        names += ['seal']
    if baseline or mode not in (1, 2):
        names += ['map_return']
    if mode not in (1, 2):
        names += ['mapped_status']
        if mode in (3, 4):
            names += ['consume_pin', 'consumed_status']
        if baseline or mode == 0:
            names += ['unmap_return']
    if baseline or mode == 0:
        names += ['final_status']
    names += ['exit']
    demand([r['phase'] for r in emitted] == names, 'QEMU 控制流不符')
    events = {r['phase']: r for r in emitted}
    before = events['begin']['owner_before']
    demand(before > 0 and events['begin']['mode'] == mode and events['begin']['write'] == write and
           events['begin']['pid'] == record['pid'], 'QEMU 初始身份错误')
    for name in ('initial_status', 'mapped_status', 'consumed_status', 'final_status'):
        if name not in events:
            continue
        refs = length // 4096 if name == 'mapped_status' else 0
        demand(events[name] == {'phase': name, 'ret': 0, 'version': 1, 'active_ops': 0,
                               'read_refs': 0 if write else refs, 'write_refs': refs if write else 0,
                               'error': 0, 'reserved': 0}, 'QEMU 查询引用不符')
    for name in ('seal', 'consume_pin'):
        if name in events:
            demand(events[name] == {'phase': name, 'ret': 0}, '故障准备没有成功')
    if 'map_return' in events:
        demand(events['map_return'] == {'phase': 'map_return', 'pointer': True, 'length': length,
                                        'dsm': True, 'owner_after': before + 1}, '返回映射或引用不符')
    if 'unmap_return' in events:
        demand(events['unmap_return'] == {'phase': 'unmap_return', 'owner_after': before}, '解除后的引用不符')
    demand(events['exit'] == {'phase': 'exit', 'mode': mode, 'returned': baseline or mode == 0,
                              'owner_before': before, 'owner_after': before}, '引用不平衡或失败路径返回给调用者')
    if mode != 0:
        error = -108 if mode in (1, 2) else -22
        phrase = f'KVM_DSM_MEMPIN failed {error}' if baseline else (
            f'Distributed DSM {"map pin" if mode in (1, 2) else "unmap unpin"} failed ({error}); terminating this node')
        demand(log.count(phrase) == 1, '缺少实际映射错误')
    demand(not re.search(r'segmentation fault|segfault|dumped core|terminating on signal', '\n'.join(data['qemu_stderr']), re.I), '不是预期失败退出')
    return {'mode': mode, 'baseline': baseline, 'native_calls': len(calls), 'trace_events': len(rows),
            'unsafe_return_reproduced': baseline and mode != 0,
            'local_failure_stop_verified': not baseline and mode != 0,
            'mapping_reference_balance_verified': True, 'whole_vm_shutdown_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
    except (ValueError, KeyError, TypeError, IndexError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
