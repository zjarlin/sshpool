#!/usr/bin/env python3
"""核对真实 KVM 在途请求与管理接口，不把清理时才返回的错误算作故障传播。"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


safety = load('check-request-safety')
demand = safety.demand
HEADER = struct.Struct('<QHHH')
REQUEST = struct.Struct('<BB6xQBBH4x')
BASE_PROBES = {'failure_enter', 'failure_done', 'failure_received', 'failure_root', 'failure_stop'}


def frame(payload, txid):
    return (HEADER.pack(14 + len(payload), 0, 0, txid) + payload).ljust(4110, b'\0')


def parse(data):
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪行格式损坏')
        comm, pid, cpu, timestamp, name, detail = match.groups()
        rows.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu), 'time': float(timestamp),
                     'name': name, 'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', data['trace']) ==
           [(str(len(rows)), str(len(rows)))], '跟踪头部与完整记录不一致')
    demand(all(a['time'] <= b['time'] for a, b in zip(rows, rows[1:])), '全局时间倒退')
    counts = Counter(row['name'] for row in rows)
    per_cpu = Counter(row['cpu'] for row in rows)
    demand(bool(data['trace_stats']), '缺少逐 CPU 计数')
    for name, stats in data['trace_stats'].items():
        demand(re.fullmatch(r'cpu\d+', name) is not None, 'CPU 标识非法')
        demand(re.findall(r'^entries: (\d+)$', stats, re.MULTILINE) == [str(per_cpu[int(name[3:])])], 'CPU 事件计数不符')
        for field in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + field + r': (\d+)$', stats, re.MULTILINE) == ['0'], '跟踪存在丢失')
    demand(set(per_cpu) <= {int(name[3:]) for name in data['trace_stats']}, '缺失有事件的 CPU 统计')
    profiles = {}
    for line in data['kprobe_profile'].splitlines():
        name, hits, missed = line.split()
        demand(name not in profiles and int(missed) == 0, 'kprobe 重复或漏采')
        profiles[name] = int(hits)
    wanted = BASE_PROBES | ({'failure_latch', 'failure_abort'} if data['kernel'].endswith('pf17') else set())
    demand(set(profiles) == set(data['probe_names']) == wanted, '函数探针集合不完整')
    demand(all(hits == counts[name] for name, hits in profiles.items()), '函数命中与跟踪事件数量不符')
    demand(set(counts) <= wanted | {'sched_process_exit', 'tracing_mark_write'}, '混入非实验事件')
    markers = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in markers] == [row['phase'] for row in data['events']], '双重阶段记录不同')
    demand(len(markers) == len({row['detail'] for row in markers}), '阶段重复')
    demand(all(a['time_ns'] <= b['time_ns'] for a, b in zip(data['events'], data['events'][1:])), '控制端时间倒退')
    return rows, {row['detail']: row for row in markers}


def inspect(data):
    demand(not data['errors'] and data['vm_closed'] and not data['remaining_tasks'] and
           data['trace_cleanup_complete'], '实验或清理没有完成')
    demand(data['kernel'] in ('7.1.0-rc3-sshpool-gvm-pf16', '7.1.0-rc3-sshpool-gvm-pf17'), '未知内核')
    mode = data['mode']
    demand(mode in ('complete', 'malformed', 'oversized', 'peer-eof'), '未知场景')
    rows, marks = parse(data)
    phases = ['transfer_page', 'write_begin', 'write_waiting']
    phases += ['release_response'] if mode == 'complete' else ['missing_page_sent', 'fault_begin', 'fault_observed']
    phases += ['observation_complete', 'cleanup_begin', 'cleanup_complete']
    demand(list(marks) == phases, '实验阶段缺失或乱序')
    times = {row['phase']: row['time_ns'] for row in data['events']}
    safety.check_response(data['initial_response'], 42, safety.PAGE, 1)
    outgoing = bytes.fromhex(data['outgoing_request_hex'])
    demand(len(outgoing) == 4110, '远端请求不是完整固定帧')
    length, copyset, version, txid = HEADER.unpack_from(outgoing)
    demand((length, copyset, version) == (38, 0, 0) and txid != 255 and
           outgoing == frame(REQUEST.pack(0, 0, 2, 2, 0, 0), txid), '未证明本地写入等待真正的远端 WRITE')
    demand(data['registers_before'] == 0, '故障前管理接口未成功')
    write = data['write_result']
    demand(times['write_begin'] <= write['started_ns'] <= times['write_waiting'] < write['finished_ns'], '本地调用没有跨越等待窗口')
    snapshot = data['initial_tasks'] if mode == 'complete' else data['all_tasks']
    expected_threads = 9 if mode == 'complete' else 17
    identities = {int(pid): value['name'] for pid, value in snapshot.items()}
    demand(len(identities) == expected_threads and set(identities.values()) ==
           {'kvm-dsm/0'} | {f'dsm-conn/0:{i}' for i in range(expected_threads - 1)}, '线程集合不完整')
    for pid, before in data['initial_tasks'].items():
        after = snapshot.get(pid)
        demand(after is not None and before['name'] == after['name'] and
               before['stat'].rsplit(')', 1)[1].split()[19] == after['stat'].rsplit(')', 1)[1].split()[19], '线程被替换')
    roots = [pid for pid, name in identities.items() if name == 'kvm-dsm/0']
    root = roots[0]
    workers = set(identities) - {root}
    for name in ('failure_enter', 'failure_done'):
        selected = safety.select(rows, name)
        demand(len(selected) == len(workers) and {row['pid'] for row in selected} == workers, '处理线程入口或返回缺失')
    exits = safety.select(rows, 'sched_process_exit')
    demand(len(exits) == expected_threads and {row['pid'] for row in exits} == set(identities), '线程退出缺失或重复')
    for row in exits:
        demand(row['comm'] == identities[row['pid']] and
               f"comm={row['comm']} pid={row['pid']} " in row['detail'], '退出线程身份不符')
    root_done = safety.one(rows, 'failure_root', root)
    demand(exits[-1]['pid'] == root and root_done['index'] < exits[-1]['index'], '根线程退出次序错误')
    for pid in workers:
        start = safety.one(rows, 'failure_enter', pid)
        done = safety.one(rows, 'failure_done', pid)
        exited = safety.one(rows, 'sched_process_exit', pid)
        demand(start['index'] < done['index'] < exited['index'] < root_done['index'], '处理线程生命周期不完整')
    stops = safety.select(rows, 'failure_stop')
    demand(len(stops) == 2 and all(row['index'] > marks['cleanup_begin']['index'] for row in stops), '探针提前关闭了 VM')
    root_code = int(safety.field(root_done, 'code'))
    if mode == 'complete':
        expected_digest = hashlib.sha256(bytes((i * 7 + 11) % 256 for i in range(4096))).hexdigest()
        demand(write['errno'] == 0 and write['return'] == 0 and data['registers_after'] == 0 and
               data['new_page_sha256'] == data['written_page_sha256'] == expected_digest and
               times['release_response'] <= write['finished_ns'] <= times['observation_complete'], '正常取页或写入未成功')
        demand(root_done['index'] > marks['cleanup_begin']['index'], '正常响应结束前根线程退出')
        return {'outcome': 'request_completed', 'thread_exits': len(exits), 'root_exit_code': root_code,
                'normal_shutdown_accepted': False, 'trace_events': len(rows)}
    missing = bytes.fromhex(data['missing_request_hex'])
    demand(missing == frame(REQUEST.pack(1, 1, 3, 1, 0, 0), 43), '缺失页请求内容不符')
    extra = workers - {int(pid) for pid in data['initial_tasks']}
    missing_receives = [row for row in safety.select(rows, 'failure_received') if row['pid'] in extra and
                        safety.field(row, 'code') == '24' and safety.between(row, marks['missing_page_sent'], marks['fault_begin'])]
    demand(len(missing_receives) == 1, '故障前未证明确实收到缺失页请求')
    expected_code = {'malformed': -71, 'oversized': -90, 'peer-eof': -104}[mode]
    if mode != 'peer-eof':
        expected_frame = frame(REQUEST.pack(1, 1, 2, 255, 0, 0), 44) if mode == 'malformed' else frame(bytes(4096), 44)
        demand(bytes.fromhex(data['fault_frame_hex']) == expected_frame, '注入的异常帧错误')
    observed_done = [row for row in safety.select(rows, 'failure_done') if safety.between(row, marks['fault_begin'], marks['fault_observed'])]
    demand(any(int(safety.field(row, 'code')) == expected_code for row in observed_done), '观察窗口内没有真实故障返回')
    if data['write_pending_after_fault']:
        demand(data['tasks_after_fault'] and data['registers_after'] == 0 and
               data.get('run_errno') is None and data.get('vm_ioctl_errno') is None and
               write['finished_ns'] > times['cleanup_begin'] and root_done['index'] > marks['cleanup_begin']['index'] and
               data['second_after_fault']['state'] == data['outgoing_after_fault']['state'] == 'waiting',
               '基线挂起缺少未完成调用与清理后才退出的证据')
        outcome = 'request_still_waiting'
        elapsed = None
    else:
        demand(not data['tasks_after_fault'] and data['registers_after'] == data['run_errno'] == data['vm_ioctl_errno'] == 5,
               'KVM 管理层未拒绝故障 VM')
        demand(write['errno'] == -expected_code and 'return' not in write and
               times['fault_begin'] < write['finished_ns'] < times['fault_observed'], '在途调用没有在清理前返回原始错误')
        elapsed = write['finished_ns'] - times['fault_begin']
        demand(elapsed < 500000000, '故障传播超过五百毫秒')
        demand(all(row['index'] < marks['fault_observed']['index'] for row in exits) and root_code == expected_code,
               '全部线程未在清理前退出或根线程丢失首次错误')
        for name in ('peer_after_fault', 'second_after_fault', 'outgoing_after_fault'):
            state = data[name]
            allowed = {'eof', 'error'} | ({'closed_by_probe'} if mode == 'peer-eof' and name == 'peer_after_fault' else set())
            demand(state['state'] in allowed, '失败连接没有通知对端')
            if state['state'] == 'error':
                demand(state['errno'] in (32, 104), '连接异常不是关闭或复位')
        latched = safety.select(rows, 'failure_latch')
        demand(latched and int(safety.field(latched[0], 'code')) == expected_code and
               safety.between(latched[0], marks['fault_begin'], root_done), '首次失败没有明确锁存边界')
        demand(len({safety.field(row, 'kvm') for row in latched}) == 1, '混入其他 KVM 实例')
        outcome = 'failure_propagated'
    return {'outcome': outcome, 'fault_code': expected_code, 'write_failure_latency_ns': elapsed,
            'root_exit_code': root_code, 'thread_exits': len(exits), 'trace_events': len(rows),
            'normal_shutdown_accepted': False}


def expand_log(record):
    """重复错误按行无损压缩；先核对大小再展开，避免缺行或篡改重复次数。"""
    demand(record['encoding'] == 'line-rle-v1', '未知日志编码')
    size = 0
    for line, count in record['runs']:
        demand(isinstance(line, str) and type(count) is int and count > 0, '日志重复次数非法')
        size += len(line.encode()) * count
    demand(size == record['decoded_utf8_bytes'] and size <= 16 * 1024 * 1024, '日志长度不符或超过核查容量')
    text = ''.join(line * count for line, count in record['runs'])
    demand(hashlib.sha256(text.encode()).hexdigest() == record['decoded_sha256'], '完整日志校验失败')
    return text


def inspect_workspace_fault(data):
    """区分双 KVM 收到故障与 QEMU 可控退出；失败退出不等于正常关机。"""
    result = data['result']
    demand(data['mode'] == 'fault' and result.get('fault_sent') is True, '缺少真实双节点注入')
    demand(result['phases'].get('inject-failure', {}).get('exit') == 0, '注入命令失败')
    injected = json.loads(data['injection_log'])
    demand(bytes.fromhex(injected['frame_hex']) == frame(REQUEST.pack(1, 1, 2, 255, 0, 0), 65000), '注入帧内容不符')
    demand(injected['result'] in ('eof', 'error'), '注入连接未失败')
    if injected['result'] == 'error':
        demand(injected['errno'] in (32, 104), '注入连接没有因关闭或复位结束')
    demand(not any(result.get(key) for key in ('management_timeout', 'harness_error', 'samples_errors', 'host_log_timeout')),
           '管理或采样过程没有完整结束')
    demand(not any('poweroff' in name for name in result['phases']), '故障结果混入操作者关机')
    exits = result['qemu_ssh_exits']
    demand(len(exits) == 2 and all(code not in (None, 0) for code in exits), '未记录两端失败退出')
    hosts = data['host_logs']
    logs = [expand_log(record) for record in data['qemu_stderr']]
    demand(len(hosts) == len(logs) == 2, '缺少某端日志')
    demand('node-0 failed with -71' in hosts[0] and 'node-1 failed with -104' in hosts[1], '两端首次错误不符')
    demand(all(re.search(r'error: kvm run failed (?:Input/output error|Connection reset by peer|Protocol error)', text)
               for text in logs), '没有两端 KVM_RUN 错误')
    failure_text = '\n'.join(hosts + logs)
    crashed = bool(re.search(r'segfault|segmentation fault|dumped core', failure_text, re.IGNORECASE))
    sync_failures = [text.count('Failed to synchronize CPU state') for text in logs]
    forced = bool(re.search(r'HARNESS_TIMEOUT|terminating on signal|Killed|timed out', failure_text, re.IGNORECASE))
    controlled = (exits == [1, 1] and not crashed and not any(sync_failures) and not forced and
                  all(text.count('Distributed KVM failure; terminating this node') == 1 for text in logs))
    return {'failure_reached_qemu': True, 'controlled_failure_exit': controlled,
            'crash_detected': crashed, 'synchronization_errors': sync_failures,
            'normal_shutdown_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--expect', choices=['failure_propagated', 'request_completed', 'request_still_waiting'], default='failure_propagated')
    parser.add_argument('--workspace-fault', action='store_true', help='核对单份双节点故障记录并要求可控失败退出')
    args = parser.parse_args()
    data = json.loads(args.record.read_text())
    if args.workspace_fault:
        report = inspect_workspace_fault(data)
        demand(report['controlled_failure_exit'], '故障已传播但 QEMU 未可控退出')
    else:
        report = inspect(data)
        demand(report['outcome'] == args.expect, '实际结果与指定预期不同')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
