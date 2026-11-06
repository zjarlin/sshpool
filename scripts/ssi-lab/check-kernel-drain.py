#!/usr/bin/env python3
"""重放入站 DSM 屏障的真实响应与内核锁释放顺序，明确保留整机关闭缺口。"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

spec = importlib.util.spec_from_file_location('safety', Path(__file__).with_name('check-request-safety.py'))
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)
demand = safety.demand
field = safety.field
HEADER = struct.Struct('<QHHH')
REQUEST = struct.Struct('<BB6xQBBH4x')
ACK = struct.Struct('<IIHHIQ')
PROBES = {'kd_send', 'kd_sent', 'kd_received', 'kd_lock', 'kd_locked', 'kd_unlocked',
          'kd_srcu_done', 'kd_failure', 'kd_handler_done', 'kd_root_done'}


def parse(data):
    rows = []
    for line in data['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = safety.teardown.EVENT.fullmatch(line)
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
    demand(set(profiles) == PROBES and set(counts) <= PROBES | {'tracing_mark_write'}, '探针集合错误')
    for name, hits in profiles.items():
        # 这两个探针按服务线程过滤；原始命中数包含被过滤的其他调用。
        demand(hits >= counts[name] if name in ('kd_srcu_done', 'kd_unlocked') else hits == counts[name], '探针计数不符')
    marks = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in marks] == [row['phase'] for row in data['events']], '双重阶段记录不一致')
    demand(len(marks) == len({row['detail'] for row in marks}), '阶段重复')
    demand(all(a['time_ns'] < b['time_ns'] for a, b in zip(data['events'], data['events'][1:])), '阶段时间倒退')
    return rows, {row['detail']: row for row in marks}


def frame(payload, txid):
    return (HEADER.pack(14 + len(payload), 0, 0, txid) + payload).ljust(4110, b'\0')


def inspect(data, host):
    demand(data['kernel'] in ('7.1.0-rc3-sshpool-gvm-pf18', '7.1.0-rc3-sshpool-gvm-pf19'), '不是 PF18/PF19')
    demand(not data['errors'] and not data['remaining_tasks'] and data['trace_cleanup_complete'], '实验或清理未完成')
    mode = data['mode']
    demand(mode in ('idle', 'active', 'lock', 'timeout', 'fault', 'version', 'generation', 'duplicate', 'late', 'partial', 'prefix'), '未知场景')
    rows, marks = parse(data)
    pending = 7 if mode == 'active' else int(mode in ('lock', 'timeout', 'fault'))
    phases = ['case_begin', 'marker_sent'] + (['requests_received'] if pending else [])
    phases += {'active': ['register_pages'], 'lock': ['release_remote_response'], 'fault': ['inject_fault'],
               'partial': ['close_partial_vm']}.get(mode, [])
    success = mode in ('idle', 'active', 'lock', 'duplicate', 'late')
    if success:
        phases.append('ack_observed')
    if mode in ('duplicate', 'late'):
        phases.append('inject_late_frame')
    if mode in ('timeout', 'fault', 'version', 'generation', 'duplicate', 'late', 'prefix'):
        phases.append('failure_observed')
    phases += ['observation_complete', 'cleanup_begin', 'cleanup_complete']
    demand(list(marks) == phases, '阶段缺失或乱序')
    times = {item['phase']: item['time_ns'] for item in data['events']}
    snapshot = data.get('all_tasks', data['initial_tasks'])
    ids = {int(pid): item['name'] for pid, item in snapshot.items()}
    worker_count = 16 if mode == 'lock' else 8
    demand(set(ids.values()) == {'kvm-dsm/0'} | {f'dsm-conn/0:{i}' for i in range(worker_count)}, '线程身份不完整')
    demand(len(ids) == worker_count + 1, '线程身份重复')
    if mode == 'fault':
        fault_ids = {int(pid): item['name'] for pid, item in data.get('fault_tasks', {}).items()}
        demand(set(fault_ids.values()) == {'kvm-dsm/0'} | {f'dsm-conn/0:{i}' for i in range(16)}, '故障注入前的处理器就绪证据缺失')
        demand(all(any('ivy_kvm_dsm_handle_req' in line for line in item['stack'])
                   for item in data['fault_tasks'].values() if item['name'].startswith('dsm-conn/')), '故障处理器尚未进入等待')
    handlers = [row for row in rows if row['name'] == 'kd_handler_done']
    roots = [row for row in rows if row['name'] == 'kd_root_done']
    extra = 8 if mode == 'fault' else 0
    demand(len(handlers) == len({row['pid'] for row in handlers}) == worker_count + extra, '处理器未全部退出')
    demand(len(roots) == 1 and ids.get(roots[0]['pid']) == 'kvm-dsm/0', '根线程退出缺失')
    demand(all(row['index'] < roots[0]['index'] for row in handlers), '根线程先于处理器退出')
    window = [row for row in rows if marks['case_begin']['index'] < row['index'] < marks['observation_complete']['index']]
    sends = [row for row in window if row['name'] == 'kd_send']
    ack_sends = [row for row in sends if field(row, 'length') == '24' and row['comm'].startswith('dsm-conn/')]
    demand(len(ack_sends) == int(success), '确认缺失或提前出现')
    generation = data['generation']
    demand(0 < generation < 2 ** 64, '关联序号无效')
    requests = []
    if mode == 'lock':
        requests.append(frame(REQUEST.pack(1, 1, 2, 1, 0, 0), 42))
    requests += [frame(REQUEST.pack(1, 1, 2 + index, 1, 0, 0), 42 + index) for index in range(pending)]
    marker = frame(REQUEST.pack(1, 1, 0 if mode == 'generation' else generation, 3, 0, 2 if mode == 'version' else 1), 100)
    if mode == 'prefix':
        requests.append(frame(REQUEST.pack(1, 1, 2, 255, 0, 0), 99) + marker)
    elif mode == 'partial':
        requests.append(marker[:8])
    else:
        requests.append(marker)
    if mode in ('duplicate', 'late', 'fault'):
        requests.append(marker if mode == 'duplicate' else frame(REQUEST.pack(1, 1, 2, 255 if mode == 'fault' else 1, 0, 0), 101))
    demand(data['requests'] == [value.hex() for value in requests], '实际注入帧与场景不符')
    if pending or mode == 'partial':
        silence = data['silence']
        demand(not silence['readable'] and silence['end_ns'] - silence['start_ns'] >= 450000000, '等待窗口不足或过早响应')
        demand(times['marker_sent'] <= silence['start_ns'] < silence['end_ns'] < times['observation_complete'], '等待窗口不在实验内')
    if success:
        expected = ACK.pack(0x44534d44, 1, 0, 1, 0, generation)
        safety.check_response(data['responses'][-1], 100, expected, 0)
        demand(data['ack_fields'] == list(ACK.unpack(expected)), '确认摘要与原始帧不符')
        ack = ack_sends[0]
        demand(ids.get(ack['pid'], '').startswith('dsm-conn/'), '确认由未知线程发出')
        returned = [row for row in window if row['pid'] == ack['pid'] and row['name'] == 'kd_sent' and row['index'] > ack['index']]
        demand(returned and field(returned[0], 'code') == '38' and returned[0]['index'] < marks['ack_observed']['index'], '确认发送未完成')
        payload = bytes((i * 7 + 11) % 256 for i in range(4096)) if mode == 'lock' else safety.PAGE
        version = int(mode == 'lock')
        received = data['responses'][:-1]
        demand(len(received) == pending and {row['txid'] for row in received} == set(range(42, 42 + pending)), '页面事务缺失或重复')
        for value in received:
            raw = bytes.fromhex(value['hex'])
            demand(HEADER.unpack_from(raw) == (4110, 1, version, value['txid']) and raw[14:] == payload, '页面内容或事务版本错误')
            demand((value['length'], value['copyset'], value['version']) == (4110, 1, version) and
                   value['payload_sha256'] == hashlib.sha256(payload).hexdigest(), '页面摘要错误')
            demand(value['received_ns'] < data['responses'][-1]['received_ns'], '确认先于页面响应')
        page_sends = [row for row in sends if field(row, 'length') == '4096' and field(row, 'cb') == field(ack, 'cb')]
        demand(len(page_sends) == pending and len({row['pid'] for row in page_sends}) == pending, '并发页面处理数不符')
        for sent in page_sends:
            done = next((row for row in window if row['pid'] == sent['pid'] and row['name'] == 'kd_sent' and row['index'] > sent['index']), None)
            demand(done is not None and field(done, 'code') == '4110', '页面响应发送失败')
            unlocked = next((row for row in window if row['pid'] == sent['pid'] and row['name'] == 'kd_unlocked' and row['index'] > done['index']), None)
            demand(unlocked is not None, '页锁未释放')
            srcu = next((row for row in window if row['pid'] == sent['pid'] and row['name'] == 'kd_srcu_done' and
                         row['index'] > unlocked['index'] and '(ivy_kvm_dsm_handle_req+' in row['detail']), None)
            demand(srcu is not None and srcu['index'] < ack['index'], '确认早于真实 DSM SRCU 释放')
        if pending:
            release = marks['release_remote_response' if mode == 'lock' else 'register_pages']
            demand(all(row['index'] > release['index'] for row in sends), '释放等待条件前发出响应')
        if mode == 'lock':
            safety.check_response(data['initial_response'], 42, safety.PAGE, 1)
            demand(data['write_result']['errno'] == 0 and data['expected_page_sha256'] == hashlib.sha256(payload).hexdigest(), '持锁写入未成功')
            locks = [row for row in window if row['name'] == 'kd_lock']
            locked = [row for row in window if row['name'] == 'kd_locked']
            demand(len(locks) == len(locked) == 1 and locks[0]['pid'] == locked[0]['pid'] and
                   locks[0]['index'] < release['index'] < locked[0]['index'] and field(locked[0], 'code') == '0', '未证明页面锁等待跨越释放时刻')
    else:
        demand(not data['responses'], '失败场景产生了确认或页面响应')
    failures = [row for row in window if row['name'] == 'kd_failure']
    if 'failure_observed' in marks:
        expected = -110 if mode == 'timeout' else -71
        demand(failures and int(field(failures[0], 'code')) == expected, '首个错误被覆盖或缺失')
        demand(data['expected_failure'] == expected and data['management_errno'] == 5, '错误未传播至管理层')
        demand(not data['tasks_before_cleanup'] and roots[0]['index'] < marks['failure_observed']['index'], '错误只在清理后发生')
        demand(re.search(r'failed with ' + str(expected) + r'; VM cannot continue', host) is not None, '宿主未记录首个故障')
        if mode == 'timeout':
            elapsed = times['failure_observed'] - times['marker_sent']
            demand(4800000000 <= elapsed <= 7500000000, '等待期限不符')
    else:
        demand(not failures, '正常观察阶段发生了故障')
        if mode != 'partial':
            demand(data['management_capability'] == 1, '排空确认后管理接口失效')
        else:
            demand(not data['tasks_before_cleanup'] and roots[0]['index'] < marks['observation_complete']['index'], '半帧等待不能取消')
    begins = re.findall(r'DSM_DRAIN_BEGIN node=(\d+) peer=(\d+) generation=(\d+) active=(\d+)', host)
    acks = re.findall(r'DSM_DRAIN_ACK node=(\d+) peer=(\d+) generation=(\d+) active=(\d+)', host)
    if mode == 'prefix':
        # 缓冲中的标记仍可能被读到；必须先锁存坏帧错误，并且绝不发送确认。
        received = [row for row in window if row['name'] == 'kd_received' and field(row, 'code') == '24']
        demand(len(received) in (1, 2) and received[0]['index'] < failures[0]['index'], '坏帧接收与故障顺序错误')
        expected_begins = []
        if len(received) == 2:
            demand(failures[0]['index'] < received[1]['index'], '后续标记越过坏帧故障')
            expected_begins = [('0', '1', str(generation), '0')]
            demand(host.index('failed with -71; VM cannot continue') < host.index('DSM_DRAIN_BEGIN'), '宿主日志未证明故障先锁存')
        demand(begins == expected_begins, '坏帧后的标记观察不符')
    else:
        demand(begins == ([] if mode in ('version', 'generation', 'partial') else [('0', '1', str(generation), str(pending))]), '实际屏障计数不符')
    demand(acks == ([('0', '1', str(generation), '0')] if success else []), '宿主确认计数不符')
    return {'mode': mode, 'inbound_stream_gate_passed': True, 'pending_requests': pending,
            'acknowledged': success, 'full_vm_shutdown_accepted': False, 'persistent_io_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('host', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.record.read_text()), args.host.read_text()), indent=2))


if __name__ == '__main__':
    main()
