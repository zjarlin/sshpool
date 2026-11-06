#!/usr/bin/env python3
"""复核出站事务及缓存的真实内核事件，拒绝把本地零计数解释为集群终止。"""
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
PROBES = {'ex_begin', 'ex_began', 'ex_done', 'ex_finished', 'ex_register', 'ex_registered',
          'ex_retire', 'ex_retired', 'ex_receive', 'ex_received', 'ex_cache', 'ex_cached',
          'ex_inbound', 'ex_failure'}


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
    demand(data['kernel'] in ('7.1.0-rc3-sshpool-gvm-pf21', '7.1.0-rc3-sshpool-gvm-pf22'), '错误内核')
    demand(not data['errors'] and not data['remaining_tasks'] and data['trace_cleanup_complete'], '实验或清理失败')
    rows, marks = parse(data)
    mode = data['mode']
    demand(mode in ('external', 'reverse', 'unknown', 'duplicate', 'partial-cancel', 'connect-fault'), '未知场景')
    phases = ['case_begin']
    if mode != 'connect-fault':
        phases.append('pending_observed')
    phases += {'reverse': ['cached_observed'], 'partial-cancel': ['cancel_partial']}.get(mode, [])
    phases += ['observation_complete', 'cleanup_begin', 'cleanup_complete']
    demand(list(marks) == phases, '阶段缺失或乱序')
    pending = 1 if mode in ('external', 'connect-fault') else 2
    for status in data['statuses']:
        values = (1, status['exchanges'], status['cached'], status['inbound'], 0, 0, 0, 0)
        demand(struct.unpack('=IIIIiIII', bytes.fromhex(status['hex'])) == values, '状态与原始 ABI 不符')
        demand(status['version'] == 1 and status['error'] == 0 and status['reserved'] == [0, 0, 0], '状态元数据错误')
    statuses = {row['name']: row for row in data['statuses']}
    expected_statuses = {'initial'}
    if mode != 'connect-fault':
        expected_statuses.add('pending')
    if mode == 'reverse':
        expected_statuses.add('cached')
    if mode in ('external', 'reverse'):
        expected_statuses.add('final')
    demand(set(statuses) == expected_statuses, '状态阶段缺失或混入其他场景')
    demand(all(a['time_ns'] < b['time_ns'] for a, b in zip(data['statuses'], data['statuses'][1:])), '状态时间倒退')
    phase_times = {row['phase']: row['time_ns'] for row in data['events']}
    demand(statuses['initial']['time_ns'] < phase_times['case_begin'], '初始快照不在操作之前')
    for name, phase in [('pending', 'pending_observed'), ('cached', 'cached_observed'), ('final', 'observation_complete')]:
        if name in statuses:
            demand(phase_times['case_begin'] < statuses[name]['time_ns'] < phase_times[phase], '快照与阶段时间不符')
    def count(name, expected):
        row = statuses[name]
        demand((row['exchanges'], row['cached'], row['inbound']) == expected, '在途或缓存计数错误: ' + name)
    count('initial', (0, 0, 0))
    if mode != 'external':
        sealed = struct.unpack('=IIQIiII', bytes.fromhex(data['ioctl_status_after_seal']))
        demand(sealed == (1, 1, 0x534449002020, 0, 0, 0, 0), '反向请求未在已封闭的 ioctl 入口下运行')
    if mode != 'connect-fault':
        count('pending', (pending, 0, 0 if mode == 'external' else pending))
    if mode == 'reverse':
        count('cached', (2, 1, 2))
    if mode in ('external', 'reverse'):
        count('final', (0, 0, 0))
    else:
        demand(data['tasks_before_cleanup'] == {}, '故障或取消未在清理前回收线程')
        if mode != 'partial-cancel':
            demand(data['management_errno'] == 5, '真实故障后 VM 仍接受管理调用')
    expected_requests = [drain.frame(drain.REQUEST.pack(1, 1, 2 + index, 1, 0, 0), 42 + index) for index in range(2)]
    if mode != 'external':
        expected_requests += [drain.frame(drain.REQUEST.pack(2, 2, 2 + index, 1, 0, 0), 100 + index) for index in range(pending)]
    demand(data['requests'] == [value.hex() for value in expected_requests], '实际入站请求与场景不符')
    responses = data['responses']
    demand(len(responses) == (4 if mode == 'reverse' else 2), '页面响应数量不符')
    for index, response in enumerate(responses[:2]):
        drain.safety.check_response(response, 42 + index, drain.safety.PAGE, 1)
    if mode == 'reverse':
        demand({row['txid'] for row in responses[2:]} == {100, 101}, '转发响应的事务编号不正确')
        for response in responses[2:]:
            drain.safety.check_response(response, response['txid'], drain.safety.PAGE, 1)
    requests = []
    for item in data['outgoing_requests']:
        raw = bytes.fromhex(item)
        demand(len(raw) == 4110 and not any(raw[38:]), '出站帧尺寸或尾部错误')
        header = drain.HEADER.unpack_from(raw)
        body = drain.REQUEST.unpack(raw[14:38])
        demand(header[:3] == (38, 0, 0) and header[3] != 255, '出站事务头错误')
        demand(body == (0, 0 if mode == 'external' else 2, body[2], 2 if mode == 'external' else 1, 0, 0), '反向取页字段错误')
        requests.append((header[3], body[2]))
    demand(len(requests) == (0 if mode == 'connect-fault' else pending), '出站请求缺失')
    ids = {item[0] for item in requests}
    demand(len(ids) == len(requests), '同连接的活跃事务编号冲突')
    if requests:
        demand({item[1] for item in requests} == set(range(2, 2 + pending)), '页号不匹配')
    def frame(txid):
        return (drain.HEADER.pack(4110, 1, 0, txid) + drain.safety.PAGE)
    if mode in ('reverse', 'duplicate'):
        own, other = data['held_txid'], data['cached_txid']
        demand({own, other} == ids and own != other, '没有选择另一真实在途事务的响应')
        held = data['partial_reader_pid']
        stack = data['partial_reader_tasks'][str(held)]['stack']
        demand(any('tcp_recvmsg' in line for line in stack) and any('kvm_dsm_fetch' in line for line in stack), '没有真实半帧等待栈')
        reader = [row for row in rows if row['pid'] == held and row['name'] == 'ex_receive' and field(row, 'txid') != '255']
        demand(len(reader) == 1 and int(field(reader[0], 'txid')) == own, '半帧读者与事务编号未对应')
        expected = [struct.pack('<Q', 4110), frame(other)[8:] + (frame(own)[:8] if mode == 'reverse' else frame(other))]
        if mode == 'reverse':
            expected.append(frame(own)[8:])
    else:
        expected = {'external': [frame(next(iter(ids)))] if ids else [],
                    'unknown': [frame(50000)], 'partial-cancel': [struct.pack('<Q', 4110)], 'connect-fault': []}[mode]
    demand(data['injected'] == [value.hex() for value in expected], '实际注入字节与期望不符')
    if mode == 'external':
        demand(data['worker']['errno'] == 0, '写入失败')
        payload = bytes((i * 7 + 11) % 256 for i in range(4096))
        demand(data['page_sha256'] == hashlib.sha256(payload).hexdigest(), '写入内容错误')
    window = [row for row in rows if marks['case_begin']['index'] < row['index'] < marks['observation_complete']['index']]
    starts = [row for row in window if row['name'] == 'ex_begin']
    demand(len(starts) == pending and len({row['pid'] for row in starts}) == pending, '出站生命周期入口不完整')
    for name in ('ex_begin', 'ex_began', 'ex_done', 'ex_finished'):
        demand(sum(row['name'] == name for row in rows) == pending, '事务生命周期未在观察结束前完成')
    for start in starts:
        events = [row for row in window if row['pid'] == start['pid']]
        def one(name):
            found = [row for row in events if row['name'] == name]
            demand(len(found) == 1, '事务事件缺失或重复: ' + name)
            return found[0]
        begun, done, finished = one('ex_began'), one('ex_done'), one('ex_finished')
        demand(int(field(begun, 'code')) == 0 and start['index'] < begun['index'] < done['index'] < finished['index'], '生命周期计数顺序错误')
        if mode == 'connect-fault':
            demand(not any(row['name'] == 'ex_register' for row in events), '建连失败却已登记响应事务')
            continue
        registered, retired = one('ex_registered'), one('ex_retired')
        demand(int(field(registered, 'code')) == 0, '事务登记失败')
        outgoing = [row for row in events if row['name'] == 'ex_receive' and field(row, 'txid') != '255']
        demand(len(outgoing) == 1, '出站接收入口缺失')
        rx = outgoing[0]
        returns = [row for row in events if row['name'] == 'ex_received' and rx['index'] < row['index'] < one('ex_retire')['index']]
        demand(len(returns) == 1, '出站接收没有唯一完成')
        code = int(field(returns[0], 'code'))
        demand(code in (-4, -32) if mode == 'partial-cancel' else code == (-71 if mode in ('unknown', 'duplicate') else 4096), '响应返回错误')
        demand(begun['index'] < one('ex_register')['index'] < registered['index'] < rx['index'] < returns[0]['index'] < one('ex_retire')['index'] < retired['index'] < done['index'], '事务未完整结束就减少出站计数')
        demand(int(field(rx, 'txid')) == int(field(one('ex_retire'), 'txid')) and int(field(rx, 'txid')) in ids, '响应事务与退休编号不一致')
        demand(field(one('ex_register'), 'cb') == field(rx, 'cb') == field(one('ex_retire'), 'cb'), '事务换到另一条连接')
        if mode == 'reverse':
            demand(marks['cached_observed']['index'] < returns[0]['index'], '缓存尚未消费却提前报告返回')
    caches = [row for row in window if row['name'] == 'ex_cache']
    demand([int(field(row, 'add')) for row in caches] == ([1, 0] if mode in ('reverse', 'duplicate') else []), '缓存增加与释放不匹配')
    for event in caches:
        after = [row for row in window if row['name'] == 'ex_cached' and row['pid'] == event['pid'] and row['index'] > event['index']]
        demand(bool(after), '缓存计数调用未返回')
        caller = 'ktcp_end_transaction' if mode == 'duplicate' and field(event, 'add') == '0' else 'ktcp_receive'
        demand(after[0]['detail'].startswith('(' + caller + '+'), '缓存成功消费与故障丢弃混淆')
    if mode == 'reverse':
        demand(caches[0]['index'] < marks['cached_observed']['index'] < caches[1]['index'], '缓存快照不在真实存活区间')
    if mode in ('connect-fault', 'unknown', 'duplicate'):
        error = -111 if mode == 'connect-fault' else -71
        failures = [row for row in window if row['name'] == 'ex_failure' and int(field(row, 'code')) == error]
        demand(bool(failures), '首次故障缺少内核证据')
        demand(all(failures[0]['index'] < row['index'] for row in window if row['name'] == 'ex_done'), '错误尚未锁存就归零')
    else:
        demand(not any(row['name'] == 'ex_failure' for row in window), '正常或主动取消窗口出现故障')
    inbound = [int(field(row, 'add')) for row in rows if row['name'] == 'ex_inbound']
    demand(sum(1 if value else -1 for value in inbound) == 0 and inbound.count(1) == 2 + (pending if mode != 'external' else 0), '入站计数未回收')
    active = Counter()
    for row in rows:
        if row['name'] == 'ex_inbound':
            active[row['pid']] += 1 if field(row, 'add') == '1' else -1
            demand(active[row['pid']] in (0, 1), '入站处理器重复登记或提前释放')
    demand(not any(active.values()), '入站处理器仍在运行')
    return {'mode': mode, 'exchanges': pending, 'cached_responses': len(caches) // 2,
            'exchange_lifecycle_verified': True, 'whole_vm_shutdown_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.probe.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
