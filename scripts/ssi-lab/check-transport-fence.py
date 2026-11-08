#!/usr/bin/env python3
"""从原始 ABI、页面帧和内核事件复核 PF25 本地封闭，不认证整机关闭。"""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path
import struct


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load('check-native-trace')
exchange = load('check-exchanges')
drain, demand, field = exchange.drain, exchange.demand, exchange.field
FENCE, STATUS, SEAL, COPY = 0x4018AEFA, 0x8020AEF8, 0x4018AEF6, 0x4020AEF1
GENERATION = 0x534449002525
PROBES = {'tf_ioctl', 'tf_return', 'tf_request', 'tf_requested', 'tf_exchange',
          'tf_exchanged', 'tf_retire', 'tf_cache', 'tf_receive', 'tf_failure'}
MODES = {'validation', 'reverse', 'cached', 'timeout', 'late', 'fault', 'race'}


def pairs(rows, entry, returned):
    active, completed = {}, []
    for row in rows:
        tid = row['pid']
        if row['name'] == entry:
            demand(tid not in active, '同线程入口未返回就再次进入: ' + entry)
            active[tid] = row
        elif row['name'] == returned:
            demand(tid in active, '返回缺少同线程入口: ' + returned)
            completed.append((active.pop(tid), row))
    demand(not active, '内核调用尚未返回: ' + entry)
    return sorted(completed, key=lambda pair: pair[0]['index'])


def calls(data, rows):
    observed = pairs(rows, 'tf_ioctl', 'tf_return')
    # 初始化三次调用也必须完整成功，但原始输入含仅对该进程有效的地址。
    initial = [(a, b) for a, b in observed if int(field(a, 'ioctl'), 16) in (0x4010AEF0, 0x4020AE46) or
               (int(field(a, 'ioctl'), 16) == COPY and int(field(b, 'code')) == 0)]
    demand([int(field(a, 'ioctl'), 16) for a, _ in initial] == [0x4010AEF0, 0x4020AE46, COPY], '初始化调用不完整')
    demand(all(int(field(b, 'code')) == 0 for _, b in initial), '初始化失败')
    initial_indices = {a['index'] for a, _ in initial}
    pending = defaultdict(list)
    for a, b in observed:
        if a['index'] not in initial_indices:
            pending[a['pid']].append((a, b))
    matched = []
    previous = {}
    for call in sorted(data['calls'], key=lambda value: value['start_ns']):
        tid = call['tid']
        demand(call['end_ns'] > call['start_ns'] >= previous.get(tid, 0), '用户态调用时间重叠或倒退')
        previous[tid] = call['end_ns']
        demand(bool(pending[tid]), '用户态调用缺少原生入口')
        a, b = pending[tid].pop(0)
        demand(int(field(a, 'ioctl'), 16) == call['ioctl'] and int(field(b, 'code')) == -call['errno'], '用户态与原生返回不符')
        if not call['errno']:
            demand('output_hex' in call, '成功调用缺少原始结果')
        matched.append((call, a, b))
    demand(not any(pending.values()), '遗漏原生 ioctl 调用')
    return matched


def inspect(data):
    mode = data['mode']
    demand(mode in MODES and data['kernel'] == '7.1.0-rc3-sshpool-gvm-pf25', '场景或内核不符')
    demand(data['generation'] == GENERATION and data['full_vm_shutdown_accepted'] is False, '本地封闭不能认证整机关闭')
    demand(not data['errors'] and not data['remaining_tasks'] and data['trace_cleanup_complete'], '实验或清理未完成')
    rows, marks = native.parse(data, PROBES)
    matched = calls(data, rows)
    pending_mode = mode in ('reverse', 'cached', 'timeout', 'fault')
    phases = ['sealed']
    if pending_mode:
        phases += ['pending_observed', {'cached': 'release_cached', 'fault': 'inject_fault'}.get(mode, 'release_responses')]
    if mode == 'late':
        phases.append('late_request')
    phases += ['observation_complete', 'cleanup_begin', 'cleanup_complete']
    demand(list(marks) == phases, '阶段缺失或乱序')
    window = [row for row in rows if row['index'] < marks['observation_complete']['index']]
    phase_times = {event['phase']: event['time_ns'] for event in data['events']}

    def one(name):
        selected = [row for row in matched if row[0]['name'] == name]
        demand(len(selected) == 1, '调用缺失或重复: ' + name)
        return selected[0]

    expected = {'seal': (SEAL, 0)}
    if mode == 'validation':
        expected.update(not_enabled=(FENCE, 22), unsealed=(FENCE, 1), wrong_generation=(FENCE, 116))
        expected.update({f'invalid_{key}_{value}': (FENCE, 22) for key, value in
                         [('version', 2), ('flags', 1), ('generation', 0), ('timeout', 0), ('timeout', 30001), ('reserved', 1)]})
    if mode in ('validation', 'late'):
        expected.update(fence=(FENCE, 0), repeat=(FENCE, 0), different_generation=(FENCE, 116), new_copy=(COPY, 108))
    if pending_mode:
        expected['waiter'] = (FENCE, 71 if mode == 'fault' else 0)
        if mode != 'fault':
            expected['repeat'] = (FENCE, 0)
    if mode == 'timeout':
        expected['timeout'] = (FENCE, 110)
    if mode in ('fault', 'late'):
        expected['failed_status'] = (STATUS, 5)
    if mode == 'race':
        expected['racing_fence'] = (FENCE, 0)
        if 'race_receive_error' in data:
            expected['race_status'] = (STATUS, 5)
    summary_calls = [call for call in data['calls'] if not call['name'].startswith('status_')]
    demand(len(summary_calls) == len(expected) and {call['name'] for call in summary_calls} == set(expected), '调用场景集合不符')
    for name, (command, error) in expected.items():
        call, start, end = one(name)
        demand((call['ioctl'], call['errno']) == (command, error), '调用结果不符: ' + name)
        if command in (FENCE, SEAL):
            values = [1, 0, GENERATION, 3000, 0]
            if name in ('wrong_generation', 'different_generation'):
                values[2] += 1
            elif name == 'timeout':
                values[3] = 100
            elif name.startswith('invalid_'):
                _, key, value = name.split('_')
                values[{'version': 0, 'flags': 1, 'generation': 2, 'timeout': 3, 'reserved': 4}[key]] = int(value)
            demand(struct.unpack('=IIQII', bytes.fromhex(call['input_hex'])) == tuple(values), 'ioctl 输入与场景不符')
            if error == 0:
                demand(call['input_hex'] == call['output_hex'], '输入型 ioctl 意外改写参数')
        if name in ('fence', 'waiter', 'racing_fence'):
            demand(marks['sealed']['index'] < start['index'] < end['index'] < marks['observation_complete']['index'], '封闭调用不在已 seal 区间')
    demand(one('seal')[2]['index'] < marks['sealed']['index'], 'seal 尚未完成')
    if mode == 'validation':
        demand(one('unsealed')[2]['index'] < one('seal')[1]['index'], '未 seal 场景错误')
        demand(one('not_enabled')[2]['index'] < next(row['index'] for row in rows if row['name'] == 'tf_ioctl' and field(row, 'ioctl') == '0x4010aef0'), '未启用场景错误')

    statuses = defaultdict(list)
    recorded = [item for item in matched if item[0]['name'].startswith('status_')]
    demand(len(recorded) == len(data['statuses']), '状态快照缺少原生调用')
    previous_time = 0
    for status, (call, start, end) in zip(data['statuses'], recorded):
        values = (status['version'], status['exchanges'], status['cached'], status['inbound'],
                  status['error'], status['state'], status['generation'])
        demand(struct.unpack('=IIIIiIQ', bytes.fromhex(status['hex'])) == values, '状态与原始 ABI 不符')
        demand(status['version'] == 2 and status['error'] == 0, '状态版本或错误不符')
        demand(call['name'] == 'status_' + status['name'] and call['ioctl'] == STATUS and call['errno'] == 0, '状态调用不符')
        demand(call['output_hex'] == status['hex'] and call['input_hex'] == bytes(32).hex(), '状态原始输入输出不符')
        demand(previous_time < status['time_ns'] and call['end_ns'] <= status['time_ns'] < phase_times['observation_complete'], '状态时间不符')
        previous_time = status['time_ns']
        demand((status['state'], status['generation']) == ((1, GENERATION) if status['name'] == 'fenced' else (0, 0)), '错误封闭状态或世代')
        statuses[status['name']].append((status, start, end))
    names = {'pending', 'while_pending'} if pending_mode else set()
    if mode == 'timeout':
        names.add('after_timeout')
    if mode == 'cached':
        names.add('cached')
    if mode not in ('fault',) and not (mode == 'race' and 'race_receive_error' in data):
        names.add('fenced')
    demand(set(statuses) == names, '状态阶段集合不符')

    def last(name, counts):
        status, start, end = statuses[name][-1]
        demand((status['exchanges'], status['cached'], status['inbound']) == counts, '真实在途计数不符: ' + name)
        return status, start, end

    if 'fenced' in statuses:
        _, start, _ = last('fenced', (0, 0, 0))
        fence_name = 'waiter' if pending_mode else 'racing_fence' if mode == 'race' else 'fence'
        demand(one(fence_name)[2]['index'] < start['index'], '封闭快照先于封闭返回')
    if pending_mode:
        last('pending', (2, 0, 2))
        _, start, end = last('while_pending', (2, 0, 2))
        waiter, begin, finish = one('waiter')
        demand(data['waiter_alive_while_pending'] is True, '在途时等待者提前完成')
        demand(marks['pending_observed']['index'] < begin['index'] < start['index'] < end['index'] < finish['index'], '等待者未覆盖真实在途窗口')
        release = marks[{'cached': 'release_cached', 'fault': 'inject_fault'}.get(mode, 'release_responses')]
        demand(release['index'] < finish['index'], '解除依赖前封闭已返回')
        if mode == 'timeout':
            timeout, tstart, tend = one('timeout')
            demand(80_000_000 <= timeout['end_ns'] - timeout['start_ns'] <= 1_000_000_000, '超时未遵守期限')
            demand(0.08 <= tend['time'] - tstart['time'] <= 1.0, '原生超时区间未遵守期限')
            _, after, _ = last('after_timeout', (2, 0, 2))
            demand(marks['pending_observed']['index'] < tstart['index'] < tend['index'] < after['index'] < begin['index'], '超时后未证明仍开放')
        if mode == 'cached':
            _, start, end = last('cached', (2, 1, 2))
            demand(data['waiter_alive_while_cached'] is True and begin['index'] < start['index'] < end['index'] < release['index'], '缓存仍活跃时已提前封闭')

    expected_requests = []
    if pending_mode:
        expected_requests += [drain.frame(drain.REQUEST.pack(1, 1, 2 + i, 1, 0, 0), 42 + i) for i in range(2)]
        expected_requests += [drain.frame(drain.REQUEST.pack(2, 2, 2 + i, 1, 0, 0), 100 + i) for i in range(2)]
    if mode == 'fault':
        expected_requests.append(drain.frame(drain.REQUEST.pack(1, 1, 2, 255, 0, 0), 200))
    if mode in ('late', 'race'):
        expected_requests.append(drain.frame(drain.REQUEST.pack(1, 1, 2, 1, 0, 0), 100))
    demand(data['requests'] == [value.hex() for value in expected_requests], '实际请求字节错误')
    response_ids = [42, 43] if pending_mode else []
    if pending_mode and mode != 'fault':
        response_ids += [100, 101]
    if mode == 'race' and 'race_receive_error' not in data:
        response_ids.append(100)
    demand(sorted(response['txid'] for response in data['responses']) == response_ids, '响应数量或事务编号不符')
    for response in data['responses']:
        drain.safety.check_response(response, response['txid'], drain.safety.PAGE, 1)
    outgoing = []
    for value in data['outgoing_requests']:
        raw = bytes.fromhex(value)
        demand(len(raw) == 4110 and not any(raw[38:]), '出站帧长度或尾部不符')
        header, body = drain.HEADER.unpack_from(raw), drain.REQUEST.unpack(raw[14:38])
        demand(header[:3] == (38, 0, 0) and header[3] != 255, '出站帧头错误')
        demand(body == (0, 2, body[2], 1, 0, 0), '真实反向请求字段不符')
        outgoing.append((header[3], body[2]))
    ids = [item[0] for item in outgoing]
    demand(len(ids) == len(set(ids)) == (2 if pending_mode else 0), '出站事务缺失或重号')
    demand({item[1] for item in outgoing} == ({2, 3} if pending_mode else set()), '出站页号错误')
    def frame(txid):
        return drain.HEADER.pack(4110, 1, 0, txid) + drain.safety.PAGE
    injected = []
    if mode in ('reverse', 'timeout'):
        injected = [frame(txid) for txid in reversed(ids)]
    if mode == 'cached':
        own, other, tid = data['held_txid'], data['cached_txid'], data['partial_reader_pid']
        demand(own != other and {own, other} == set(ids), '半帧读者与缓存事务不符')
        stack = data['partial_reader_tasks'][str(tid)]['stack']
        demand(any('tcp_recvmsg' in line for line in stack) and any('kvm_dsm_fetch' in line for line in stack), '没有真实半帧等待栈')
        receives = [row for row in rows if row['name'] == 'tf_receive' and row['pid'] == tid and field(row, 'txid') != '255']
        demand(len(receives) == 1 and int(field(receives[0], 'txid')) == own, '半帧与原生事务未对应')
        injected = [struct.pack('<Q', 4110), frame(other)[8:] + frame(own)[:8], frame(own)[8:]]
    demand(data['injected'] == [value.hex() for value in injected], '实际注入字节不符')

    requests = pairs(rows, 'tf_request', 'tf_requested')
    active, accepted, denied = {}, [], []
    for start, end in requests:
        tid, add, code = start['pid'], int(field(start, 'add')), int(field(end, 'code'))
        demand(add in (0, 1), '请求计数方向非法')
        if add and code:
            demand(code == -108 and tid not in active, '拒绝请求的错误或生命周期不符')
            denied.append((start, end))
            continue
        demand(code == 0, '请求计数失败')
        if add:
            demand(tid not in active, '重复计入请求')
            active[tid] = start
        else:
            demand(tid in active, '尚未准入就减少计数')
            accepted.append((active.pop(tid), end))
    demand(not active, '请求未回收')
    expect_denied = mode == 'late' or (mode == 'race' and 'race_receive_error' in data)
    demand(len(denied) == int(expect_denied), '晚到请求未被原生拒绝')
    demand(len(accepted) == (4 if pending_mode else int(mode == 'race' and not expect_denied)), '准入请求数量错误')
    demand(all(end['index'] < marks['observation_complete']['index'] for _, end in accepted + denied), '清理前请求未完成')
    if mode != 'fault':
        name = 'waiter' if pending_mode else 'racing_fence' if mode == 'race' else 'fence'
        finish = one(name)[2]['index']
        demand(all(start['index'] < finish for start, _ in requests if field(start, 'add') == '0'),
               '成功准入的请求尚未释放就封闭')
    if expect_denied:
        name = 'fence' if mode == 'late' else 'racing_fence'
        demand(one(name)[1]['index'] < denied[0][1]['index'], '拒绝发生在封闭调用之前')
        if mode == 'late':
            demand(one(name)[2]['index'] < marks['late_request']['index'] < denied[0][0]['index'], '晚到请求实际早于封闭')
    starts = pairs(rows, 'tf_exchange', 'tf_exchanged')
    retires = [row for row in rows if row['name'] == 'tf_retire']
    demand(len(starts) == len(retires) == (2 if pending_mode else 0), '出站生命周期数量不符')
    for start, end in starts:
        demand(int(field(end, 'code')) == 0 and marks['sealed']['index'] < start['index'], '反向取页未在 seal 后准入')
        done = [row for row in retires if row['pid'] == start['pid']]
        demand(len(done) == 1 and end['index'] < done[0]['index'] < marks['observation_complete']['index'], '出站事务未退休')
        receives = [row for row in rows if row['name'] == 'tf_receive' and row['pid'] == start['pid'] and field(row, 'txid') != '255']
        demand(len(receives) == 1 and int(field(receives[0], 'txid')) in ids, '真实出站事务接收不符')
        demand(end['index'] < receives[0]['index'] < done[0]['index'], '出站接收不在生命周期内')
    caches = [row for row in rows if row['name'] == 'tf_cache']
    balance = 0
    for row in caches:
        value = int(field(row, 'add'))
        demand(value in (0, 1), '缓存方向非法')
        balance += 1 if value else -1
        demand(balance >= 0 and row['index'] < marks['observation_complete']['index'], '缓存提前减少或清理前未消费')
    demand(balance == 0, '缓存未回收')
    if mode == 'cached':
        demand([int(field(row, 'add')) for row in caches] == [1, 0], '受控缓存生命周期不符')
        demand(caches[0]['index'] < statuses['cached'][-1][1]['index'] < marks['release_cached']['index'] < caches[1]['index'] < one('waiter')[2]['index'], '缓存消费顺序不符')
    if pending_mode and mode != 'fault':
        demand(all(row['index'] < one('waiter')[2]['index'] for row in retires + caches), '出站或缓存尚未退休就封闭')
        # 减少计数在函数内完成；唤醒后的封闭线程可能早于计数函数的返回探针。
        demand(all(start['index'] < one('waiter')[2]['index'] for start, _ in requests if field(start, 'add') == '0'), '入站尚未开始释放就封闭')
    failures = [row for row in window if row['name'] == 'tf_failure']
    if mode == 'fault' or expect_denied:
        error = -71 if mode == 'fault' else -108
        demand(bool(failures) and int(field(failures[0], 'code')) == error, '首次故障缺少原生证据')
        demand(data['tasks_before_cleanup'] == {}, '故障线程依赖清理才退出')
        if mode == 'fault':
            demand(marks['inject_fault']['index'] < failures[0]['index'] < one('waiter')[2]['index'], '故障未优先返回给等待者')
            demand(all(failures[0]['index'] < row['index'] for row in retires), '故障尚未锁存就减少出站计数')
    else:
        demand(not failures, '正常观察窗口发生故障')
    return {'mode': mode, 'admitted_requests': len(accepted), 'denied_requests': len(denied),
            'outgoing_exchanges': len(starts), 'native_calls_verified': len(matched),
            'local_transport_fenced': mode != 'fault', 'whole_vm_shutdown_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.probe.read_text())), ensure_ascii=False))


if __name__ == '__main__':
    main()
