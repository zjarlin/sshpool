"""从完整原生跟踪、实际 ioctl 参数和受控对端字节重建关闭结果。"""
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module('native_close_trace', 'check-native-trace.py')
probe = module('close_probe', 'probe-kernel-close.py')
demand = native.demand
# 捕获目标为 Linux x86；检查器也在 macOS 执行，不能使用宿主 errno 编号。
LINUX_EINTR = 4
LINUX_EIO = 5
LINUX_EINVAL = 22
LINUX_EBUSY = 16
LINUX_ENODATA = 61
LINUX_ETIMEDOUT = 110
LINUX_EPROTO = 71

NORMAL = {'single', 'pair', 'remote', 'validation', 'synthetic-clean', 'active-ioctl'}
PAIRS = {
    'kc_ioctl': 'kc_return',
    'kc_close': 'kc_closed',
    'kc_request': 'kc_ack',
    'kc_eof': 'kc_eof_done',
    'kc_fence': 'kc_fenced',
    'kc_accept': 'kc_accepted',
    'kc_connect': 'kc_connected',
    'kc_freeze': 'kc_frozen',
}


def fields(row):
    return {key: int(value, 0) for key, value in
            re.findall(r'(\w+)=(0x[0-9a-f]+|-?\d+)', row['detail'])}


def pair_calls(rows, entry, leave):
    pending = {}
    calls = []
    for row in rows:
        if row['name'] == entry:
            demand(row['pid'] not in pending, '同线程入口未配对或递归')
            pending[row['pid']] = row
        elif row['name'] == leave:
            demand(row['pid'] in pending, '返回找不到同线程入口')
            start = pending.pop(row['pid'])
            calls.append({'start': start, 'end': row, 'input': fields(start),
                          'code': fields(row)['code']})
    demand(not pending, '原生调用没有返回')
    return calls


def check_ioctls(data, pairs):
    commands = {probe.CLOSE, probe.device.DSM_MEMCPY, 0x4018AEF2, 0x8020AEF8, 0x8020AEF7}
    actual = defaultdict(list)
    expected = defaultdict(list)
    for call in pairs['kc_ioctl']:
        if call['input']['ioctl'] in commands:
            actual[call['start']['pid']].append(call)
    for call in data['calls']:
        expected[call['tid']].append(call)
    demand(set(actual) == set(expected), '用户记录与内核线程集合不一致')
    for tid, recorded in expected.items():
        recorded.sort(key=lambda call: call['start_ns'])
        observed = sorted(actual[tid], key=lambda call: call['start']['index'])
        demand(len(recorded) == len(observed), '用户记录遗漏了原生 ioctl')
        for row, event in zip(recorded, observed):
            demand(row['ioctl'] == event['input']['ioctl'], '实际 ioctl 编号不同')
            demand(row['errno'] == -event['code'], '原生返回值与记录不一致')
            demand(row['end_ns'] > row['start_ns'], '用户计时无效')
            raw = bytes.fromhex(row['input_hex'])
            if row['ioctl'] == probe.CLOSE:
                demand(len(raw) == 24, '关闭 ABI 长度错误')
                version, flags, generation, timeout, reserved = struct.unpack('=IIQII', raw)
                if row['name'] == 'invalid':
                    demand(row['errno'] == LINUX_EINVAL, '非法关闭参数未拒绝')
                else:
                    expected_generation = probe.GENERATION + int(
                        data['mode'] == 'wrong-generation' and row['node'] == 1)
                    demand((version, flags, generation, reserved) ==
                           (1, 0, expected_generation, 0), '关闭世代或参数错误')
                    demand(timeout == (250 if data['mode'] == 'deadline' and row['node'] == 0 else 1500),
                           '实验期限被修改')
                    elapsed = (row['end_ns'] - row['start_ns']) / 1e6
                    demand(elapsed <= timeout + 500, '关闭没有在总期限内结束')
                    if row['errno'] == LINUX_ETIMEDOUT:
                        demand(elapsed >= timeout - 25, '超时在期限到达前误触发')
            if row['name'] in ('write', 'read'):
                demand(row['errno'] == 0 and len(raw) == 32, '页面访问失败')
                write, address, buffer, length = struct.unpack('=?7xQQQ', raw)
                demand(write == (row['name'] == 'write') and address and buffer and length == 8192,
                       '页面复制 ABI 与操作不同')
                payload = bytes.fromhex(row['payload_hex'])
                demand(len(payload) == 8192, '实际页面内容缺失')
                demand(hashlib.sha256(payload).hexdigest() == row['payload_sha256'], '页面哈希错误')
                demand(payload in (probe.safety.PAGE * 2, probe.safety.PAGE[::-1] * 2),
                       '实际页面内容错误')
    copies = sorted((row for row in data['calls'] if row['name'] in ('write', 'read')),
                    key=lambda row: row['start_ns'])
    forward, reverse = probe.safety.PAGE * 2, probe.safety.PAGE[::-1] * 2
    expected_copies = [(0, 'write', forward), (0, 'read', forward)]
    if data['mode'] in {'peer-absent', 'connect-timeout'}:
        expected_copies = []
    elif data['mode'] == 'remote':
        node = next(row['node'] for row in data['calls'] if row['name'] == 'close')
        expected_copies = ([(0, 'write', forward), (0, 'read', reverse)] if node == 0 else
                           [(1, 'read', forward), (1, 'write', reverse)])
    elif data['mode'] not in probe.SYNTHETIC and data['mode'] not in {'single', 'root-signal', 'validation'}:
        expected_copies += [(1, 'read', forward), (1, 'write', reverse), (0, 'read', reverse)]
        if data['mode'] == 'active-ioctl':
            expected_copies += [(0, 'write', forward), (1, 'write', reverse)]
    demand([(row['node'], row['name'], bytes.fromhex(row['payload_hex'])) for row in copies] == expected_copies,
           '双向读写顺序或具体返回内容错误')
    return [row for row in data['calls'] if row['name'] == 'close' and row['errno'] != LINUX_EBUSY]


def check_wire(data):
    if data['mode'] not in probe.SYNTHETIC:
        return None
    frames = data['synthetic_wire']
    decoded = []
    for frame in frames:
        raw = bytes.fromhex(frame['hex'])
        demand(len(raw) == 4110, '受控对端固定帧长度错误')
        length, copyset, version, txid = probe.safety.request.HEADER.unpack_from(raw)
        demand(14 <= length <= 4110 and txid != 255, '帧头或事务号错误')
        demand(not any(raw[length:]), '固定帧尾部包含未清零数据')
        if length == 4110:
            demand(frame['channel'] == 'data' and frame['direction'] == 'receive', '异常页面响应')
            demand(raw[14:] == probe.safety.PAGE, '受控对端读到错误页面')
            continue
        demand(length == 38 and copyset == 0 and version == 0, '关闭帧头错误')
        payload = raw[14:38]
        if payload[:4] == struct.pack('<I', 0x44534d43):
            magic, ver, phase, sender, target, reserved, generation = struct.unpack('<IHHHHIQ', payload)
            demand(ver == 1 and reserved == 0, '确认版本或保留字段错误')
            demand((sender, target) == ((1, 0) if frame['direction'] == 'send' else (0, 1)),
                   '确认端点错误')
            wrong_generation = data['mode'] == 'synthetic-bad-generation' and sender == 1
            demand(generation == probe.GENERATION + int(wrong_generation), '确认世代与注入不符')
            kind = 'ack'
        else:
            sender, origin, generation, phase, smm, ver = probe.safety.request.REQUEST.unpack(payload)
            demand(sender == origin == (1 if frame['direction'] == 'send' else 0), '请求端点错误')
            demand(payload == probe.safety.request.REQUEST.pack(sender, origin, generation, phase, smm, ver),
                   '请求对齐字节异常')
            if phase == 1:
                demand(frame['channel'] in ('data', 'late') and generation == 2 and smm == ver == 0,
                       '页面请求与实验不符')
            else:
                demand(generation == probe.GENERATION and smm == 0 and ver == 1 and phase in (4, 5, 6, 7),
                       '关闭请求字段错误')
            kind = 'request'
        decoded.append({**frame, 'kind': kind, 'sender': sender, 'phase': phase, 'txid': txid})
    outgoing = [row for row in decoded if row['kind'] == 'request' and row['sender'] == 0]
    demand([row['phase'] for row in outgoing] == sorted({row['phase'] for row in outgoing}),
           '内核管理请求重复或乱序')
    demand(outgoing and outgoing[0]['phase'] == 5, '缺少内核 PREPARE')
    replies = [row for row in decoded if row['kind'] == 'ack' and row['sender'] == 1]
    for reply in replies:
        request = next((row for row in outgoing if row['txid'] == reply['txid']), None)
        demand(request is not None, '确认没有对应的真实事务')
        offset = int(data['mode'] == 'synthetic-bad-phase')
        demand(reply['phase'] == request['phase'] + offset, 'ACK 阶段与注入不符')
        if data['mode'] == 'synthetic-budget':
            demand(reply['time_ns'] - request['time_ns'] >= 550_000_000, '分阶段延迟没有实际发生')
    incoming = [row for row in decoded if row['kind'] == 'request' and row['sender'] == 1]
    if data['mode'] == 'synthetic-clean':
        demand([row['phase'] for row in outgoing] == [5, 6, 7], '缺少出站最终确认')
        demand([row['phase'] for row in incoming] == [5, 6, 7], '缺少入站最终确认')
        demand(len(replies) == 3 and not data.get('synthetic_errors'), '受控正常对端失败')
        demand(data['responder_eof'] == data['requester_eof'] == '', '两条管理连接没有实际 EOF')
    if data['mode'] == 'synthetic-missing-ack':
        demand(not replies and data['withheld_phase'] == 5, '缺失 ACK 注入未发生')
    if data['mode'] == 'synthetic-missing-final':
        demand([row['phase'] for row in incoming] == [5, 6] and data['withheld_final'],
               '缺失最终确认注入未发生')
    if data['mode'] == 'synthetic-late':
        demand([row['phase'] for row in incoming if row['channel'] in ('data', 'late')] == [1, 4, 1],
               '缺少 CLOSE 后的真实晚到页请求')
    return {'requests': len(outgoing) + len(incoming), 'peer_acks': len(replies)}


def inspect(data):
    demand(data['kernel'] == '7.1.0-rc3-sshpool-gvm-pf28', '内核版本错误')
    demand(data['mode'] in probe.MODES and data['generation'] == probe.GENERATION, '模式或世代错误')
    demand(not data['errors'], '采集器报告失败')
    demand(data['remaining_tasks'] == data['tasks_before_cleanup'] == {}, '关闭后仍有 DSM 线程')
    demand(data['trace_cleanup_complete'] and data['qemu_shutdown_accepted'] is False, '清理或验收范围错误')
    rows, marks = native.parse(data, {name for _, name, _ in probe.PROBES})
    demand(marks['observed']['index'] < marks['cleanup_begin']['index'], '观察发生在清理之后')
    pairs = {entry: pair_calls(rows, entry, leave) for entry, leave in PAIRS.items()}
    closes = check_ioctls(data, pairs)
    demand(len(closes) == (2 if data['mode'] in {'pair', 'active-ioctl', 'partial', 'occupied', 'unknown', 'wrong-generation', 'deadline'} else 1),
           '缺少关闭调用')
    failures = [row for row in rows if row['name'] == 'kc_fail']
    normal = data['mode'] in NORMAL
    demand(all((row['errno'] == 0) == normal for row in closes), '关闭成功/失败与实际场景矛盾')
    if normal:
        demand(not failures, '正常关闭掩盖了内核失败')
        completed = [row for row in rows if row['name'] == 'kc_root_done']
        demand(len(completed) == len(closes), '根线程未完成入站连接回收')
        final_calls = [row for row in pairs['kc_close'] if row['code'] == 0]
        for call in final_calls:
            done = [row for row in completed if fields(row)['kvm'] == call['input']['kvm']]
            demand(len(done) == 1 and done[0]['index'] < call['end']['index'], '关闭先于根线程资源回收返回')
            user_call = next(row for row in closes if row['tid'] == call['start']['pid'])
            demand(done[0]['comm'] == 'kvm-dsm/' + str(user_call['node']), '关闭节点与实际根线程身份不符')
        demand(len(pairs['kc_fence']) == len(closes), '缺少本地传输封闭')
        demand(len(pairs['kc_freeze']) == len(closes), '没有实际停止监听器')
        demand(all(row['code'] == 0 for row in pairs['kc_fence'] + pairs['kc_freeze']), '封闭或停止监听失败')
        demand(all(row['input']['generation'] == probe.GENERATION for row in pairs['kc_fence']),
               '本地封闭与关闭世代不同')
        connections = defaultdict(list)
        for call in pairs['kc_request']:
            demand(call['code'] == 0 and call['input']['generation'] == probe.GENERATION, '入站确认失败或世代错误')
            connections[call['input']['conn']].append(call)
        for conn, calls in connections.items():
            calls.sort(key=lambda row: row['start']['index'])
            phases = [row['input']['phase'] for row in calls]
            demand(phases in ([4], [5, 6, 7]), '连接混用了页面与管理阶段或缺少最终确认')
            if phases == [4]:
                fence = [row for row in pairs['kc_fence']
                         if row['input']['kvm'] == calls[0]['input']['kvm']]
                demand(len(fence) == 1 and fence[0]['end']['index'] < calls[0]['end']['index'],
                       'CLOSE 确认早于本地封闭')
        accepted = defaultdict(int)
        for call in pairs['kc_accept']:
            demand(call['code'] == 0, '正常关闭期间接收连接失败')
            accepted[call['input']['kvm']] += 1
        classified = defaultdict(int)
        for calls in connections.values():
            classified[calls[0]['input']['kvm']] += 1
        demand(accepted == classified, '接受过的连接被关闭协议遗漏')
        eof_connections = set()
        for call in pairs['kc_eof']:
            conn = call['input']['conn']
            demand(conn in connections and conn not in eof_connections, 'EOF 未对应已确认的连接')
            demand(call['code'] == -LINUX_ENODATA, 'EOF 被错误地视作正常')
            demand(connections[conn][-1]['end']['index'] < call['start']['index'], 'EOF 早于该连接的确认完成')
            done = [row for row in completed if fields(row)['kvm'] == call['input']['kvm']]
            demand(len(done) == 1 and call['end']['index'] < done[0]['index'],
                   '根线程回收早于连接 EOF 完成')
            eof_connections.add(conn)
        demand(eof_connections == set(connections), '有连接未观察到实际 EOF')
    else:
        demand(failures and all(fields(row)['code'] < 0 for row in failures), '没有真实内核失败')
        demand(all(call['end']['index'] < marks['cleanup_begin']['index'] for call in pairs['kc_close']),
               '依赖释放 VM 才结束等待')
    if data['mode'] == 'root-signal':
        demand(data['tasks_after_signal'] == {} and len(data['signal_tasks']) == 1, '定向取消未回收根线程')
        demand(fields(failures[0])['code'] == -LINUX_EINTR and closes[0]['errno'] == LINUX_EIO,
               '取消故障没有向管理接口传播')
    if data['mode'] == 'validation':
        invalid = [struct.unpack('=IIQII', bytes.fromhex(row['input_hex']))
                   for row in data['calls'] if row['name'] == 'invalid']
        demand(invalid == [(2, 0, probe.GENERATION, 1500, 0),
                           (1, 1, probe.GENERATION, 1500, 0),
                           (1, 0, 0, 1500, 0),
                           (1, 0, probe.GENERATION, 0, 0),
                           (1, 0, probe.GENERATION, 30001, 0),
                           (1, 0, probe.GENERATION, 1500, 1)],
               '非法参数集合缺失或被重复调用替代')
        demand([row['errno'] for row in data['calls'] if row['name'] == 'close'] == [LINUX_EBUSY, 0],
               '固定引用没有阻止关闭或无法解除后关闭')
    if data['mode'] == 'connect-timeout':
        demand(closes[0]['errno'] == LINUX_ETIMEDOUT, '建连没有由总期限取消')
        demand(any(call['code'] == -LINUX_ETIMEDOUT and
                   1.4 <= call['end']['time'] - call['start']['time'] <= 2.0
                   for call in pairs['kc_connect']), '未观察到实际等待中的建连被取消')
    if data['mode'] in {'unknown', 'partial', 'occupied'}:
        status = next(row for row in data['calls'] if row['name'] == 'injected_status')
        version, exchanges, cached, inbound, error, state, generation = struct.unpack(
            '=IIIIiIQ', bytes.fromhex(status['output_hex']))
        demand((version, exchanges, cached, error, state, generation) == (2, 0, 0, 0, 0, 0), '注入时传输状态异常')
        demand(inbound == (8 if data['mode'] == 'occupied' else 0), '八个在途请求或零计数对照未发生')
        demand(any(row['errno'] == LINUX_ETIMEDOUT for row in closes), '未分类或半帧连接被遗漏')
        if data['mode'] == 'partial':
            demand(bytes.fromhex(data['partial_hex']) == probe.safety.read_request(111)[:8], '半帧注入损坏')
        if data['mode'] == 'occupied':
            demand([bytes.fromhex(value) for value in data['occupied_requests']] ==
                   [probe.safety.read_request(110 + i, gfn=20 + i) for i in range(8)], '八个请求注入损坏')
    if data['mode'] in {'synthetic-missing-ack', 'synthetic-missing-final', 'synthetic-budget',
                        'synthetic-half-ack', 'synthetic-send-pressure'}:
        demand(closes[0]['errno'] == LINUX_ETIMEDOUT, '缺失确认没有由同一总期限终止')
    if data['mode'] == 'synthetic-half-ack':
        demand(len(bytes.fromhex(data['partial_ack_hex'])) == 8, '半帧 ACK 没有实际发送')
        demand(data['partial_ack_read'] == '', '半帧接收器未被故障取消')
    if data['mode'] == 'synthetic-send-pressure':
        blocked = data['pressure_blocked_tids']
        locked = data['pressure_locked_tids']
        demand(len(blocked) == 1 and len(locked) == 7 and len(set(blocked + locked)) == 8,
               '没有实际发送阻塞及七个锁等待处理器')
        for tid in blocked:
            stack = data['pressure_tasks'][tid]['stack']
            demand(any('sk_stream_wait_memory' in line for line in stack), '没有真实发送缓冲等待')
        for tid in locked:
            stack = data['pressure_tasks'][tid]['stack']
            demand(any('__mutex_lock' in line or 'dsm_lock_killable' in line or 'ktcp_send' in line
                       for line in stack), '其余处理器没有实际锁等待')
            demand(any('ivy_kvm_dsm_handle_req' in line for line in stack), '锁等待不属于页面处理器')
        workers = {pid for pid, task in data['pressure_tasks'].items()
                   if task['name'].startswith('dsm-conn/')}
        demand(workers == set(blocked + locked), '处理器集合与实际等待者不同')
        count = data['pressure_sent_bytes']
        payload = b''.join(probe.safety.read_request(1000 + i, gfn=2 + i) for i in range(2048))
        demand(8 * 4110 <= count <= len(payload), '真实发送请求不足')
        demand(hashlib.sha256(payload[:count]).hexdigest() == data['pressure_sent_sha256'], '发送请求前缀损坏')
        status = struct.unpack('=IIIIiIQ', bytes.fromhex(data['pressure_status']['output_hex']))
        demand(status == (2, 0, 0, 8, 0, 0, 0), '真实在途响应数不足八个')
    if data['mode'] == 'active-ioctl':
        demand(data['close_waiting_before_unpin'] and not data.get('active_copy_error'), '关闭没有等待在途根调用')
        demand(bytes.fromhex(data['active_memory_hex']) == probe.safety.PAGE[::-1] * 2, '在途写入没有完成')
        statuses = [struct.unpack('=IIQIiII', bytes.fromhex(row['output_hex']))
                    for row in data['calls'] if row['name'] == 'active_status']
        demand((1, 0, 0, 1, 0, 0, 0) in statuses and
               (1, 1, probe.GENERATION, 1, 0, 0, 0) in statuses, '未同时观察封闭前后仍有在途调用')
        release = marks['release_pin']['index']
        demand(all(call['start']['index'] > release for call in pairs['kc_fence']), '根调用仍阻塞时提前封闭传输')
        writer = max((row for row in data['calls'] if row['name'] == 'write' and row['node'] == 1),
                     key=lambda row: row['start_ns'])
        native_writer = [row for row in pairs['kc_ioctl'] if row['start']['pid'] == writer['tid']]
        demand(len(native_writer) == 1 and all(row['start']['index'] > native_writer[0]['end']['index']
                                              for row in pairs['kc_fence']),
               '在途根调用的原生返回早于本地封闭的证据缺失')
    if data['mode'] in {'synthetic-bad-generation', 'synthetic-bad-phase', 'synthetic-late'}:
        demand(closes[0]['errno'] == LINUX_EPROTO, '协议错误被关闭成功或其他错误覆盖')
    return {'mode': data['mode'], 'events': len(rows), 'ioctls': len(data['calls']),
            'close_errors': [row['errno'] for row in closes],
            'close_ms': [(row['end_ns'] - row['start_ns']) / 1e6 for row in closes],
            'inbound_close_frames': len(pairs['kc_request']), 'normal_eof': sum(row['code'] == -LINUX_ENODATA for row in pairs['kc_eof']),
            'wire': check_wire(data)}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(json.loads(args.record.read_text())), indent=2))
