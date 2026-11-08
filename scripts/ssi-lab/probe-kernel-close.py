#!/usr/bin/env python3
"""在独占 PF28 上核查全节点关闭与失败回收；不代表 QEMU 设备清理已集成。"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import mmap
import os
import platform
import socket
import struct
import subprocess
import threading
import time
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('probe-ioctl-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
(device, safety, trace) = (admission.device, admission.safety, admission.trace)
CLOSE = 0x4018aefb
GENERATION = 0x534449002626
SYNTHETIC = ('synthetic-half-ack', 'synthetic-send-pressure', 'synthetic-clean',
 'synthetic-bad-generation',
 'synthetic-bad-phase',
 'synthetic-missing-ack',
 'synthetic-missing-final',
 'synthetic-late',
 'synthetic-budget')
MODES = SYNTHETIC + ('active-ioctl', 'validation', 'root-signal', 'connect-timeout', 'remote', 'single', 'pair', 'unknown', 'partial', 'occupied', 'wrong-generation', 'deadline', 'peer-absent')
PROBES = [('p', 'kc_root_done', 'dsm_close_root_done kvm=$arg1:x64'), ('p', 'kc_freeze', 'ktcp_shutdown_listener cb=$arg1:x64'),
 ('r128', 'kc_frozen', 'ktcp_shutdown_listener code=$retval:s32'),
 ('p', 'kc_ioctl', 'kvm_vm_ioctl ioctl=$arg2:x32'),
 ('r128', 'kc_return', 'kvm_vm_ioctl code=$retval:s32'),
 ('p', 'kc_close', 'dsm_close_ioctl kvm=$arg1:x64'),
 ('r128', 'kc_closed', 'dsm_close_ioctl code=$retval:s32'),
 ('p',
  'kc_request',
  'dsm_close_request conn=$arg1:x64 kvm=+16($arg1):x64 phase=+16($arg2):u8 generation=+8($arg2):x64'),
 ('r128', 'kc_ack', 'dsm_close_request code=$retval:s32'),
 ('p', 'kc_eof', 'dsm_close_eof conn=$arg1:x64 kvm=+16($arg1):x64'),
 ('r128', 'kc_eof_done', 'dsm_close_eof code=$retval:s32'),
 ('p', 'kc_fence', 'dsm_transport_try_fence kvm=$arg1:x64 generation=$arg2:x64'),
 ('r128', 'kc_fenced', 'dsm_transport_try_fence code=$retval:s32'),
 ('p', 'kc_fail', 'kvm_dsm_fail kvm=$arg1:x64 code=$arg2:s32'),
 ('p', 'kc_accept', 'dsm_close_accept kvm=$arg1:x64'),
 ('r128', 'kc_accepted', 'dsm_close_accept code=$retval:s32'),
 ('p', 'kc_connect', 'ktcp_connect kvm=$arg1:x64 port=$arg3:u16'),
 ('r128', 'kc_connected', 'ktcp_connect code=$retval:s32')]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=MODES, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--require-kernel', required=True)
    p.add_argument('--node', type=int, choices=[0, 1])
    p.add_argument('--peers', nargs=2)
    a = p.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or a.require_kernel != '7.1.0-rc3-sshpool-gvm-pf28' or (platform.release() != a.require_kernel):
        p.error('仅允许显式指定的独占 PF28 x86 内核')
    if safety.tasks():
        p.error('已有 DSM 线程')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError, ProcessLookupError):
            continue
        if name.startswith(('qemu-system-', 'memfd:sshpool', 'probe-dsm-')):
            p.error('已有其他实验进程')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        p.error('已有跟踪')
    group = f'sshpool_close_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'mode': a.mode, 'kernel': platform.release(), 'calls': [], 'events': [], 'errors': [], 'generation': GENERATION, 'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'qemu_shutdown_accepted': False}
    vms = [None, None] if a.mode == 'remote' else []
    memory = [None, None] if a.mode == 'remote' else []
    buffers = []
    threads = []
    sockets = []
    registered = []
    kvm = None

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def call(n, name, cmd, arg):
        row = {'node': n, 'name': name, 'ioctl': cmd, 'input_hex': arg.hex(), 'tid': threading.get_native_id(), 'start_ns': time.monotonic_ns(), 'errno': 0}
        try:
            row['output_hex'] = fcntl.ioctl(vms[n], cmd, arg).hex()
        except OSError as e:
            row['errno'] = e.errno
        row['end_ns'] = time.monotonic_ns()
        result['calls'].append(row)
        return row

    def close(n, generation=GENERATION, timeout=1500):
        return call(n, 'close', CLOSE, struct.pack('=IIQII', 1, 0, generation, timeout, 0))

    def start(n, generation=GENERATION, timeout=1500):
        t = threading.Thread(target=lambda: close(n, generation, timeout))
        threads.append(t)
        t.start()
        return t

    def copy(n, write, contents):
        buf = ctypes.create_string_buffer(contents)
        buffers.append(buf)
        row = call(n, 'write' if write else 'read', device.DSM_MEMCPY, device.copy_request(write, ctypes.addressof(ctypes.c_char.from_buffer(memory[n])), ctypes.addressof(buf), len(contents)))
        if row['errno']:
            raise RuntimeError('取页失败 ' + str(row))
        actual = buf.raw[:len(contents)]
        row['payload_sha256'] = hashlib.sha256(actual).hexdigest()
        row['payload_hex'] = actual.hex()
        return actual

    def wire(sock, direction, value=None, channel='control'):
        if direction == 'receive':
            value = safety.receive_frame(sock)
        else:
            sock.sendall(value)
        result.setdefault('synthetic_wire', []).append({'direction': direction, 'channel': channel, 'hex': value.hex(), 'time_ns': time.monotonic_ns()})
        return value

    def setup_synthetic():
        nonlocal listener, data_peer, pressure_blob
        listener = socket.socket()
        listener.settimeout(4)
        listener.bind(('127.0.0.2', 37711))
        listener.listen(1)
        sockets.append(listener)
        if a.mode == 'synthetic-send-pressure':
            data_peer = socket.socket()
            data_peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            data_peer.settimeout(0.2)
            data_peer.connect(('127.0.0.1', 37710))
            sockets.append(data_peer)
            pressure_blob = b''.join(probe_frame(i) for i in range(2048))
            result['pressure_sent_bytes'] = 0
            sender = threading.Thread(target=pressure_send)
            threads.append(sender)
            sender.start()
            deadline = time.monotonic() + 3
            while True:
                tasks = safety.tasks()
                blocked = [pid for pid, item in tasks.items() if
                           any('sk_stream_wait_memory' in line for line in item['stack'])]
                # 每页仅请求一次避免所有权反向取页；同连接发送串行，确认真实网络及发送锁等待。
                workers = [pid for pid, item in tasks.items() if
                           item['name'].startswith('dsm-conn/')]
                locked = [pid for pid in workers if pid not in blocked and
                          any('__mutex_lock' in line or 'dsm_lock_killable' in line or 'ktcp_send' in line
                              for line in tasks[pid]['stack'])]
                result['pressure_tasks'] = tasks
                result['pressure_blocked_tids'] = blocked
                result['pressure_locked_tids'] = locked
                if len(blocked) == 1 and len(locked) == 7 and len(workers) == 8:
                    result['pressure_status'] = call(0, 'pressure_status', 0x8020AEF8, bytes(32))
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('未观察到真实发送等待与其余七个锁等待处理器')
                time.sleep(0.01)
        if a.mode == 'synthetic-late':
            data_peer = socket.create_connection(('127.0.0.1', 37710), timeout=4)
            sockets.append(data_peer)
            wire(data_peer, 'send', safety.read_request(90), channel='data')
            wire(data_peer, 'receive', channel='data')

    def probe_frame(index):
        return safety.read_request(1000 + index, gfn=2 + index)

    def pressure_send():
        try:
            deadline = time.monotonic() + 6
            while result['pressure_sent_bytes'] < len(pressure_blob):
                offset = result['pressure_sent_bytes']
                try:
                    sent = data_peer.send(pressure_blob[offset:])
                except socket.timeout:
                    if time.monotonic() >= deadline:
                        raise
                    continue
                if not sent:
                    raise RuntimeError('发送进度为零')
                result['pressure_sent_bytes'] += sent
        except (OSError, RuntimeError) as error:
            result['pressure_send_error'] = {'type': type(error).__name__, 'error': str(error)}
        finally:
            prefix = pressure_blob[:result['pressure_sent_bytes']]
            result['pressure_sent_sha256'] = hashlib.sha256(prefix).hexdigest()

    def synthetic_thread(fn):
        try:
            fn()
        except (OSError, RuntimeError, AssertionError) as e:
            result.setdefault('synthetic_errors', []).append({'function': fn.__name__, 'type': type(e).__name__, 'error': str(e)})

    def synthetic_responder():
        (sock, _) = listener.accept()
        sockets.append(sock)
        sock.settimeout(4)
        for phase in (5, 6, 7):
            raw = wire(sock, 'receive')
            (length, copyset, version, txid) = safety.request.HEADER.unpack_from(raw)
            fields = safety.request.REQUEST.unpack(raw[14:38])
            if length != 38 or copyset or version or (fields != (0, 0, GENERATION, phase, 0, 1)):
                raise RuntimeError('内核发送的关闭请求字段错误')
            if a.mode == 'synthetic-missing-ack':
                result['withheld_phase'] = phase
                result['withheld_read'] = sock.recv(1).hex()
                return
            if a.mode == 'synthetic-budget':
                time.sleep(0.6)
            ack_phase = phase + 1 if a.mode == 'synthetic-bad-phase' else phase
            gen = GENERATION + 1 if a.mode == 'synthetic-bad-generation' else GENERATION
            ack = struct.pack('<IHHHHIQ', 0x44534d43, 1, ack_phase, 1, 0, 0, gen)
            if a.mode == 'synthetic-half-ack':
                fragment = safety.frame(ack, txid)[:8]
                sock.sendall(fragment)
                result['partial_ack_hex'] = fragment.hex()
                result['partial_ack_read'] = sock.recv(1).hex()
                return
            wire(sock, 'send', safety.frame(ack, txid))
        tail = sock.recv(1)
        result['responder_eof'] = tail.hex()
        if tail:
            raise RuntimeError('最终确认后出现非 EOF 数据')
        sock.shutdown(socket.SHUT_WR)

    def synthetic_request(sock, phase, channel='control'):
        wire(sock, 'send', safety.read_request(100 + phase, kind=phase, gfn=GENERATION, version=1), channel)
        raw = wire(sock, 'receive', channel=channel)
        (length, copyset, version, txid) = safety.request.HEADER.unpack_from(raw)
        if length != 38 or copyset or version or (txid != 100 + phase):
            raise RuntimeError('关闭确认帧头错误')
        if struct.unpack('<IHHHHIQ', raw[14:38]) != (0x44534d43, 1, phase, 0, 1, 0, GENERATION):
            raise RuntimeError('关闭确认字段错误')

    def synthetic_requester():
        sock = socket.create_connection(('127.0.0.1', 37710), timeout=4)
        sockets.append(sock)
        synthetic_request(sock, 5)
        if a.mode == 'synthetic-late':
            synthetic_request(data_peer, 4, 'data')
            wire(data_peer, 'send', safety.read_request(200), channel='late')
            result['late_receive'] = data_peer.recv(1).hex()
            return
        synthetic_request(sock, 6)
        if a.mode == 'synthetic-missing-final':
            result['withheld_final'] = True
            result['missing_final_read'] = sock.recv(1).hex()
            return
        synthetic_request(sock, 7)
        sock.shutdown(socket.SHUT_WR)
        tail = sock.recv(1)
        result['requester_eof'] = tail.hex()
        if tail:
            raise RuntimeError('管理连接 EOF 后仍有数据')
    def active_write():
        try:
            copy(1, True, safety.PAGE[::-1] * 2)
            result['active_memory_hex'] = memory[1][:].hex()
        except (RuntimeError, OSError) as error:
            result['active_copy_error'] = str(error)

    def await_active(sealed):
        deadline = time.monotonic() + 0.5
        while True:
            row = call(1, 'active_status', 0x8020aef7, bytes(32))
            if row['errno']:
                raise RuntimeError('在途调用状态读取失败')
            version, state, generation, active, error, reserved1, reserved2 = struct.unpack('=IIQIiII', bytes.fromhex(row['output_hex']))
            if (version, state, generation, active, error, reserved1, reserved2) == (1, int(sealed), GENERATION if sealed else 0, 1, 0, 0, 0):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('没有观察到所需的封闭状态与在途 ioctl')
            time.sleep(0.005)

    listener = data_peer = pressure_blob = None
    with a.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '4096')
            for (kind, name, symbol) in PROBES:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            mark('setup')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            count = 1 if a.mode in ('single', 'root-signal', 'validation') else 2
            addrs = [ctypes.create_string_buffer(x) for x in (tuple((x.encode() for x in a.peers)) if a.mode == 'remote' else (b'127.0.0.1', b'127.0.0.2')[:count])]
            ptrs = (ctypes.c_void_p * count)(*[ctypes.addressof(x) for x in addrs])
            for n in [a.node] if a.mode == 'remote' else range(1 if a.mode in ('peer-absent', 'connect-timeout') + SYNTHETIC else count):
                vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
                if a.mode == 'remote':
                    vms[n] = vm
                else:
                    vms.append(vm)
                fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', n, count, ctypes.addressof(ptrs)))
                memory_size = 4096 * 2048 if a.mode == 'synthetic-send-pressure' else 8192
                mm = mmap.mmap(-1, memory_size)
                mm[:] = bytes(memory_size)
                if a.mode == 'remote':
                    memory[n] = mm
                else:
                    memory.append(mm)
                fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, 8192, memory_size, ctypes.addressof(ctypes.c_char.from_buffer(mm))))
            if a.mode not in ('peer-absent', 'connect-timeout', 'remote'):
                count_for_copy = 1 if a.mode in SYNTHETIC else count
                copy(0, True, safety.PAGE * 2)
                for n in range(count_for_copy):
                    if copy(n, False, bytes(8192)) != safety.PAGE * 2:
                        raise RuntimeError('实际页面内容错误')
                if count_for_copy == 2:
                    copy(1, True, safety.PAGE[::-1] * 2)
                    if copy(0, False, bytes(8192)) != safety.PAGE[::-1] * 2:
                        raise RuntimeError('反向页面内容错误')
            if a.mode in ('unknown', 'partial', 'occupied'):
                peer = socket.create_connection(('127.0.0.1', 37710), timeout=3)
                sockets.append(peer)
                if a.mode == 'partial':
                    fragment = safety.read_request(111)[:8]
                    peer.sendall(fragment)
                    result['partial_hex'] = fragment.hex()
                if a.mode == 'occupied':
                    result['occupied_requests'] = []
                    for i in range(8):
                        frame = safety.read_request(110 + i, gfn=20 + i)
                        peer.sendall(frame)
                        result['occupied_requests'].append(frame.hex())
                    peer.sendall(safety.read_request(200)[:8])
                time.sleep(0.1)
                result['injected_tasks'] = safety.tasks()
                row = call(0, 'injected_status', 0x8020aef8, bytes(32))
                if row['errno']:
                    raise RuntimeError('注入状态读取失败')
                fields = struct.unpack('=IIIIiIQ', bytes.fromhex(row['output_hex']))
                if fields[3] != (8 if a.mode == 'occupied' else 0):
                    raise RuntimeError('在途请求数未达到预期')
            if a.mode == 'remote':
                print(json.dumps({'ready': True, 'node': a.node}), flush=True)
                for line in sys.stdin:
                    command = json.loads(line)
                    if command['op'] == 'close':
                        break
                    expected = (safety.PAGE[::-1] if command.get('reverse') else safety.PAGE) * 2
                    observed = copy(a.node, command['op'] == 'write', expected if command['op'] == 'write' else bytes(8192))
                    if observed != expected:
                        raise RuntimeError('跨 VM 页面内容错误')
                    print(json.dumps({'node': a.node, 'op': command['op'], 'sha256': hashlib.sha256(observed).hexdigest()}), flush=True)
                else:
                    raise RuntimeError('管理输入在关闭前结束')
            if a.mode == 'validation':
                params = [1, 0, GENERATION, 1500, 0]
                for (index, value) in ((0, 2), (1, 1), (2, 0), (3, 0), (3, 30001), (4, 1)):
                    invalid = params.copy()
                    invalid[index] = value
                    row = call(0, 'invalid', CLOSE, struct.pack('=IIQII', *invalid))
                    if row['errno'] != errno.EINVAL:
                        raise RuntimeError('非法参数未拒绝')
                addr = ctypes.addressof(ctypes.c_char.from_buffer(memory[0]))
                for unpin in (False, True):
                    row = call(0, 'unpin' if unpin else 'pin', 0x4018aef2, struct.pack('=??6xQQ', False, unpin, addr, 4096))
                    if row['errno']:
                        raise RuntimeError('固定引用操作失败')
                    if not unpin and close(0)['errno'] != errno.EBUSY:
                        raise RuntimeError('仍有固定引用却允许关闭')
            if a.mode in SYNTHETIC:
                setup_synthetic()
            if a.mode == 'root-signal':
                tasks = safety.require_tasks(1)
                result['signal_tasks'] = tasks
                target = next(iter(tasks))
                mark('root_signal')
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.syscall(234, int(target), int(target), 9):
                    raise OSError(ctypes.get_errno(), 'tgkill failed')
                result['tasks_after_signal'] = safety.require_tasks(0, timeout=0.5)
            if a.mode == 'active-ioctl':
                copy(0, True, safety.PAGE * 2)
                addr = ctypes.addressof(ctypes.c_char.from_buffer(memory[0]))
                pin = call(0, 'active_pin', 0x4018aef2, struct.pack('=??6xQQ', False, False, addr, 4096))
                if pin['errno']:
                    raise RuntimeError('不能固定在途操作所需的页面')
                writer = threading.Thread(target=active_write)
                threads.append(writer)
                writer.start()
                await_active(False)
            mark('close_begin')
            if a.mode == 'active-ioctl':
                waiting = start(1)
                await_active(True)
                time.sleep(0.2)
                result['close_waiting_before_unpin'] = waiting.is_alive()
                if not waiting.is_alive():
                    raise RuntimeError('根调用尚未返回，关闭却已结束')
                mark('release_pin')
                unpin = call(0, 'active_unpin', 0x4018aef2, struct.pack('=??6xQQ', False, True, addr, 4096))
                if unpin['errno']:
                    raise RuntimeError('未能解除在途操作的页面固定')
                start(0)
            else:
                start(a.node if a.mode == 'remote' else 0, timeout=250 if a.mode == 'deadline' else 1500)
            if count == 2 and a.mode not in ('active-ioctl', 'peer-absent', 'connect-timeout', 'remote') + SYNTHETIC:
                if a.mode == 'deadline':
                    time.sleep(0.5)
                start(1, generation=GENERATION + 1 if a.mode == 'wrong-generation' else GENERATION)
            if a.mode in SYNTHETIC:
                for fn in (synthetic_responder, synthetic_requester):
                    t = threading.Thread(target=lambda fn=fn: synthetic_thread(fn))
                    threads.append(t)
                    t.start()
            for t in threads:
                t.join(5)
            if any((t.is_alive() for t in threads)):
                raise RuntimeError('关闭调用没有按期限返回')
            if a.mode == 'active-ioctl':
                if result.get('active_copy_error') or bytes.fromhex(result.get('active_memory_hex', '')) != safety.PAGE[::-1] * 2:
                    raise RuntimeError('在途根调用未完成实际内存写入')
            result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=3)
            mark('observed')
            closed = [x for x in result['calls'] if x['name'] == 'close' and x['errno'] != errno.EBUSY]
            if a.mode == 'synthetic-clean' and result.get('synthetic_errors'):
                raise RuntimeError('受控正常对端失败')
            if a.mode in ('single', 'pair', 'remote', 'validation', 'synthetic-clean', 'active-ioctl') and any((x['errno'] for x in closed)):
                raise RuntimeError('正常关闭失败')
            if a.mode not in ('single', 'pair', 'remote', 'validation', 'synthetic-clean', 'active-ioctl') and any((not x['errno'] for x in closed)):
                raise RuntimeError('故障被误报为关闭成功')
        except (OSError, RuntimeError, ValueError, AssertionError) as e:
            result['errors'].append(str(e))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            for s in sockets:
                s.close()
            for t in threads:
                t.join(5)
            if any((t.is_alive() for t in threads)):
                result['errors'].append('仍有调用者，保留映射')
            else:
                for vm in vms:
                    if vm is not None:
                        os.close(vm)
                for mm in memory:
                    if mm is not None:
                        mm.close()
                if kvm is not None:
                    os.close(kvm)
            result['remaining_tasks'] = safety.request.await_tasks(0, 3)
            if instance.exists():
                mark('cleanup_complete')
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {x.name: (x / 'stats').read_text() for x in (instance / 'per_cpu').iterdir()}
                names = {name for (_, name, _) in PROBES}
                result['kprobe_profile'] = '\n'.join((x for x in (root / 'kprobe_profile').read_text().splitlines() if x.split() and x.split()[0] in names))
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ('mode', 'errors', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))
if __name__ == '__main__':
    main()
