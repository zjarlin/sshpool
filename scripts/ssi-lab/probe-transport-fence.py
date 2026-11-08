#!/usr/bin/env python3
"""在独占 PF25 VM 验证本地传输封闭与真实反向请求；不把它当作全局正常关闭。"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import threading
import time

spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('probe-ioctl-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
device, safety, trace = admission.device, admission.safety, admission.trace
FENCE = 0x4018AEFA
STATUS = 0x8020AEF8
GENERATION = 0x534449002525
MODES = ('validation', 'reverse', 'cached', 'timeout', 'late', 'fault', 'race')
PROBES = [('p', 'tf_ioctl', 'kvm_vm_ioctl ioctl=$arg2:x32'),
          ('r128', 'tf_return', 'kvm_vm_ioctl code=$retval:s32'),
          ('p', 'tf_request', 'kvm_dsm_request_count add=$arg2:u8'),
          ('r128', 'tf_requested', 'kvm_dsm_request_count code=$retval:s32'),
          ('p', 'tf_exchange', 'kvm_dsm_exchange_begin'),
          ('r128', 'tf_exchanged', 'kvm_dsm_exchange_begin code=$retval:s32'),
          ('p', 'tf_retire', 'kvm_dsm_exchange_done'),
          ('p', 'tf_cache', 'kvm_dsm_cache_count add=$arg2:u8'),
          ('p', 'tf_receive', 'ktcp_receive cb=$arg1:x64 txid=+4($arg5):u16'),
          ('p', 'tf_failure', 'kvm_dsm_fail code=$arg2:s32')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel != '7.1.0-rc3-sshpool-gvm-pf25' or platform.release() != args.require_kernel):
        parser.error('只允许显式指定的独占 PF25 x86 内核与 root')
    if safety.tasks():
        parser.error('已有 DSM 线程')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError, ProcessLookupError):
            continue
        if name.startswith(('qemu-system-', 'memfd:sshpool', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有其他实验进程')
    ports = ' or '.join(f'{side} = :{port}' for side in ('sport', 'dport') for port in (37710, 37711, 40000, 40001))
    if subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip():
        parser.error('实验端口仍有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有跟踪，拒绝混用')
    group = f'sshpool_fence_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [],
              'calls': [], 'statuses': [], 'requests': [], 'responses': [], 'outgoing_requests': [],
              'injected': [], 'generation': GENERATION, 'full_vm_shutdown_accepted': False,
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    sockets, threads, registered = [], [], []
    kvm = vm = memory = None

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def call(name, command, data):
        row = {'name': name, 'ioctl': command, 'tid': threading.get_native_id(),
               'input_hex': data.hex(), 'start_ns': time.monotonic_ns()}
        try:
            raw = fcntl.ioctl(vm, command, data)
            row['output_hex'] = raw.hex()
            row['errno'] = 0
        except OSError as error:
            row['errno'] = error.errno
        row['end_ns'] = time.monotonic_ns()
        result['calls'].append(row)
        return row

    def fence(name, timeout=3000, generation=GENERATION, version=1, flags=0, reserved=0):
        return call(name, FENCE, struct.pack('=IIQII', version, flags, generation, timeout, reserved))

    def status(name):
        observed = call('status_' + name, STATUS, bytes(32))
        require_error(observed, 0)
        raw = bytes.fromhex(observed['output_hex'])
        version, exchanges, cached, inbound, error, state, generation = struct.unpack('=IIIIiIQ', raw)
        row = dict(name=name, version=version, exchanges=exchanges, cached=cached, inbound=inbound,
                   error=error, state=state, generation=generation, time_ns=time.monotonic_ns(), hex=raw.hex())
        if version != 2:
            raise RuntimeError('需要传输状态版本二')
        result['statuses'].append(row)
        return row

    def await_status(name, counts):
        deadline = time.monotonic() + 3
        while True:
            row = status(name)
            if (row['exchanges'], row['cached'], row['inbound']) == counts:
                return row
            if time.monotonic() >= deadline:
                raise RuntimeError(f'未达到计数 {counts}: {row}')
            time.sleep(0.005)

    def send(peer, value):
        result['requests'].append(value.hex())
        peer.sendall(value)

    def inject(value):
        result['injected'].append(value.hex())
        outgoing.sendall(value)

    def start_waiter():
        waiter = threading.Thread(target=lambda: fence('waiter'))
        threads.append(waiter)
        waiter.start()
        return waiter

    def require_error(row, expected):
        if row['errno'] != expected:
            raise RuntimeError(f'调用 {row["name"]} 错误码不符: {row["errno"]} != {expected}')

    def blocked_reader():
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            snapshot = safety.tasks()
            found = [int(pid) for pid, item in snapshot.items()
                     if any('tcp_recvmsg' in line for line in item['stack']) and
                     any('kvm_dsm_fetch' in line for line in item['stack'])]
            if len(found) == 1:
                result['partial_reader_tasks'] = snapshot
                return found[0]
            time.sleep(0.005)
        raise RuntimeError('未找到唯一半帧读者')

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '4096')
            for kind, name, symbol in PROBES:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            if args.mode == 'validation':
                require_error(fence('not_enabled'), errno.EINVAL)
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2', b'127.0.0.3')]
            pointers = (ctypes.c_void_p * 3)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 3, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 8192)
            memory[:] = safety.PAGE * 2
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, 8192, 8192, address))
            initial = ctypes.create_string_buffer(safety.PAGE * 2)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(initial), 8192))
            if args.mode == 'validation':
                require_error(fence('unsealed'), errno.EPERM)
                for key, value in (('version', 2), ('flags', 1), ('generation', 0), ('timeout', 0), ('timeout', 30001), ('reserved', 1)):
                    require_error(fence('invalid_' + key + '_' + str(value), **{key: value}), errno.EINVAL)
            peer = socket.create_connection(('127.0.0.1', 37710), timeout=3)
            sockets.append(peer)
            if args.mode in ('reverse', 'cached', 'timeout', 'fault'):
                for index in range(2):
                    send(peer, safety.read_request(42 + index, gfn=2 + index))
                    result['responses'].append(safety.response(peer))
            require_error(call('seal', admission.DRAIN, struct.pack('=IIQII', 1, 0, GENERATION, 3000, 0)), 0)
            mark('sealed')
            if args.mode == 'validation':
                require_error(fence('wrong_generation', generation=GENERATION + 1), errno.ESTALE)
            if args.mode in ('validation', 'late'):
                require_error(fence('fence'), 0)
                status('fenced')
                require_error(fence('repeat'), 0)
                require_error(fence('different_generation', generation=GENERATION + 1), errno.ESTALE)
                require_error(call('new_copy', device.DSM_MEMCPY, device.copy_request(True, address, 1, 0)), errno.ESHUTDOWN)
                if args.mode == 'late':
                    mark('late_request')
                    send(peer, safety.read_request(100, gfn=2))
                    result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=5)
                    require_error(call('failed_status', STATUS, bytes(32)), errno.EIO)
            elif args.mode == 'race':
                barrier = threading.Barrier(2)
                def racing_fence():
                    barrier.wait()
                    fence('racing_fence')
                waiter = threading.Thread(target=racing_fence)
                threads.append(waiter)
                waiter.start()
                barrier.wait()
                send(peer, safety.read_request(100, gfn=2))
                waiter.join(4)
                if waiter.is_alive():
                    raise RuntimeError('竞争中的传输封闭等待者没有退出')
                try:
                    result['responses'].append(safety.response(peer))
                except (OSError, RuntimeError) as error:
                    result['race_receive_error'] = str(error)
                    result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=5)
                    require_error(call('race_status', STATUS, bytes(32)), errno.EIO)
                else:
                    status('fenced')
            else:
                listener = socket.socket()
                sockets.append(listener)
                listener.settimeout(3)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                for index in range(2):
                    send(peer, safety.read_request(100 + index, gfn=2 + index, requester=2, sender=2))
                outgoing, _ = listener.accept()
                sockets.append(outgoing)
                outgoing.settimeout(3)
                for _ in range(2):
                    result['outgoing_requests'].append(safety.receive_frame(outgoing).hex())
                await_status('pending', (2, 0, 2))
                ids = [safety.request.HEADER.unpack_from(bytes.fromhex(raw))[3] for raw in result['outgoing_requests']]
                mark('pending_observed')
                if args.mode == 'timeout':
                    require_error(fence('timeout', timeout=100), errno.ETIMEDOUT)
                    status('after_timeout')
                waiter = start_waiter()
                time.sleep(0.1)
                result['waiter_alive_while_pending'] = waiter.is_alive()
                status('while_pending')
                if args.mode == 'fault':
                    mark('inject_fault')
                    send(peer, safety.read_request(200, kind=255))
                    result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=5)
                elif args.mode == 'cached':
                    inject(struct.pack('<Q', 4110))
                    tid = blocked_reader()
                    lines = [line for line in (instance / 'trace').read_text().splitlines()
                             if f'-{tid} ' in line and 'tf_receive:' in line and 'txid=255' not in line]
                    if len(lines) != 1:
                        raise RuntimeError('半帧读者事务记录不唯一')
                    own = int(lines[0].split('txid=')[1].split()[0])
                    other = next(value for value in ids if value != own)
                    result.update(partial_reader_pid=tid, held_txid=own, cached_txid=other)
                    foreign = safety.frame(safety.PAGE, other, copyset=1)
                    own_frame = safety.frame(safety.PAGE, own, copyset=1)
                    inject(foreign[8:] + own_frame[:8])
                    await_status('cached', (2, 1, 2))
                    result['waiter_alive_while_cached'] = waiter.is_alive()
                    mark('release_cached')
                    inject(own_frame[8:])
                else:
                    mark('release_responses')
                    for txid in reversed(ids):
                        inject(safety.frame(safety.PAGE, txid, copyset=1))
                if args.mode != 'fault':
                    for _ in range(2):
                        result['responses'].append(safety.response(peer))
                waiter.join(4)
                if waiter.is_alive():
                    raise RuntimeError('传输封闭等待者没有退出')
                if args.mode == 'fault':
                    require_error(call('failed_status', STATUS, bytes(32)), errno.EIO)
                else:
                    status('fenced')
                    require_error(fence('repeat'), 0)
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError, StopIteration) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            for value in sockets:
                value.close()
            for worker in threads:
                worker.join(5)
            if any(worker.is_alive() for worker in threads):
                result['errors'].append('仍有调用线程，保留映射')
            else:
                if vm is not None:
                    os.close(vm)
                if memory is not None:
                    memory.close()
                if kvm is not None:
                    os.close(kvm)
            result['remaining_tasks'] = safety.request.await_tasks(0, 3)
            if instance.exists():
                mark('cleanup_complete')
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text() for cpu in (instance / 'per_cpu').iterdir()}
                names = {name for _, name, _ in PROBES}
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines()
                                                    if row.split() and row.split()[0] in names)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result.get(key) for key in ('mode', 'errors', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
