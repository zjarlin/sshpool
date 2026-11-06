#!/usr/bin/env python3
"""在独占 PF21/PF22 VM 核查真实出站事务登记、反向请求及缓存响应消费。"""
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
STATUS = 0x8020AEF8
MODES = ('external', 'reverse', 'unknown', 'duplicate', 'partial-cancel', 'connect-fault')
PROBES = [('p', 'ex_begin', 'kvm_dsm_exchange_begin'),
          ('r128', 'ex_began', 'kvm_dsm_exchange_begin code=$retval:s32'),
          ('p', 'ex_done', 'kvm_dsm_exchange_done'),
          ('r128', 'ex_finished', 'kvm_dsm_exchange_done'),
          ('p', 'ex_register', 'ktcp_begin_transaction cb=$arg1:x64'),
          ('r128', 'ex_registered', 'ktcp_begin_transaction code=$retval:s32'),
          ('p', 'ex_retire', 'ktcp_end_transaction cb=$arg1:x64 txid=+16($arg2):u16'),
          ('r128', 'ex_retired', 'ktcp_end_transaction'),
          ('p', 'ex_receive', 'ktcp_receive cb=$arg1:x64 capacity=$arg3:u64 txid=+4($arg5):u16'),
          ('r128', 'ex_received', 'ktcp_receive code=$retval:s32'),
          ('p', 'ex_cache', 'kvm_dsm_cache_count add=$arg2:u8'),
          ('r128', 'ex_cached', 'kvm_dsm_cache_count'),
          ('p', 'ex_inbound', 'kvm_dsm_request_count add=$arg2:u8'),
          ('p', 'ex_failure', 'kvm_dsm_fail code=$arg2:s32')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel not in ('7.1.0-rc3-sshpool-gvm-pf21', '7.1.0-rc3-sshpool-gvm-pf22') or platform.release() != args.require_kernel):
        parser.error('只允许显式指定的独占 PF21/PF22 x86 内核与 root')
    if safety.tasks():
        parser.error('已有 DSM 线程')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有其他实验进程')
    ports = ' or '.join(f'{side} = :{port}' for side in ('sport', 'dport') for port in (37710, 37711, 40000, 40001))
    if subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip():
        parser.error('实验端口仍有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有跟踪，拒绝混用')
    group = f'sshpool_exchange_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [],
              'statuses': [], 'requests': [], 'responses': [], 'outgoing_requests': [], 'injected': [], 'worker': {}}
    kvm = vm = memory = worker = None
    registered, sockets = [], []

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def status(name):
        raw = fcntl.ioctl(vm, STATUS, bytes(32))
        values = struct.unpack('=IIIIiIII', raw)
        row = dict(name=name, version=values[0], exchanges=values[1], cached=values[2], inbound=values[3],
                   error=values[4], reserved=list(values[5:]), hex=raw.hex(), time_ns=time.monotonic_ns())
        result['statuses'].append(row)
        return row

    def await_status(name, counts):
        deadline = time.monotonic() + 3
        while True:
            row = status(name)
            if (row['exchanges'], row['cached'], row['inbound']) == counts:
                return row
            if time.monotonic() >= deadline:
                raise RuntimeError(f'统计未达到 {name} {counts}: {row}')
            time.sleep(0.005)

    def send_request(value):
        result['requests'].append(value.hex())
        peer.sendall(value)

    def inject(value):
        result['injected'].append(value.hex())
        outgoing.sendall(value)

    def fault_observed():
        result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=5)
        try:
            fcntl.ioctl(vm, STATUS, bytes(32))
            result['management_errno'] = 0
        except OSError as error:
            result['management_errno'] = error.errno
        if result['management_errno'] != errno.EIO:
            raise RuntimeError('故障后管理入口未失效')

    def blocked_reader():
        deadline = time.monotonic() + 3
        while True:
            snapshot = safety.tasks()
            blocked = {pid: item for pid, item in snapshot.items() if
                       any('tcp_recvmsg' in line for line in item['stack']) and
                       any('ktcp_receive' in line for line in item['stack']) and
                       any('kvm_dsm_fetch' in line for line in item['stack'])}
            if len(blocked) == 1:
                result['partial_reader_tasks'] = snapshot
                result['partial_reader_pid'] = int(next(iter(blocked)))
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('未找到独占半帧接收锁的出站事务')
            time.sleep(0.005)

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
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2', b'127.0.0.3')]
            pointers = (ctypes.c_void_p * 3)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 3, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 8192)
            memory[:] = safety.PAGE * 2
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, 8192, 8192, address))
            initial = ctypes.create_string_buffer(safety.PAGE * 2)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(initial), 8192))
            peer = socket.create_connection(('127.0.0.1', 37710), timeout=3)
            sockets.append(peer)
            for index in range(2):
                send_request(safety.read_request(42 + index, gfn=2 + index))
                result['responses'].append(safety.response(peer))
            await_status('initial', (0, 0, 0))
            if args.mode != 'connect-fault':
                listener = socket.socket()
                listener.settimeout(3)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                sockets.append(listener)
            mark('case_begin')
            if args.mode == 'external':
                source = ctypes.create_string_buffer(bytes((i * 7 + 11) % 256 for i in range(4096)))
                def write():
                    result['worker']['tid'] = threading.get_native_id()
                    try:
                        fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(source), 4096))
                        result['worker']['errno'] = 0
                    except OSError as error:
                        result['worker']['errno'] = error.errno
                worker = threading.Thread(target=write)
                worker.start()
                expected = (1, 0, 0)
                pending = 1
            else:
                fcntl.ioctl(vm, admission.DRAIN, struct.pack('=IIQII', 1, 0, admission.GENERATION, 3000, 0))
                result['ioctl_status_after_seal'] = fcntl.ioctl(vm, admission.STATUS, bytes(32)).hex()
                pending = 1 if args.mode == 'connect-fault' else 2
                for index in range(pending):
                    send_request(safety.read_request(100 + index, gfn=2 + index, requester=2, sender=2))
                expected = (pending, 0, pending)
            if args.mode == 'connect-fault':
                fault_observed()
            else:
                outgoing, _ = listener.accept()
                sockets.append(outgoing)
                outgoing.settimeout(3)
                for _ in range(pending):
                    result['outgoing_requests'].append(safety.receive_frame(outgoing).hex())
                await_status('pending', expected)
                mark('pending_observed')
                ids = [safety.request.HEADER.unpack_from(bytes.fromhex(value))[3] for value in result['outgoing_requests']]
                if len(set(ids)) != pending or 255 in ids:
                    raise RuntimeError('在途事务编号重复或使用了通配编号')
                if args.mode == 'external':
                    inject(safety.frame(safety.PAGE, ids[0], copyset=1))
                    worker.join(3)
                    if worker.is_alive() or result['worker']['errno']:
                        raise RuntimeError('正常出站写入未完成')
                    result['page_sha256'] = hashlib.sha256(memory[:4096]).hexdigest()
                    await_status('final', (0, 0, 0))
                elif args.mode == 'unknown':
                    inject(safety.frame(safety.PAGE, 50000, copyset=1))
                    fault_observed()
                else:
                    inject(struct.pack('<Q', 4110))
                    blocked_reader()
                    if args.mode == 'partial-cancel':
                        mark('cancel_partial')
                        os.close(vm)
                        vm = None
                        result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=5)
                    else:
                        # 首八字节只有长度；确定持锁读者后才选择另一个在途事务作为响应目标。
                        events = (instance / 'trace').read_text().splitlines()
                        tid = result['partial_reader_pid']
                        lines = [line for line in events if f'-{tid} ' in line and 'ex_receive:' in line and 'txid=255' not in line]
                        if len(lines) != 1:
                            raise RuntimeError('无法唯一对应半帧读者的事务编号')
                        own = int(lines[0].split('txid=')[1].split()[0])
                        other = next(value for value in ids if value != own)
                        result['held_txid'], result['cached_txid'] = own, other
                        foreign = safety.frame(safety.PAGE, other, copyset=1)
                        if args.mode == 'duplicate':
                            inject(foreign[8:] + foreign)
                            fault_observed()
                        else:
                            own_frame = safety.frame(safety.PAGE, own, copyset=1)
                            inject(foreign[8:] + own_frame[:8])
                            await_status('cached', (2, 1, 2))
                            mark('cached_observed')
                            inject(own_frame[8:])
                            for _ in range(pending):
                                result['responses'].append(safety.response(peer))
                            await_status('final', (0, 0, 0))
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError, StopIteration) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            for value in sockets:
                value.close()
            if worker is not None:
                worker.join(5)
            if worker is not None and worker.is_alive():
                result['errors'].append('清理时写入线程仍存活，保留映射')
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
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines() if row.split() and row.split()[0] in names)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result.get(key) for key in ('mode', 'errors', 'worker', 'management_errno', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
