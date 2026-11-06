#!/usr/bin/env python3
"""在独占研究 VM 用真实页固定和单个合成读请求复核副本集合重试路径。"""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import re
import select
import socket
import struct
import subprocess
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


device = load('probe-dsm-device')
request = load('probe-request-cancel')
trace = request.trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pin', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        parser.error('需要显式指定的独占 x86 研究内核和 root')
    if request.tasks():
        parser.error('已有 DSM 线程')
    ports = subprocess.check_output(['ss', '-H', '-tan', '( sport = :37710 or sport = :37711 or sport = :40000 or sport = :40001 )'])
    if ports.strip():
        parser.error('实验端口存在 TCP 状态')
    root = Path('/sys/kernel/tracing')
    group = f'sshpool_copyset_{os.getpid()}'
    instance = root / 'instances' / group
    events = [('p', 'copy_lock', 'dsm_lock_killable slot=$arg1:x64 vfn=$arg2:x64'),
              ('r64', 'copy_locked', 'dsm_lock_killable code=$retval:s32'),
              ('p', 'copy_unlock', 'dsm_unlock slot=$arg2:x64 vfn=$arg3:x64'),
              ('r64', 'copy_done', 'ivy_kvm_dsm_handle_req code=$retval:s32')]
    names = {event for _, event, _ in events}
    if any(row.split()[0] in names for row in (root / 'kprobe_profile').read_text().splitlines() if row.split()):
        parser.error('存在同名跟踪事件')
    registered = []
    result = {'kernel': platform.release(), 'pin': args.pin, 'errors': [], 'events': []}
    vm = None
    kvm = None
    memory = None
    peer = None
    pinned = False

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def pin(unpin):
        # 与内核 ABI 一致：只读固定阻塞远端读请求，布尔字段后六字节对齐。
        fcntl.ioctl(vm, 0x4018AEF2, struct.pack('=??6xQQ', False, unpin, address, 4096))

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '16384')
            for kind, name, symbol in events:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
                trace.write(instance / 'events' / group / name / 'filter', f'common_pid != {os.getpid()}')
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            if fcntl.ioctl(kvm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM) != 1:
                raise RuntimeError('缺少 DSM capability')
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            peers = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in peers))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 4096)
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, 8192, 4096, address))
            expected = bytes((index * 17 + 3) % 256 for index in range(4096))
            buffer = ctypes.create_string_buffer(expected)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(buffer), 4096))
            result['expected_page_sha256'] = hashlib.sha256(expected).hexdigest()
            result['vfn'] = address >> 12
            mark('owner_initialized')
            if args.pin:
                pin(False)
                pinned = True
                mark('page_pinned')
            peer = socket.create_connection(('127.0.0.1', 37710), timeout=5)
            peer.settimeout(2)
            result['initial_tasks'] = request.await_tasks(9, 3)
            if len(result['initial_tasks']) != 9:
                raise RuntimeError('服务线程数不符')
            payload = request.request_frame()
            result['request_hex'] = payload.hex()
            profile = (root / 'kprobe_profile').read_text().splitlines()
            initial_unlocks = next(int(row.split()[1]) for row in profile if row.split()[0] == 'copy_unlock')
            mark('request_sent')
            peer.sendall(payload)
            if args.pin:
                deadline = time.monotonic() + 3
                while True:
                    profile = (root / 'kprobe_profile').read_text().splitlines()
                    unlocks = next(int(row.split()[1]) for row in profile if row.split()[0] == 'copy_unlock') - initial_unlocks
                    if unlocks >= 2:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('未观察到两次服务请求重试')
                    time.sleep(0.002)
                result['observed_retry_unlocks'] = unlocks
                result['response_before_unpin'] = bool(select.select([peer], [], [], 0)[0])
                if result['response_before_unpin']:
                    raise RuntimeError('固定期间出现提前响应或断连')
                mark('unpin_begin')
                pin(True)
                pinned = False
                mark('unpin_done')
            try:
                result['response'] = request.read_page(peer)
            except (OSError, RuntimeError) as error:
                result['response_error'] = str(error)
            mark('read_complete')
        except (OSError, ValueError, RuntimeError) as error:
            result['errors'].append(str(error))
        finally:
            if pinned:
                pin(True)
            if peer is not None:
                peer.close()
            if vm is not None:
                mark('close_begin')
                os.close(vm)
                result['vm_closed'] = True
                mark('close_done')
            if memory is not None:
                memory.close()
            if kvm is not None:
                os.close(kvm)
            if instance.exists():
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text() for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines()
                                                   if row.split() and row.split()[0] in names)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            result['remaining_tasks'] = request.tasks()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('trace', 'trace_stats', 'initial_tasks', 'request_hex')}))
    raise SystemExit(bool(result['errors']) or not result.get('response', {}).get('matches', False))


if __name__ == '__main__':
    main()
