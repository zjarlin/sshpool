#!/usr/bin/env python3
"""独占实验中验证跨 ioctl 固定引用、关闭拒绝、错误解除及取页失败回滚。"""
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
import select
import socket
import struct
import subprocess
import threading
import time

spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('probe-ioctl-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
device, safety, trace = admission.device, admission.safety, admission.trace
PIN = 0x4018AEF2
STATUS = 0x8020AEF9
MODES = ('service', 'lifecycle', 'active', 'rollback')
PROBES = [('p', 'pp_enter', 'kvm_dsm_ioctl_enter ioctl=$arg2:x32 vm=$arg3:u8'),
          ('r128', 'pp_entered', 'kvm_dsm_ioctl_enter code=$retval:s32'),
          ('p', 'pp_leave', 'kvm_dsm_ioctl_leave token=$arg2:s32'),
          ('r128', 'pp_left', 'kvm_dsm_ioctl_leave'),
          ('p', 'pp_dsm', 'kvm_vm_ioctl_dsm ioctl=$arg2:x32'),
          ('r128', 'pp_done', 'kvm_vm_ioctl_dsm code=$retval:s32'),
          ('p', 'pp_seal', 'kvm_dsm_ioctl_drain'),
          ('r128', 'pp_sealed', 'kvm_dsm_ioctl_drain code=$retval:s32')]
NEW_PROBES = [('p', 'pp_change', 'kvm_dsm_pin_change.isra.0'),
              ('r128', 'pp_changed', 'kvm_dsm_pin_change.isra.0 code=$retval:s32'),
              ('p', 'pp_slots', 'kvm_dsm_has_pins'),
              ('r128', 'pp_busy', 'kvm_dsm_has_pins code=$retval:u8')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    baseline = args.require_kernel == '7.1.0-rc3-sshpool-gvm-pf22'
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel not in ('7.1.0-rc3-sshpool-gvm-pf22', '7.1.0-rc3-sshpool-gvm-pf23') or
            platform.release() != args.require_kernel or (baseline and args.mode != 'service')):
        parser.error('只允许独占 PF22 对照或 PF23 候选，必须显式匹配内核与架构')
    if safety.tasks():
        parser.error('已有 DSM 线程')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有实验进程')
    ports = ' or '.join(f'{side} = :{port}' for side in ('sport', 'dport') for port in (37710, 37711, 40000, 40001))
    if subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip():
        parser.error('实验端口仍有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有跟踪')
    group = f'sshpool_pins_{os.getpid()}'
    instance = root / 'instances' / group
    probes = PROBES + ([] if baseline else NEW_PROBES)
    result = {'kernel': platform.release(), 'mode': args.mode, 'baseline': baseline, 'errors': [],
              'events': [], 'calls': [], 'statuses': [], 'requests': [], 'responses': [], 'worker': {}}
    kvm = vm = memory = worker = None
    registered, sockets = [], []

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def call(name, ioctl, raw, expected):
        row = {'name': name, 'ioctl': ioctl, 'hex': raw.hex(), 'tid': threading.get_native_id(), 'start_ns': time.monotonic_ns()}
        try:
            value = fcntl.ioctl(vm, ioctl, raw)
            row['errno'] = 0
        except OSError as error:
            row['errno'] = error.errno
        row['end_ns'] = time.monotonic_ns()
        result['calls'].append(row)
        if row['errno'] != expected:
            raise RuntimeError(f'{name}: errno={row["errno"]}, expected={expected}')
        return row

    def pin(name, offset, length, write=False, unpin=False, expected=0):
        return call(name, PIN, struct.pack('=??6xQQ', write, unpin, address + offset, length), expected)

    def drain(name, expected):
        row = call(name, admission.DRAIN, struct.pack('=IIQII', 1, 0, admission.GENERATION, 1000, 0), expected)
        row['admission_status'] = fcntl.ioctl(vm, admission.STATUS, bytes(32)).hex()

    def status(name, expected):
        raw = fcntl.ioctl(vm, STATUS, bytes(32))
        values = struct.unpack('=IIQQiI', raw)
        result['statuses'].append({'name': name, 'hex': raw.hex(), 'version': values[0], 'active': values[1],
                                   'read': values[2], 'write': values[3], 'error': values[4], 'reserved': values[5],
                                   'time_ns': time.monotonic_ns()})
        if values != (1, *expected, 0, 0):
            raise RuntimeError(f'{name}: actual={values}, expected={expected}')

    def peer():
        value = socket.create_connection(('127.0.0.1', 37710), timeout=3)
        sockets.append(value)
        return value

    def send(value, data):
        result['requests'].append(data.hex())
        value.sendall(data)

    def response(value):
        result['responses'].append(safety.response(value))

    def region(name, slot, gfn, size, offset, expected=0, flags=0):
        call(name, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', slot, flags, gfn * 4096, size, address + offset), expected)

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '4096')
            for kind, name, symbol in probes:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 12288)
            memory[:] = safety.PAGE * 3
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            result['address'] = address
            if args.mode == 'rollback':
                region('setup_first', 0, 2, 4096, 0)
                region('setup_second', 1, 3, 4096, 4096)
            else:
                region('setup', 0, 2, 12288, 0)
            initial = ctypes.create_string_buffer(safety.PAGE * 2)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(initial), 8192))
            if not baseline:
                status('initial', (0, 0, 0))
            mark('case_begin')
            if args.mode == 'service':
                pin('hold_read', 0, 4096)
                if not baseline:
                    status('held', (0, 1, 0))
                stream = peer()
                send(stream, safety.read_request(42))
                before = time.monotonic_ns()
                result['blocked_readable'] = bool(select.select([stream], [], [], 0.15)[0])
                result['blocked_wait_ns'] = time.monotonic_ns() - before
                result['blocked_tasks'] = safety.tasks()
                if result['blocked_readable']:
                    raise RuntimeError('固定读页面仍然被提前交出')
                mark('blocked_observed')
                drain('drain_pinned', 0 if baseline else 16)
                pin('release_read', 0, 4096, unpin=True, expected=108 if baseline else 0)
                if baseline:
                    result['still_blocked'] = not bool(select.select([stream], [], [], 0.1)[0])
                else:
                    response(stream)
                    status('released', (0, 0, 0))
                    drain('drain_released', 0)
            elif args.mode == 'lifecycle':
                pin('unmatched', 0, 4096, unpin=True, expected=22)
                pin('zero_length', 0, 0)
                pin('read_cross_page', 4080, 32)
                status('read_two', (0, 2, 0))
                pin('write_overlap', 0, 1, write=True)
                status('mixed', (0, 2, 1))
                pin('wrong_kind', 4096, 4096, write=True, unpin=True, expected=22)
                pin('partly_unmatched', 0, 12288, unpin=True, expected=22)
                status('unchanged_after_invalid', (0, 2, 1))
                pin('read_overlap', 0, 1)
                status('overlap_refs', (0, 3, 1))
                region('delete_pinned', 0, 2, 0, 0, expected=16)
                region('move_pinned', 0, 6, 12288, 0, expected=16)
                region('flags_pinned', 0, 2, 12288, 0, expected=16, flags=1)
                region('alias_pinned', 1, 8, 4096, 0, expected=16)
                drain('drain_pinned', 16)
                pin('release_overlap', 0, 1, unpin=True)
                pin('release_cross_page', 4080, 32, unpin=True)
                pin('release_write', 0, 1, write=True, unpin=True)
                pin('duplicate_release', 0, 1, write=True, unpin=True, expected=22)
                status('released', (0, 0, 0))
                region('delete_released', 0, 2, 0, 0)
                region('restore_released', 0, 2, 12288, 0)
                drain('drain_released', 0)
                pin('new_after_seal', 0, 4096, expected=108)
            elif args.mode == 'rollback':
                region('remove_second', 1, 3, 0, 4096)
                pin('preexisting_read', 0, 4096)
                status('preexisting', (0, 1, 0))
                pin('failed_range', 0, 8192, expected=14)
                status('rolled_back', (0, 1, 0))
                pin('first_still_usable', 0, 4096)
                status('first_held', (0, 2, 0))
                pin('release_first', 0, 4096, unpin=True)
                pin('release_preexisting', 0, 4096, unpin=True)
                region('restore_second', 1, 3, 4096, 4096)
                pin('range_repaired', 0, 8192)
                status('repaired', (0, 2, 0))
                pin('release_repaired', 0, 8192, unpin=True)
                status('released', (0, 0, 0))
                drain('drain_released', 0)
            else:
                stream = peer()
                send(stream, safety.read_request(42, gfn=3))
                response(stream)
                listener = socket.socket()
                listener.settimeout(3)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                sockets.append(listener)
                def run_pin():
                    try:
                        result['worker'] = pin('active_pin', 0, 8192, write=True)
                    except (OSError, RuntimeError) as error:
                        result['errors'].append(str(error))
                worker = threading.Thread(target=run_pin)
                worker.start()
                outgoing, _ = listener.accept()
                outgoing.settimeout(3)
                sockets.append(outgoing)
                raw = safety.receive_frame(outgoing)
                result['outgoing_request'] = raw.hex()
                status('pending', (1, 0, 1))
                mark('pending_observed')
                drain('drain_active_pin', 16)
                txid = safety.request.HEADER.unpack_from(raw)[3]
                injected = safety.frame(safety.PAGE, txid, copyset=1)
                result['injected'] = injected.hex()
                outgoing.sendall(injected)
                worker.join(3)
                if worker.is_alive():
                    raise RuntimeError('固定调用未完成')
                status('completed', (0, 0, 2))
                drain('drain_pinned', 16)
                pin('release_completed', 0, 8192, write=True, unpin=True)
                status('released', (0, 0, 0))
                drain('drain_released', 0)
            result['page_sha256'] = hashlib.sha256(memory[:4096]).hexdigest()
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            for value in sockets:
                value.close()
            if worker is not None:
                worker.join(5)
            if worker is not None and worker.is_alive():
                result['errors'].append('固定线程仍存活，保留其映射')
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
                names = {name for _, name, _ in probes}
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines() if row.split() and row.split()[0] in names)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result.get(key) for key in ('mode', 'baseline', 'errors', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
