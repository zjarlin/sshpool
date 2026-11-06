#!/usr/bin/env python3
"""在独占 KVM 中制造取页与解除固定的反向依赖，并验证暂存引用不可提前解除。"""
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
PIN, STATUS = 0x4018AEF2, 0x8020AEF9
MODES = ('dependency', 'pending', 'pending-write', 'empty', 'rollback', 'duplicate')
PROBES = [('p', 'pr_enter', 'kvm_dsm_ioctl_enter ioctl=$arg2:x32 vm=$arg3:u8'),
          ('r128', 'pr_entered', 'kvm_dsm_ioctl_enter code=$retval:s32'),
          ('p', 'pr_leave', 'kvm_dsm_ioctl_leave token=$arg2:s32'),
          ('r128', 'pr_left', 'kvm_dsm_ioctl_leave'),
          ('p', 'pr_dsm', 'kvm_vm_ioctl_dsm ioctl=$arg2:x32'),
          ('r128', 'pr_done', 'kvm_vm_ioctl_dsm code=$retval:s32'),
          ('p', 'pr_slots', 'kvm_dsm_has_pins'),
          ('r128', 'pr_busy', 'kvm_dsm_has_pins code=$retval:u8')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    baseline = args.require_kernel.endswith('-pf23')
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel not in ('7.1.0-rc3-sshpool-gvm-pf23', '7.1.0-rc3-sshpool-gvm-pf24') or
            platform.release() != args.require_kernel or (baseline and args.mode != 'dependency')):
        parser.error('只允许独占 PF23 反向依赖对照或 PF24 候选，要求 root 与精确内核')
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
        parser.error('实验端口尚有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有跟踪')
    group = f'sshpool_pin_release_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'kernel': platform.release(), 'baseline': baseline, 'mode': args.mode, 'errors': [],
              'events': [], 'calls': [], 'statuses': [], 'requests': [], 'responses': [], 'jobs': {}}
    kvm = vm = memory = outgoing = None
    registered, sockets, threads = [], [], []
    response_sent = False
    injected = None

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def call(name, ioctl, raw, expected):
        row = {'name': name, 'ioctl': ioctl, 'hex': raw.hex(), 'tid': threading.get_native_id(), 'start_ns': time.monotonic_ns()}
        try:
            fcntl.ioctl(vm, ioctl, raw)
            row['errno'] = 0
        except OSError as error:
            row['errno'] = error.errno
        row['end_ns'] = time.monotonic_ns()
        result['calls'].append(row)
        if row['errno'] not in expected:
            raise RuntimeError(f'{name}: errno={row["errno"]}, expected={expected}')
        return row

    def pin(name, offset, size, write=False, unpin=False, expected=(0,)):
        return call(name, PIN, struct.pack('=??6xQQ', write, unpin, address + offset, size), expected)

    def region(name, slot, gfn, size, offset, expected=(0,)):
        return call(name, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', slot, 0, gfn * 4096, size, address + offset), expected)

    def status(name, expected):
        raw = fcntl.ioctl(vm, STATUS, bytes(32))
        values = struct.unpack('=IIQQiI', raw)
        result['statuses'].append({'name': name, 'hex': raw.hex(), 'values': values, 'time_ns': time.monotonic_ns()})
        if values != (1, *expected, 0, 0):
            raise RuntimeError(f'{name}: {values}, expected={expected}')

    def start(name, fn, barrier=None):
        started = threading.Event()
        job = {}
        result['jobs'][name] = job
        def run():
            job['tid'] = threading.get_native_id()
            started.set()
            if barrier is not None:
                barrier.wait(timeout=3)
            try:
                job['call'] = fn()
            except (OSError, RuntimeError) as error:
                result['errors'].append(str(error))
        thread = threading.Thread(target=run)
        threads.append(thread)
        thread.start()
        if not started.wait(2):
            raise RuntimeError('工作线程未启动')
        return thread

    def finish(thread):
        thread.join(2)
        if thread.is_alive():
            raise RuntimeError('操作没有在观察期限内返回')

    def send(peer, frame):
        result['requests'].append({'hex': frame.hex(), 'time_ns': time.monotonic_ns()})
        peer.sendall(frame)

    def receive(peer):
        row = safety.response(peer)
        row['time_ns'] = time.monotonic_ns()
        result['responses'].append(row)

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
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 12288)
            memory[:] = safety.PAGE * 3
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            result['address'] = address
            region('setup', 0, 2, 8192, 0)
            region('setup_last', 1, 4, 4096, 8192)
            source = ctypes.create_string_buffer(safety.PAGE * 3)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(source), 12288))
            if args.mode == 'rollback':
                region('remove_last', 1, 4, 0, 8192)
            peer = socket.create_connection(('127.0.0.1', 37710), timeout=3)
            sockets.append(peer)
            # 转移写所有权使本地页面无效，后面的只读固定也必须真正向远端取页。
            send(peer, safety.read_request(42, gfn=3, kind=2))
            receive(peer)
            listener = socket.socket()
            listener.settimeout(3)
            listener.bind(('127.0.0.2', 37711))
            listener.listen(1)
            sockets.append(listener)
            status('initial', (0, 0, 0))
            mark('case_begin')
            if args.mode != 'empty':
                pin('preexisting', 0, 4096, write=args.mode == 'pending-write')
            across = args.mode in ('pending', 'pending-write', 'rollback')
            offset = 0 if across else 4096
            size = 12288 if args.mode == 'rollback' else 8192 if across else 4096
            write = not across or args.mode == 'pending-write'
            worker = start('pin', lambda: pin('waiting_pin', offset, size, write=write, expected=(14,) if args.mode == 'rollback' else (0,)))
            outgoing, _ = listener.accept()
            outgoing.settimeout(3)
            sockets.append(outgoing)
            raw = safety.receive_frame(outgoing)
            result['outgoing_request'] = {'hex': raw.hex(), 'time_ns': time.monotonic_ns()}
            txid = safety.request.HEADER.unpack_from(raw)[3]
            injected = safety.frame(safety.PAGE, txid, copyset=0 if write else 2)
            status('waiting', (1, 0 if args.mode in ('empty', 'pending-write') else 2 if across else 1, 2 if args.mode == 'pending-write' else 0))
            mark('waiting_observed')
            if args.mode == 'dependency':
                send(peer, safety.read_request(44))
                result['before_release_readable'] = bool(select.select([peer], [], [], 0.15)[0])
                release = start('release', lambda: pin('release_old', 0, 4096, unpin=True))
                if baseline:
                    release.join(0.15)
                    result['release_blocked'] = release.is_alive()
                    tid = result['jobs']['release']['tid']
                    result['release_stack'] = Path(f'/proc/self/task/{tid}/stack').read_text()
                    result['pin_stack'] = Path(f'/proc/self/task/{result["jobs"]["pin"]["tid"]}/stack').read_text()
                    status('blocked', (2, 1, 0))
                    mark('baseline_blocked')
                else:
                    finish(release)
                    receive(peer)
                    status('old_released', (1, 0, 0))
                    mark('callback_complete')
            elif args.mode in ('pending', 'pending-write', 'rollback'):
                pin('release_old', 0, 4096, write=write, unpin=True)
                pin('cannot_release_pending', 0, 4096, write=write, unpin=True, expected=(22,))
                pin('cannot_release_partial', 0, 8192, write=write, unpin=True, expected=(22,))
                status('only_pending', (1, 0 if write else 1, 1 if write else 0))
                mark('pending_protected')
            elif args.mode == 'empty':
                region('delete_active', 0, 2, 0, 0, expected=(16,))
                status('still_waiting', (1, 0, 0))
                mark('slot_protected')
            else:
                barrier = threading.Barrier(3)
                releases = [start(f'release_{i}', lambda i=i: pin(f'release_{i}', 0, 4096, unpin=True, expected=(0, 22)), barrier) for i in range(2)]
                barrier.wait(timeout=3)
                for thread in releases:
                    finish(thread)
                status('one_released', (1, 0, 0))
                mark('duplicates_completed')
            result['pin_alive_before_response'] = worker.is_alive()
            mark('release_response')
            result['injected'] = {'hex': injected.hex(), 'time_ns': time.monotonic_ns()}
            outgoing.sendall(injected)
            response_sent = True
            finish(worker)
            if baseline:
                finish(release)
                receive(peer)
            status('completed', (0, 2 if args.mode == 'pending' else 0, 2 if args.mode == 'pending-write' else 1 if write else 0))
            if args.mode == 'rollback':
                pin('nothing_left', 0, 4096, unpin=True, expected=(22,))
            else:
                pin('release_new', offset, size, write=write, unpin=True)
            status('released', (0, 0, 0))
            call('drain', admission.DRAIN, struct.pack('=IIQII', 1, 0, admission.GENERATION, 1000, 0), (0,))
            result['admission_status'] = fcntl.ioctl(vm, admission.STATUS, bytes(32)).hex()
            result['page_sha256'] = hashlib.sha256(memory[:8192]).hexdigest()
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            if outgoing is not None and injected is not None and not response_sent:
                result['cleanup_rescue'] = True
                try:
                    outgoing.sendall(injected)
                except OSError as error:
                    result['errors'].append('清理响应失败: ' + str(error))
            for value in sockets:
                value.close()
            for thread in threads:
                thread.join(5)
            result['live_workers'] = sum(thread.is_alive() for thread in threads)
            if result['live_workers']:
                result['errors'].append('仍有工作线程，保留映射')
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
    print(json.dumps({key: result.get(key) for key in ('mode', 'baseline', 'errors', 'live_workers', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
