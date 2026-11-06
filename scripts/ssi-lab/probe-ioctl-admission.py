#!/usr/bin/env python3
"""独占 PF20 实验：封闭 VM/vCPU ioctl 入口，保留已准入调用与入站页面服务。"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import threading
import time
import importlib.util


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('probe-kernel-drain')
device, safety, trace = base.device, base.safety, base.trace
DRAIN = 0x4018AEF6
STATUS = 0x8020AEF7
GENERATION = 0x534449002020
PROBES = [('p', 'ia_enter', 'kvm_dsm_ioctl_enter ioctl=$arg2:x32 vm=$arg3:u8'),
          ('r128', 'ia_entered', 'kvm_dsm_ioctl_enter code=$retval:s32'),
          ('p', 'ia_leave', 'kvm_dsm_ioctl_leave token=$arg2:s32'),
          ('r128', 'ia_left', 'kvm_dsm_ioctl_leave'),
          ('p', 'ia_dsm', 'kvm_vm_ioctl_dsm ioctl=$arg2:x32'),
          ('r128', 'ia_dsm_done', 'kvm_vm_ioctl_dsm code=$retval:s32'),
          ('p', 'ia_run', 'kvm_arch_vcpu_ioctl_run'),
          ('r128', 'ia_run_done', 'kvm_arch_vcpu_ioctl_run code=$retval:s32'),
          ('r128', 'ia_srcu_done', '__srcu_read_unlock'),
          ('p', 'ia_failure', 'kvm_dsm_fail code=$arg2:s32')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=('validation', 'active', 'timeout', 'fault', 'vcpu'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel != '7.1.0-rc3-sshpool-gvm-pf20' or platform.release() != args.require_kernel):
        parser.error('只允许显式指定的独占 PF20 x86 内核与 root')
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
    group = f'sshpool_admission_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [],
              'calls': [], 'statuses': [], 'generation': GENERATION, 'worker': {}, 'waiters': []}
    registered, sockets, threads = [], [], []
    kvm = vm = vcpu = memory = runmap = None
    worker = None

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def call(name, fd, ioctl, data=0):
        row = {'name': name, 'ioctl': ioctl, 'tid': threading.get_native_id(), 'start_ns': time.monotonic_ns()}
        try:
            value = fcntl.ioctl(fd, ioctl, data)
            row['errno'] = 0
            if isinstance(value, int):
                row['return'] = value
        except OSError as error:
            row['errno'] = error.errno
        row['end_ns'] = time.monotonic_ns()
        result['calls'].append(row)
        return row

    def drain(name, timeout=3000, generation=GENERATION, version=1, flags=0, reserved=0):
        return call(name, vm, DRAIN, struct.pack('=IIQII', version, flags, generation, timeout, reserved))

    def status(name):
        raw = fcntl.ioctl(vm, STATUS, bytes(32))
        version, state, generation, active, error, r0, r1 = struct.unpack('=IIQIiII', raw)
        row = dict(name=name, version=version, state=state, generation=generation, active=active,
                   error=error, reserved=[r0, r1], time_ns=time.monotonic_ns(), hex=raw.hex())
        result['statuses'].append(row)
        return row

    def wait_sealed():
        deadline = time.monotonic() + 2
        while True:
            row = status('poll_seal')
            if row['state'] == 1:
                return row
            if time.monotonic() >= deadline:
                raise RuntimeError('未观察到入口封闭')
            time.sleep(0.005)

    def start_waiter(name):
        value = {}
        result['waiters'].append(value)
        def wait():
            value.update(drain(name))
        thread = threading.Thread(target=wait)
        threads.append(thread)
        thread.start()
        return thread

    def reject_new():
        for name, fd, ioctl, data in (
                ('new_vm', vm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM),
                ('new_vcpu', vcpu, 0x8090AE81, bytes(144)),
                ('new_run', vcpu, 0xAE80, 0),
                ('new_copy', vm, device.DSM_MEMCPY, device.copy_request(True, address, 1, 0))):
            if call(name, fd, ioctl, data)['errno'] != errno.ESHUTDOWN:
                raise RuntimeError('新入口未返回 ESHUTDOWN: ' + name)

    def peer():
        value = socket.create_connection(('127.0.0.1', 37710), timeout=3)
        sockets.append(value)
        return value

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '4096')
            for kind, name, symbol in PROBES:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'ia_srcu_done/filter', 'common_pid == 0')
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            if args.mode == 'vcpu':
                fcntl.ioctl(vm, 0xAE60, 0)
            vcpu = fcntl.ioctl(vm, 0xAE41, 0)
            result['not_enabled_errno'] = drain('not_enabled')['errno']
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 8192)
            memory[:] = safety.PAGE * 2
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            gpa = 0 if args.mode == 'vcpu' else 8192
            fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, gpa, 8192, address))
            initial = ctypes.create_string_buffer(safety.PAGE * 2)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(initial), 8192))
            status('initial')
            mark('case_begin')
            if args.mode == 'validation':
                for name, kwargs in [('version', {'version': 2}), ('flags', {'flags': 1}),
                                     ('generation', {'generation': 0}), ('zero_timeout', {'timeout': 0}),
                                     ('large_timeout', {'timeout': 30001}), ('reserved', {'reserved': 1})]:
                    if drain(name, **kwargs)['errno'] != errno.EINVAL:
                        raise RuntimeError('非法控制字段没有拒绝')
                    if status('after_' + name)['state'] != 0:
                        raise RuntimeError('非法输入封闭了入口')
                if call('bad_pointer', vm, DRAIN, 1)['errno'] != errno.EFAULT:
                    raise RuntimeError('非法用户指针没有拒绝')
                if status('after_pointer')['state'] != 0:
                    raise RuntimeError('非法用户指针封闭了入口')
                if drain('idle')['errno']:
                    raise RuntimeError('空闲 ioctl 屏障失败')
                mark('sealed')
                reject_new()
            elif args.mode == 'vcpu':
                memory[:3] = b'\xf4\xeb\xfd'
                sregs = bytearray(fcntl.ioctl(vcpu, 0x8138AE83, bytes(312)))
                struct.pack_into('=Q', sregs, 0, 0)
                struct.pack_into('=H', sregs, 12, 0)
                fcntl.ioctl(vcpu, 0x4138AE84, sregs)
                regs = [0] * 18
                regs[17] = 2
                fcntl.ioctl(vcpu, 0x4090AE82, struct.pack('=18Q', *regs))
                runmap = mmap.mmap(vcpu, fcntl.ioctl(kvm, 0xAE04, 0))
                signal.signal(signal.SIGUSR1, lambda *_: None)
                worker = threading.Thread(target=lambda: result['worker'].update(call('running_vcpu', vcpu, 0xAE80)))
                threads.append(worker)
                worker.start()
                deadline = time.monotonic() + 3
                while True:
                    stack = Path(f'/proc/self/task/{worker.native_id}/stack').read_text()
                    if 'kvm_vcpu_block' in stack:
                        result['blocked_stack'] = stack
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('vCPU 未进入真实 HLT 等待')
                    time.sleep(0.005)
                start_waiter('vcpu_drain')
                if wait_sealed()['active'] != 1:
                    raise RuntimeError('KVM_RUN 在途计数错误')
                mark('sealed')
                reject_new()
                mark('release_vcpu')
                runmap[1] = 1
                signal.pthread_kill(worker.ident, signal.SIGUSR1)
                worker.join(3)
                if worker.is_alive() or result['worker'].get('errno') != errno.EINTR:
                    raise RuntimeError('已进入 KVM_RUN 未正常中断退出')
            else:
                first = peer()
                first.sendall(safety.read_request())
                result['initial_response'] = safety.response(first)
                listener = socket.socket()
                sockets.append(listener)
                listener.settimeout(3)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                source = ctypes.create_string_buffer(bytes((i * 7 + 11) % 256 for i in range(4096)))
                worker = threading.Thread(target=lambda: result['worker'].update(call('write_page', vm, device.DSM_MEMCPY,
                    device.copy_request(True, address, ctypes.addressof(source), 4096))))
                threads.append(worker)
                worker.start()
                outgoing, _ = listener.accept()
                sockets.append(outgoing)
                result['outgoing_request_hex'] = safety.receive_frame(outgoing).hex()
                trace.write(instance / 'events' / group / 'ia_srcu_done/filter', f'common_pid == {worker.native_id}')
                if status('pending')['active'] != 1:
                    raise RuntimeError('内存复制在途计数错误')
                if args.mode == 'timeout':
                    if drain('timeout', timeout=100)['errno'] != errno.ETIMEDOUT:
                        raise RuntimeError('未完成的操作没有触发等待超时')
                    result['worker_alive_after_timeout'] = worker.is_alive()
                else:
                    start_waiter('drain_first')
                if wait_sealed()['active'] != 1:
                    raise RuntimeError('封闭入口后丢失在途操作')
                mark('sealed')
                reject_new()
                if drain('wrong_generation', generation=GENERATION + 1)['errno'] != errno.ESTALE:
                    raise RuntimeError('不同关联序号没有拒绝')
                start_waiter('drain_second')
                first.sendall(safety.read_request(55, gfn=3))
                result['server_response_while_sealed'] = safety.response(first)
                result['before_release'] = {'worker_alive': worker.is_alive(),
                                            'waiters_finished': sum(bool(row) for row in result['waiters'])}
                if args.mode == 'fault':
                    mark('inject_fault')
                    first.sendall(safety.read_request(56, kind=255))
                else:
                    mark('release_response')
                    _, _, _, txid = safety.request.HEADER.unpack_from(bytes.fromhex(result['outgoing_request_hex']))
                    outgoing.sendall(safety.frame(safety.PAGE, txid, copyset=1))
                worker.join(3)
                if worker.is_alive():
                    raise RuntimeError('已准入操作未退出')
                result['page_sha256'] = hashlib.sha256(memory[:4096]).hexdigest()
            for thread in threads:
                thread.join(4)
                if thread.is_alive():
                    raise RuntimeError('控制等待线程未退出')
            if args.mode == 'fault':
                result['after_fault_errno'] = call('after_fault', vm, STATUS, bytes(32))['errno']
            else:
                status('final')
                result['repeat_errno'] = drain('repeat')['errno']
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            if runmap is not None:
                runmap[1] = 1
                if worker is not None and worker.is_alive():
                    signal.pthread_kill(worker.ident, signal.SIGUSR1)
            for value in sockets:
                value.close()
            for thread in threads:
                thread.join(5)
            live = any(thread.is_alive() for thread in threads)
            if live:
                result['errors'].append('清理时仍有调用线程，保留映射')
            else:
                if runmap is not None:
                    runmap.close()
                if vcpu is not None:
                    os.close(vcpu)
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
    print(json.dumps({key: result.get(key) for key in ('mode', 'errors', 'worker', 'repeat_errno', 'remaining_tasks')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
