#!/usr/bin/env python3
"""独占研究 VM 中用真实 KVM 调用验证连接故障、在途请求退出与管理接口失效。"""
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
import re
import select
import socket
import struct
import subprocess
import threading
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


device = load('probe-dsm-device')
safety = load('probe-request-safety')
request = safety.request
trace = safety.trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=['malformed', 'oversized', 'peer-eof', 'complete'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        parser.error('需要显式指定的独占 x86 研究内核与 root')
    if not re.fullmatch(r'7\.1\.0-rc3-sshpool-gvm-pf(?:16|17)', args.require_kernel):
        parser.error('只允许已修复接收容量的 PF16/PF17 实验内核')
    if safety.tasks():
        parser.error('已有 DSM 实例')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有实验进程')
    ports = ' or '.join(f'{direction} = :{port}' for direction in ('sport', 'dport') for port in (37710, 37711, 40000, 40001))
    if subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip():
        parser.error('实验端口仍有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    group = f'sshpool_failure_{os.getpid()}'
    instance = root / 'instances' / group
    probes = [('p', 'failure_enter', 'ivy_kvm_dsm_handle_req'),
              ('r128', 'failure_done', 'ivy_kvm_dsm_handle_req code=$retval:s32'),
              ('r128', 'failure_received', 'ktcp_receive code=$retval:s32'),
              ('r128', 'failure_root', 'kvm_dsm_threadfn code=$retval:s32'),
              ('p', 'failure_stop', 'kvm_dsm_stop')]
    symbols = {row.split()[2] for row in Path('/proc/kallsyms').read_text().splitlines() if len(row.split()) >= 3}
    if 'kvm_dsm_fail' in symbols:
        probes += [('p', 'failure_latch', 'kvm_dsm_fail kvm=$arg1:x64 code=$arg2:s32'),
                   ('p', 'failure_abort', 'ktcp_abort cb=$arg1:x64 code=$arg2:s32')]
    names = {name for _, name, _ in probes}
    if any(row.split()[0] in names for row in (root / 'kprobe_profile').read_text().splitlines() if row.split()):
        parser.error('已存在同名跟踪事件')
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [],
              'probe_names': sorted(names), 'write_result': {}}
    registered = []
    sockets = []
    kvm = vm = vcpu = memory = worker = None
    peer = second = outgoing = None

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def registers():
        try:
            fcntl.ioctl(vcpu, 0x8090AE81, bytes(144))
            return 0
        except OSError as error:
            return error.errno

    def ready_peer():
        value = socket.create_connection(('127.0.0.1', 37710), timeout=3)
        sockets.append(value)
        value.settimeout(2)
        return value

    def read_state(value):
        if value is None or value.fileno() < 0:
            return {'state': 'closed_by_probe'}
        if not select.select([value], [], [], 0)[0]:
            return {'state': 'waiting'}
        try:
            data = value.recv(4110, socket.MSG_PEEK)
            return {'state': 'eof' if not data else 'data', 'bytes': len(data)}
        except OSError as error:
            return {'state': 'error', 'errno': error.errno}

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
            trace.write(instance / 'events/sched/sched_process_exit/filter', 'comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*"')
            trace.write(instance / 'events/sched/sched_process_exit/enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            if fcntl.ioctl(kvm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM) != 1:
                raise RuntimeError('缺少 DSM capability')
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            vcpu = fcntl.ioctl(vm, 0xAE41, 0)
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 4096)
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION, struct.pack('=IIQQQ', 0, 0, 8192, 4096, address))
            original = ctypes.create_string_buffer(safety.PAGE)
            fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(original), 4096))
            result['registers_before'] = registers()
            if result['registers_before']:
                raise RuntimeError('故障前无法读取 vCPU 寄存器')
            listener = socket.socket()
            sockets.append(listener)
            listener.settimeout(3)
            listener.bind(('127.0.0.2', 37711))
            listener.listen(1)
            peer = ready_peer()
            result['initial_tasks'] = safety.require_tasks(9)
            mark('transfer_page')
            peer.sendall(safety.read_request())
            result['initial_response'] = safety.response(peer)
            source = ctypes.create_string_buffer(bytes((i * 7 + 11) % 256 for i in range(4096)))
            result['new_page_sha256'] = hashlib.sha256(source.raw[:4096]).hexdigest()

            def write_page():
                row = result['write_result']
                row['started_ns'] = time.monotonic_ns()
                try:
                    fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(source), 4096))
                    row['return'] = 0
                    row['errno'] = 0
                except OSError as error:
                    row['errno'] = error.errno
                row['finished_ns'] = time.monotonic_ns()

            mark('write_begin')
            worker = threading.Thread(target=write_page)
            worker.start()
            outgoing, _ = listener.accept()
            sockets.append(outgoing)
            outgoing.settimeout(3)
            result['outgoing_request_hex'] = safety.receive_frame(outgoing).hex()
            mark('write_waiting')
            if not worker.is_alive():
                raise RuntimeError('尚未释放响应，本地写入已经结束')
            if args.mode == 'complete':
                _, _, _, txid = request.HEADER.unpack_from(bytes.fromhex(result['outgoing_request_hex']))
                mark('release_response')
                outgoing.sendall(safety.frame(safety.PAGE, txid, copyset=1))
                worker.join(timeout=1)
                if worker.is_alive():
                    raise RuntimeError('正常响应后写入仍未完成')
                result['written_page_sha256'] = hashlib.sha256(memory[:]).hexdigest()
            else:
                second = ready_peer()
                result['all_tasks'] = safety.require_tasks(17)
                extra = set(result['all_tasks']) - set(result['initial_tasks'])
                mark('missing_page_sent')
                missing = safety.read_request(43, gfn=3)
                result['missing_request_hex'] = missing.hex()
                second.sendall(missing)
                deadline = time.monotonic() + 1
                while True:
                    captured = (instance / 'trace').read_text()
                    if any(re.search(r'-' + pid + r'\s+\[.*failure_received:.*code=24$', captured, re.MULTILINE) for pid in extra):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('未观察到第二条连接完整接收缺失页请求')
                    time.sleep(0.005)
                mark('fault_begin')
                if args.mode == 'peer-eof':
                    peer.close()
                else:
                    bad = safety.read_request(44, kind=255) if args.mode == 'malformed' else safety.frame(bytes(4096), 44)
                    result['fault_frame_hex'] = bad.hex()
                    peer.sendall(bad)
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    if not worker.is_alive() and not safety.tasks():
                        break
                    time.sleep(0.005)
                result['tasks_after_fault'] = safety.tasks()
                result['write_pending_after_fault'] = worker.is_alive()
                result['peer_after_fault'] = read_state(peer)
                result['second_after_fault'] = read_state(second)
                result['outgoing_after_fault'] = read_state(outgoing)
                mark('fault_observed')
            result['registers_after'] = registers()
            if result['registers_after'] == errno.EIO:
                try:
                    fcntl.ioctl(vcpu, 0xAE80, 0)
                    result['run_errno'] = 0
                except OSError as error:
                    result['run_errno'] = error.errno
                try:
                    fcntl.ioctl(vm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM)
                    result['vm_ioctl_errno'] = 0
                except OSError as error:
                    result['vm_ioctl_errno'] = error.errno
            mark('observation_complete')
        except (OSError, ValueError, RuntimeError) as error:
            result['errors'].append(str(error))
        finally:
            mark('cleanup_begin')
            for value in sockets:
                value.close()
            if worker is not None:
                worker.join(timeout=5)
                if worker.is_alive():
                    result['errors'].append('网络对端关闭后写线程仍未退出')
            if vcpu is not None:
                os.close(vcpu)
            if vm is not None:
                os.close(vm)
                result['vm_closed'] = True
            if memory is not None and (worker is None or not worker.is_alive()):
                memory.close()
            if kvm is not None:
                os.close(kvm)
            result['remaining_tasks'] = request.await_tasks(0, 3)
            mark('cleanup_complete')
            if instance.exists():
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text() for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines() if row.split() and row.split()[0] in names)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result.get(key) for key in ['kernel', 'mode', 'errors', 'write_result', 'write_pending_after_fault', 'registers_after', 'run_errno', 'vm_ioctl_errno', 'vm_closed', 'remaining_tasks', 'trace_cleanup_complete']}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
