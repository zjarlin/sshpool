#!/usr/bin/env python3
"""仅在独占 PF18/PF19 VM 验证入站流屏障；不将此确认当作整个 VM 可以关闭。"""
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
ACK = struct.Struct('<IIHHIQ')
MODES = ('idle', 'active', 'lock', 'timeout', 'fault', 'version', 'generation', 'duplicate', 'late', 'partial', 'prefix')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64'
            or platform.release() != args.require_kernel
            or args.require_kernel not in ('7.1.0-rc3-sshpool-gvm-pf18', '7.1.0-rc3-sshpool-gvm-pf19')):
        parser.error('只允许显式指定的独占 PF18/PF19 x86 研究内核与 root')
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
    group = f'sshpool_drain_{os.getpid()}'
    instance = root / 'instances' / group
    probes = [('p', 'kd_send', 'ktcp_send cb=$arg1:x64 length=$arg3:u64'),
              ('r128', 'kd_sent', 'ktcp_send code=$retval:s32'),
              ('r128', 'kd_received', 'ktcp_receive code=$retval:s32'),
              ('p', 'kd_lock', 'dsm_lock_killable'),
              ('r128', 'kd_locked', 'dsm_lock_killable code=$retval:s32'),
              ('r128', 'kd_unlocked', 'dsm_unlock'),
              ('r128', 'kd_srcu_done', '__srcu_read_unlock'),
              ('p', 'kd_failure', 'kvm_dsm_fail code=$arg2:s32'),
              ('r128', 'kd_handler_done', 'ivy_kvm_dsm_handle_req code=$retval:s32'),
              ('r128', 'kd_root_done', 'kvm_dsm_threadfn code=$retval:s32')]
    names = {name for _, name, _ in probes}
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [],
              'generation': 0x534449001234, 'responses': [], 'requests': [], 'write_result': {}}
    kvm = vm = memory = worker = None
    registered = []
    sockets = []

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def peer():
        value = socket.create_connection(('127.0.0.1', 37710), timeout=8)
        sockets.append(value)
        return value

    def send(value, data):
        result['requests'].append(data.hex())
        value.sendall(data)

    def wait_trace(pattern, count=1, timeout=2):
        deadline = time.monotonic() + timeout
        while True:
            data = (instance / 'trace').read_text()
            if data.count(pattern) >= count:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f'未观察到 {pattern} 达到 {count} 次')
            time.sleep(0.005)

    def response(value):
        row = safety.response(value)
        row['received_ns'] = time.monotonic_ns()
        result['responses'].append(row)
        return row

    def expect_silence(value):
        start = time.monotonic_ns()
        readable = select.select([value], [], [], 0.5)[0]
        result['silence'] = {'start_ns': start, 'end_ns': time.monotonic_ns(), 'readable': bool(readable)}
        if readable:
            raise RuntimeError('旧请求尚未完成就产生响应或断连')

    def register_pages(count):
        fcntl.ioctl(vm, device.KVM_SET_USER_MEMORY_REGION,
                    struct.pack('=IIQQQ', 0, 0, 8192, count * 4096, address))

    def expect_ack(value):
        row = response(value)
        raw = bytes.fromhex(row['hex'])
        fields = ACK.unpack(raw[14:38])
        result['ack_fields'] = list(fields)
        if (row['length'] != 38 or row['txid'] != 100 or row['copyset'] or row['version']
                or fields != (0x44534d44, 1, 0, 1, 0, result['generation'])
                or any(raw[38:])):
            raise RuntimeError('排空确认字段或尾部无效')

    def wait_failure(code):
        result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=7)
        mark('failure_observed')
        try:
            fcntl.ioctl(vm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM)
            result['management_errno'] = 0
        except OSError as error:
            result['management_errno'] = error.errno
        if result['management_errno'] != errno.EIO:
            raise RuntimeError('故障后 VM 管理接口仍可用')
        result['expected_failure'] = code

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '4096')
            for kind, name, symbol in probes:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            # 只观察 DSM 服务线程的页锁与 SRCU，排除系统其他业务活动。
            for name in ('kd_srcu_done', 'kd_unlocked'):
                trace.write(instance / 'events' / group / name / 'filter', 'common_pid == 0')
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'tracing_on', '1')
            kvm = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            if fcntl.ioctl(kvm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM) != 1:
                raise RuntimeError('缺少 DSM capability')
            vm = fcntl.ioctl(kvm, device.KVM_CREATE_VM, 0)
            addresses = [ctypes.create_string_buffer(value) for value in (b'127.0.0.1', b'127.0.0.2')]
            pointers = (ctypes.c_void_p * 2)(*(ctypes.addressof(value) for value in addresses))
            fcntl.ioctl(vm, device.DSM_ENABLE, struct.pack('=IIQ', 0, 2, ctypes.addressof(pointers)))
            memory = mmap.mmap(-1, 7 * 4096)
            memory[:] = safety.PAGE * 7
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            first = peer()
            deadline = time.monotonic() + 2
            while True:
                snapshot = safety.require_tasks(9)
                handlers = [item for item in snapshot.values() if item['name'].startswith('dsm-conn/')]
                if all(any('ivy_kvm_dsm_handle_req' in line for line in item['stack']) for item in handlers):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('初始连接的处理线程尚未全部进入等待')
                time.sleep(0.005)
            result['initial_tasks'] = snapshot
            active_peer = first
            if args.mode == 'lock':
                register_pages(1)
                initial = ctypes.create_string_buffer(safety.PAGE)
                fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(initial), 4096))
                listener = socket.socket()
                sockets.append(listener)
                listener.settimeout(3)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                send(first, safety.read_request())
                result['initial_response'] = safety.response(first)
                source = ctypes.create_string_buffer(bytes((i * 7 + 11) % 256 for i in range(4096)))
                result['expected_page_sha256'] = hashlib.sha256(source.raw[:4096]).hexdigest()

                def write_page():
                    try:
                        fcntl.ioctl(vm, device.DSM_MEMCPY, device.copy_request(True, address, ctypes.addressof(source), 4096))
                        result['write_result']['errno'] = 0
                    except OSError as error:
                        result['write_result']['errno'] = error.errno
                    result['write_result']['finished_ns'] = time.monotonic_ns()

                worker = threading.Thread(target=write_page)
                worker.start()
                outgoing, _ = listener.accept()
                sockets.append(outgoing)
                result['outgoing_request_hex'] = safety.receive_frame(outgoing).hex()
                active_peer = peer()
                result['all_tasks'] = safety.require_tasks(17)
            pids = [pid for pid, item in safety.tasks().items() if item['name'].startswith('dsm-conn/')]
            for name in ('kd_srcu_done', 'kd_unlocked'):
                trace.write(instance / 'events' / group / name / 'filter', ' || '.join(f'common_pid == {pid}' for pid in pids))
            mark('case_begin')
            pending = 7 if args.mode == 'active' else int(args.mode in ('timeout', 'fault', 'lock'))
            for index in range(pending):
                send(active_peer, safety.read_request(42 + index, gfn=2 + index))
            marker = safety.read_request(100, kind=3, gfn=result['generation'], version=1)
            if args.mode == 'version':
                marker = safety.read_request(100, kind=3, gfn=result['generation'], version=2)
            if args.mode == 'generation':
                marker = safety.read_request(100, kind=3, gfn=0, version=1)
            mark('marker_sent')
            if args.mode == 'prefix':
                send(active_peer, safety.read_request(99, kind=255) + marker)
            else:
                send(active_peer, marker[:8] if args.mode == 'partial' else marker)
            if pending:
                wait_trace('code=24', pending + 1 + int(args.mode == 'lock'))
                mark('requests_received')
                expect_silence(active_peer)
            if args.mode == 'active':
                mark('register_pages')
                register_pages(7)
            if args.mode == 'lock':
                if not worker.is_alive():
                    raise RuntimeError('远端未响应但持锁写入已完成')
                wait_trace('kd_lock:', 2)
                mark('release_remote_response')
                _, _, _, txid = request.HEADER.unpack_from(bytes.fromhex(result['outgoing_request_hex']))
                outgoing.sendall(safety.frame(safety.PAGE, txid, copyset=1))
                worker.join(timeout=2)
                if worker.is_alive() or result['write_result'].get('errno') != 0:
                    raise RuntimeError('释放远端响应后本地写入未成功')
            if args.mode in ('active', 'lock'):
                for _ in range(pending):
                    response(active_peer)
            if args.mode in ('idle', 'active', 'lock', 'duplicate', 'late'):
                expect_ack(active_peer)
                mark('ack_observed')
            if args.mode in ('version', 'generation', 'timeout', 'prefix'):
                wait_failure(-110 if args.mode == 'timeout' else -71)
            elif args.mode == 'fault':
                other = peer()
                # 新连接的八个线程全部进入处理器后才注入，避免启动取消混入退出计数。
                deadline = time.monotonic() + 2
                while True:
                    snapshot = safety.require_tasks(17)
                    handlers = [item for item in snapshot.values() if item['name'].startswith('dsm-conn/')]
                    if all(any('ivy_kvm_dsm_handle_req' in line for line in item['stack']) for item in handlers):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('故障连接的处理线程尚未全部进入等待')
                    time.sleep(0.005)
                result['fault_tasks'] = snapshot
                mark('inject_fault')
                send(other, safety.read_request(101, kind=255))
                wait_failure(-71)
            elif args.mode in ('duplicate', 'late'):
                mark('inject_late_frame')
                send(active_peer, marker if args.mode == 'duplicate' else safety.read_request(101))
                wait_failure(-71)
            elif args.mode == 'partial':
                expect_silence(active_peer)
                mark('close_partial_vm')
                os.close(vm)
                vm = None
                result['tasks_before_cleanup'] = safety.require_tasks(0, timeout=3)
            else:
                result['management_capability'] = fcntl.ioctl(vm, device.KVM_CHECK_EXTENSION, device.KVM_CAP_X86_DSM)
            mark('observation_complete')
        except (OSError, RuntimeError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                mark('cleanup_begin')
            for value in sockets:
                value.close()
            if worker is not None:
                worker.join(timeout=5)
                if worker.is_alive():
                    result['errors'].append('清理时本地写入仍未退出')
            if vm is not None:
                os.close(vm)
            if memory is not None and (worker is None or not worker.is_alive()):
                memory.close()
            if kvm is not None:
                os.close(kvm)
            result['remaining_tasks'] = request.await_tasks(0, 3)
            if instance.exists():
                mark('cleanup_complete')
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
    print(json.dumps({key: result.get(key) for key in ('mode', 'errors', 'ack_fields', 'management_errno', 'remaining_tasks', 'trace_cleanup_complete')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
