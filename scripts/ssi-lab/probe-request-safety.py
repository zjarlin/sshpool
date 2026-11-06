#!/usr/bin/env python3
"""仅在独占 PF11 实验 VM 验证完整异常帧和页面锁竞争，不执行客体代码。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import time

import importlib.util

spec = importlib.util.spec_from_file_location('request', Path(__file__).with_name('probe-request-cancel.py'))
request = importlib.util.module_from_spec(spec)
spec.loader.exec_module(request)
trace = request.trace
PAGE = bytes((i * 17 + 3) % 256 for i in range(4096))


def frame(payload, txid=42, length=None, copyset=0):
    header = request.HEADER.pack(14 + len(payload) if length is None else length, copyset, 0, txid)
    return (header + payload).ljust(request.FRAME_BYTES, b'\0')


def read_request(txid=42, **changes):
    fields = {'requester': 1, 'sender': 1, 'gfn': 2, 'kind': 1, 'smm': 0, 'version': 0}
    fields.update(changes)
    return frame(request.REQUEST.pack(*fields.values()), txid)


def malformed_cases():
    cases = [(f'payload_{size}', frame(bytes(size)), -90 if size > 24 else -71)
             for size in (0, 1, 23, 25, 4096)]
    cases += [(f'{key}_{value}', read_request(**{key: value}), -71)
              for key, value in [('kind', 3), ('kind', 255), ('smm', 2),
                                 ('requester', 2), ('requester', 255), ('requester', 0),
                                 ('sender', 2), ('sender', 255)]]
    cases += [(f'length_{size}', frame(b'', length=size), -71) for size in (13, 4111)]
    return cases


def receive_frame(connection):
    data = bytearray()
    while len(data) < request.FRAME_BYTES:
        part = connection.recv(request.FRAME_BYTES - len(data))
        if not part:
            raise RuntimeError('对端未完整响应')
        data.extend(part)
    return bytes(data)


def response(connection):
    data = receive_frame(connection)
    length, copyset, version, txid = request.HEADER.unpack_from(data)
    return {'hex': data.hex(), 'length': length, 'copyset': copyset, 'version': version,
            'txid': txid, 'payload_sha256': hashlib.sha256(data[14:length]).hexdigest()}


def tasks():
    # 出错处理线程现在会立即退出；读取 /proc/stack 时 ESRCH 是可重试的采样竞态。
    for _ in range(20):
        try:
            return request.tasks()
        except ProcessLookupError:
            time.sleep(0.001)
    raise RuntimeError('线程快照连续遇到退出竞态')


def require_tasks(count, timeout=2):
    deadline = time.monotonic() + timeout
    while True:
        observed = tasks()
        if len(observed) == count:
            return observed
        if time.monotonic() >= deadline:
            raise RuntimeError(f'预期 {count} 个 DSM 线程，实际 {len(observed)}')
        time.sleep(0.01)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=['malformed', 'lock-cancel'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64'
            or platform.release() != args.require_kernel
            or not args.require_kernel.endswith('-sshpool-gvm-pf11')):
        parser.error('异常完整帧只允许在指定 PF11 候选内核上执行')
    if tasks():
        parser.error('已有 DSM 线程')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有实验进程')
    if subprocess.check_output(['ss', '-H', '-tan', '( sport = :37710 or sport = :37711 )']).strip():
        parser.error('实验端口仍有 TCP 状态')
    root = Path('/sys/kernel/tracing')
    symbols = [(int(row.split()[0], 16), row.split()[2])
               for row in Path('/proc/kallsyms').read_text().splitlines() if len(row.split()) >= 3]
    start = next(address for address, name in symbols if name == 'ivy_kvm_dsm_handle_req')
    end = min(address for address, _ in symbols if address > start)
    if start == 0:
        parser.error('需要可读取的真实内核符号地址')
    group = f'sshpool_safety_{os.getpid()}'
    instance = root / 'instances' / group
    probes = [('p', 'safe_enter', 'ivy_kvm_dsm_handle_req'),
              ('r128', 'safe_done', 'ivy_kvm_dsm_handle_req code=$retval:s32'),
              ('p', 'safe_receive', 'ktcp_receive cb=$arg1:x64 capacity=$arg3:u64'),
              ('r128', 'safe_received', 'ktcp_receive code=$retval:s32'),
              ('p', 'safe_lock', 'dsm_lock_killable slot=$arg1:x64 vfn=$arg2:x64'),
              ('r128', 'safe_locked', 'dsm_lock_killable code=$retval:s32'),
              ('p', 'safe_unlock', 'dsm_unlock slot=$arg2:x64 vfn=$arg3:x64'),
              ('p', 'safe_srcu', '__srcu_read_lock srcu=$arg1:x64'),
              ('p', 'safe_srcu_done', '__srcu_read_unlock srcu=$arg1:x64'),
              ('p', 'safe_register', 'kvm_dsm_add_memslot'),
              ('p', 'safe_stop', 'kvm_dsm_stop')]
    names = {name for _, name, _ in probes}
    if any(line.split()[0] in names for line in (root / 'kprobe_profile').read_text().splitlines()):
        parser.error('同名 kprobe 已存在')
    registered = []
    sockets = []
    worker = None
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [], 'events': [], 'cases': []}

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    def connection():
        peer = socket.create_connection(('127.0.0.1', 37710), timeout=5)
        sockets.append(peer)
        snapshot = require_tasks(9)
        # 只跟踪当前连接处理线程的释放与 SRCU，避免其他系统活动混入证据。
        pids = [pid for pid, task in snapshot.items() if task['name'].startswith('dsm-conn/')]
        condition = ' || '.join(f'common_pid == {pid}' for pid in pids)
        for path in ['events/kmem/kfree/filter', f'events/{group}/safe_srcu/filter',
                     f'events/{group}/safe_srcu_done/filter']:
            trace.write(instance / path, condition)
        return peer, snapshot

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '2048')
            for kind, name, symbol in probes:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            for name in ('safe_srcu', 'safe_srcu_done'):
                trace.write(instance / 'events' / group / name / 'filter', 'common_pid == 0')
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'events/kmem/kmalloc/filter',
                        f'bytes_req == 4096 && call_site >= {start} && call_site < {end}')
            trace.write(instance / 'events/kmem/kmalloc/enable', '1')
            trace.write(instance / 'events/kmem/kfree/filter', 'common_pid == 0')
            trace.write(instance / 'events/kmem/kfree/enable', '1')
            trace.write(instance / 'events/sched/sched_process_exit/filter',
                        'comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*"')
            trace.write(instance / 'events/sched/sched_process_exit/enable', '1')
            trace.write(instance / 'events/signal/signal_generate/filter',
                        'sig == 9 && (comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*")')
            trace.write(instance / 'events/signal/signal_generate/enable', '1')
            trace.write(instance / 'tracing_on', '1')
            worker = subprocess.Popen([str(args.worker.resolve()), args.require_kernel],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            result['worker_pid'] = worker.pid
            if request.receive_probe.receive(worker) != {'op': 'ready', 'registered_pages': 0}:
                raise RuntimeError('空 VM 未就绪')
            require_tasks(1)
            if args.mode == 'malformed':
                for label, data, code in malformed_cases():
                    mark(label + '_begin')
                    peer, initial = connection()
                    case = {'label': label, 'frame_hex': data.hex(), 'expected_code': code, 'initial_tasks': initial}
                    result['cases'].append(case)
                    mark(label + '_send')
                    peer.sendall(data)
                    case['after_reject'] = require_tasks(8)
                    mark(label + '_rejected')
                    peer.close()
                    case['after_close'] = require_tasks(1)
                    mark(label + '_done')
                mark('register')
                request.command(worker, 'register', {'op': 'registered', 'gfn': 2})
                peer, result['normal_tasks'] = connection()
                mark('normal_read')
                peer.sendall(read_request())
                result['normal_response'] = response(peer)
                mark('normal_invalidate')
                peer.sendall(read_request(43, kind=0))
                result['invalidate_response'] = response(peer)
            else:
                listener = socket.socket()
                sockets.append(listener)
                listener.settimeout(5)
                listener.bind(('127.0.0.2', 37711))
                listener.listen(1)
                mark('register')
                request.command(worker, 'register', {'op': 'registered', 'gfn': 2})
                peer, result['normal_tasks'] = connection()
                mark('normal_read')
                peer.sendall(read_request())
                result['normal_response'] = response(peer)
                mark('holder_send')
                peer.sendall(read_request(43))
                forwarded, _ = listener.accept()
                sockets.append(forwarded)
                forwarded.settimeout(5)
                result['forwarded_request'] = receive_frame(forwarded).hex()
                mark('holder_waiting')
                peer.sendall(read_request(44))
                deadline = time.monotonic() + 2
                while True:
                    snapshot = tasks()
                    # 尾调用优化会从 /proc/stack 隐去包装函数；用真实入口/返回事件识别尚未取锁者。
                    pending = {}
                    for line in (instance / 'trace').read_text().splitlines():
                        match = re.match(r'^\s*.*-(\d+)\s+\[\d+\].*:\s+(safe_lock|safe_locked):', line)
                        if match:
                            pid, event = match.groups()
                            pending[pid] = pending.get(pid, 0) + (1 if event == 'safe_lock' else -1)
                    waiting = [int(pid) for pid, count in pending.items() if count == 1 and pid in snapshot]
                    if len(waiting) == 1:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('未观察到唯一页面锁等待者')
                    time.sleep(0.01)
                result['waiting_tasks'] = snapshot
                result['waiter_selection'] = 'unreturned_kprobe'
                result['waiter_pid'] = waiting[0]
                result['cancel_method'] = 'tgkill'
                mark('cancel_waiter')
                request.cancel_thread(waiting[0])
                result['after_cancel'] = require_tasks(8, 0.5)
                mark('cancel_observed')
                _, _, _, txid = request.HEADER.unpack_from(bytes.fromhex(result['forwarded_request']))
                mark('release_holder')
                forwarded.sendall(frame(PAGE, txid, copyset=1))
                result['holder_response'] = response(peer)
                mark('holder_complete')
            mark('quit_begin')
            request.command(worker, 'quit', {'op': 'closed'})
            mark('quit_done')
            result['exit'] = worker.wait(timeout=3)
            result['remaining_tasks'] = require_tasks(0)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            for peer in sockets:
                peer.close()
            if worker is not None and worker.poll() is None:
                worker.kill()
                try:
                    worker.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    result['errors'].append('实验进程未退出，需要恢复专用 VM')
            if instance.exists():
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                         for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(
                    line for line in (root / 'kprobe_profile').read_text().splitlines()
                    if line.split() and line.split()[0] in registered)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = (
                not instance.exists() and group not in (root / 'kprobe_events').read_text())
            output.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'mode': args.mode, 'errors': result['errors'], 'exit': result.get('exit'),
                          'trace_cleanup_complete': result['trace_cleanup_complete']}))
        if result['errors'] or result.get('exit') != 0 or result.get('remaining_tasks') != {}:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
