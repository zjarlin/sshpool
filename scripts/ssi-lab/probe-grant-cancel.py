#!/usr/bin/env python3
"""在独占 PF30 VM 观察写授权睡眠，再取消指定线程或复位受控对端。"""
import argparse
import hashlib
import importlib.util
import json
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

spec = importlib.util.spec_from_file_location('safety', Path(__file__).with_name('probe-request-safety.py'))
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)
trace = safety.trace
KERNEL = '7.1.0-rc3-sshpool-gvm-pf30'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=['control', 'handler', 'root', 'reset'], required=True)
    parser.add_argument('--grace', type=int, choices=[0, 1000], default=1000)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64'
            or platform.release() != args.require_kernel or args.require_kernel != KERNEL):
        parser.error('只允许指定的独占 x86 PF30 研究内核与 root')
    root = Path('/sys/kernel/tracing')
    parameter = Path('/sys/module/kvm/parameters/dsm_write_grace_us')
    if safety.tasks() or (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有 DSM 线程或跟踪')
    if parameter.read_text().strip() != '0':
        parser.error('写授权开关未处于默认值')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'probe-', 'grant-reader')):
            parser.error('已有实验进程')
    ports = ' or '.join(f'{side} = :{port}' for side in ('sport', 'dport') for port in (37710, 37711, 40000, 40001))
    if subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip():
        parser.error('实验 TCP 未排空')
    if os.statvfs('/').f_bavail * os.statvfs('/').f_frsize < 64 * 1024 * 1024:
        parser.error('根文件系统余量不足')
    group = f'sshpool_grant_cancel_{os.getpid()}'
    archive = root / 'instances' / group
    notify = root / 'instances' / (group + '_notify')
    probes = [('p', 'gc_sleep', 'schedule_hrtimeout delay=+0($arg1):s64 mode=$arg2:u32'),
              ('r128', 'gc_wake', 'schedule_hrtimeout code=$retval:s32'),
              ('p', 'gc_lock', 'dsm_lock_killable slot=$arg1:x64 vfn=$arg2:x64'),
              ('r128', 'gc_locked', 'dsm_lock_killable code=$retval:s32'),
              ('r128', 'gc_unlock', 'dsm_unlock'),
              ('p', 'gc_srcu', '__srcu_read_lock srcu=$arg1:x64'),
              ('r128', 'gc_srcu_done', '__srcu_read_unlock'),
              ('p', 'gc_failure', 'kvm_dsm_fail code=$arg2:s32'),
              ('p', 'gc_send', 'ktcp_send length=$arg3:u64'),
              ('r128', 'gc_sent', 'ktcp_send code=$retval:s32'),
              ('r128', 'gc_handler_done', 'ivy_kvm_dsm_handle_req code=$retval:s32'),
              ('r128', 'gc_root_done', 'kvm_dsm_threadfn code=$retval:s32'),
              ('p', 'gc_free', 'kvm_dsm_free'),
              ('r128', 'gc_freed', 'kvm_dsm_free')]
    result = {'kernel': platform.release(), 'mode': args.mode, 'grace_us': args.grace,
              'errors': [], 'worker_records': [], 'events': [],
              'worker_sha256': hashlib.sha256(args.worker.read_bytes()).hexdigest(),
              'request_hex': safety.read_request().hex()}
    worker = peer = observer = None
    registered = []
    stopped = threading.Event()
    armed = threading.Event()
    buffer = bytearray()
    marker_lock = threading.Lock()

    def mark(name):
        # 两个采集线程共享阶段顺序；日志与内核标记在同一临界区内写入。
        with marker_lock:
            result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
            trace.write(archive / 'trace_marker', name)

    def receive():
        deadline = time.monotonic() + 5
        while b'\n' not in buffer:
            if not select.select([worker.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                raise RuntimeError('工作进程响应超时')
            data = os.read(worker.stdout.fileno(), 65536)
            if not data:
                raise RuntimeError('工作进程提前退出')
            buffer.extend(data)
        line, _, remaining = buffer.partition(b'\n')
        buffer[:] = remaining
        row = json.loads(line)
        result['worker_records'].append(row)
        return row

    def send(command):
        worker.stdin.write((command + '\n').encode())
        worker.stdin.flush()

    def observe():
        descriptor = os.open(notify / 'trace_pipe', os.O_RDONLY | os.O_NONBLOCK)
        pending = b''
        result['observer_tid'] = threading.get_native_id()
        if args.mode == 'reset':
            trace.write(archive / 'events/tcp/tcp_send_reset/filter', f"common_pid == {result['observer_tid']}")
            trace.write(archive / 'events/tcp/tcp_send_reset/enable', '1')
        armed.set()
        try:
            while not stopped.is_set():
                if not select.select([descriptor], [], [], 0.05)[0]:
                    continue
                pending += os.read(descriptor, 65536)
                lines = pending.split(b'\n')
                pending = lines.pop()
                for line in lines:
                    match = re.match(rb'^\s*.*-(\d+)\s+\[\d+\].*:\s+gc_sleep:', line)
                    if not match:
                        continue
                    pid = int(match[1])
                    result['notification'] = line.decode()
                    result['sleep_pid'] = pid
                    mark('action_begin')
                    if args.mode in ('root', 'handler'):
                        target = result['root_pid'] if args.mode == 'root' else pid
                        result['signal_target'] = target
                        safety.request.cancel_thread(target)
                    elif args.mode == 'reset':
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                        peer.close()
                    mark('action_done')
                    return
        except (OSError, ValueError, RuntimeError) as error:
            result['errors'].append('通知线程：' + str(error))
        finally:
            os.close(descriptor)

    with args.output.open('x') as output:
        try:
            for instance in (archive, notify):
                instance.mkdir()
                trace.write(instance / 'tracing_on', '0')
                trace.write(instance / 'trace_clock', 'mono')
                trace.write(instance / 'buffer_size_kb', '2048')
                trace.write(instance / 'buffer_percent', '0')
            for kind, name, symbol in probes:
                result['registering_probe'] = name
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            # 高频通用函数先关掉，再限定为本次连接的处理线程。
            filtered = ('gc_sleep', 'gc_wake', 'gc_lock', 'gc_locked', 'gc_unlock', 'gc_srcu', 'gc_srcu_done')
            for name in filtered:
                trace.write(archive / 'events' / group / name / 'filter', 'common_pid == 0')
            trace.write(archive / 'events' / group / 'enable', '1')
            trace.write(archive / 'events/sched/sched_process_exit/filter',
                        'comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*"')
            trace.write(archive / 'events/sched/sched_process_exit/enable', '1')
            trace.write(archive / 'events/signal/signal_generate/filter',
                        'sig == 9 && (comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*")')
            trace.write(archive / 'events/signal/signal_generate/enable', '1')
            trace.write(archive / 'tracing_on', '1')
            worker = subprocess.Popen([str(args.worker.resolve()), '0', '127.0.0.1', '127.0.0.2', KERNEL],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result['worker_pid'] = worker.pid
            if receive()['op'] != 'ready':
                raise RuntimeError('工作进程未就绪')
            peer = socket.create_connection(('127.0.0.1', 37710), timeout=3)
            result['connection'] = {'local': list(peer.getsockname()), 'remote': list(peer.getpeername())}
            result['initial_tasks'] = safety.require_tasks(9)
            result['root_pid'] = next(int(pid) for pid, item in result['initial_tasks'].items()
                                      if item['name'] == 'kvm-dsm/0')
            pids = [pid for pid, item in result['initial_tasks'].items() if item['name'].startswith('dsm-conn/')]
            condition = ' || '.join(f'common_pid == {pid}' for pid in pids)
            for name in filtered:
                trace.write(archive / 'events' / group / name / 'filter', condition)
            trace.write(notify / 'events' / group / 'gc_sleep/filter', condition)
            trace.write(notify / 'events' / group / 'gc_sleep/enable', '1')
            trace.write(notify / 'tracing_on', '1')
            trace.write(parameter, str(args.grace))
            if args.mode != 'control':
                observer = threading.Thread(target=observe)
                observer.start()
                if not armed.wait(1):
                    raise RuntimeError('通知线程未就绪')
            mark('write_begin')
            send('write 1 0')
            row = receive()
            if row != {**row, 'op': 'write', 'value': 1, 'observed': 1, 'exit_reason': 5, 'rip': 4101}:
                raise RuntimeError('单条客体写入失败')
            # 先投递请求，避免额外的日志和进程快照耗尽真实的一毫秒窗口。
            peer.sendall(bytes.fromhex(result['request_hex']))
            mark('request_sent')
            if receive()['op'] != 'writes_done':
                raise RuntimeError('写入未结束')
            if args.mode == 'control':
                result['response'] = safety.response(peer)
                mark('response_received')
            else:
                observer.join(1)
                stopped.set()
                observer.join(1)
                result['tasks_at_action_return'] = safety.tasks()
                if 'notification' in result:
                    result['tasks_after_action'] = safety.require_tasks(0, timeout=3)
                if 'notification' not in result:
                    result['missed_window'] = True
                if args.mode != 'reset':
                    peer.settimeout(0.05)
                    try:
                        result['after_action_data'] = peer.recv(8192).hex()
                    except socket.timeout:
                        result['after_action_data'] = None
                    except ConnectionResetError:
                        result['after_action_reset'] = True
            # 受控对端不实现全套原生 CLOSE；关闭探针 fd 只作为故障资源回收。
            mark('cleanup_begin')
            if args.mode != 'control' and 'notification' in result:
                result['management_probe'] = 'read_after_failure'
                send('read')
            else:
                send('quit')
            result['worker_exit'] = worker.wait(timeout=8)
            result['worker_stderr'] = worker.stderr.read().decode()
            result['remaining_tasks'] = safety.require_tasks(0, timeout=3)
            mark('cleanup_done')
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            stopped.set()
            if observer:
                observer.join(1)
            if peer:
                peer.close()
            if worker and worker.poll() is None:
                worker.kill()
                try:
                    worker.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    result['errors'].append('工作进程卡在内核，保留状态待恢复')
            trace.write(parameter, '0')
            result['grace_restored'] = parameter.read_text().strip() == '0'
            if archive.exists():
                trace.write(archive / 'tracing_on', '0')
                result['trace'] = (archive / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text() for cpu in (archive / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(line for line in (root / 'kprobe_profile').read_text().splitlines()
                                                    if line.split() and line.split()[0] in registered)
            for instance in (notify, archive):
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    trace.write(instance / 'events/enable', '0')
                    instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = group not in (root / 'kprobe_events').read_text()
            result['final_tasks'] = safety.tasks()
            output.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps({key: result.get(key) for key in ('mode', 'errors', 'sleep_pid', 'missed_window', 'worker_exit', 'final_tasks')}))
        if result['errors'] or result['final_tasks'] or not result['trace_cleanup_complete']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
