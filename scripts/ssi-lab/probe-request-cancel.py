#!/usr/bin/env python3
"""在独占实验 VM 发送完整页面请求，验证延迟注册和缺失槽重试取消。"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trace = load('trace-teardown')
receive_probe = load('probe-receive')
HEADER = struct.Struct('<QHHH')
REQUEST = struct.Struct('<BB6xQBBH4x')
FRAME_BYTES = HEADER.size + 4096


def request_frame():
    request = REQUEST.pack(1, 1, 2, 1, 0, 0)
    header = HEADER.pack(HEADER.size + len(request), 0, 0, 42)
    return (header + request).ljust(FRAME_BYTES, b'\0')


def tasks():
    result = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / 'comm').read_text().strip()
            if name.startswith(('kvm-dsm/', 'dsm-conn/')):
                result[entry.name] = {'name': name, 'stat': (entry / 'stat').read_text(),
                                     'stack': (entry / 'stack').read_text().splitlines()}
        except FileNotFoundError:
            continue
    return result


def await_tasks(count, timeout):
    deadline = time.monotonic() + timeout
    while True:
        observed = tasks()
        if len(observed) == count or time.monotonic() >= deadline:
            return observed
        time.sleep(0.01)


def command(worker, value, wanted):
    worker.stdin.write(value + '\n')
    worker.stdin.flush()
    reply = receive_probe.receive(worker)
    if reply != wanted:
        raise RuntimeError(f'探针回复错误：{reply}')


def cancel_thread(pid):
    # 内核 send_sig 是线程定向投递；kill 的共享 pending 队列不能复现该路径。
    libc = ctypes.CDLL(None, use_errno=True)
    libc.tgkill.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    libc.tgkill.restype = ctypes.c_int
    if libc.tgkill(pid, pid, signal.SIGKILL):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def read_page(connection):
    data = bytearray()
    while len(data) < FRAME_BYTES:
        part = connection.recv(FRAME_BYTES - len(data))
        if not part:
            raise RuntimeError('页面响应未完整接收即断开')
        data.extend(part)
    length, copyset, version, txid = HEADER.unpack_from(data)
    expected = bytes((index * 17 + 3) % 256 for index in range(4096))
    return {'length': length, 'copyset': copyset, 'version': version, 'txid': txid,
            'sha256': hashlib.sha256(data[HEADER.size:]).hexdigest(),
            'matches': length == FRAME_BYTES and txid == 42 and data[HEADER.size:] == expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--mode', choices=['late-register', 'cancel-root', 'close-vm'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.release() != args.require_kernel or platform.machine() != 'x86_64':
        parser.error('仅在指定 x86 研究内核的独占实验 VM 以 root 执行')
    if tasks():
        parser.error('已有 DSM 线程，拒绝混用实验')
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
    group = f'sshpool_request_{os.getpid()}'
    instance = root / 'instances' / group
    events = [('r64', 'req_receive', 'ktcp_receive len=$retval:s32'),
              ('r64', 'req_handler_done', 'ivy_kvm_dsm_handle_req code=$retval:s32'),
              ('p', 'req_register', 'kvm_dsm_add_memslot'),
              ('p', 'req_stop', 'kvm_dsm_stop')]
    names = {name for _, name, _ in events}
    if any(line.split()[0] in names for line in (root / 'kprobe_profile').read_text().splitlines()
           if line.split()):
        parser.error('同名 kprobe 已存在')
    registered = []
    worker = None
    connection = None
    result = {'kernel': platform.release(), 'mode': args.mode, 'errors': [],
              'request_hex': request_frame().hex(), 'events': []}

    def mark(name):
        result['events'].append({'phase': name, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', name)

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '256')
            for kind, name, symbol in events:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            trace.write(instance / 'events/sched/sched_process_exit/filter',
                        'comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*"')
            trace.write(instance / 'events/sched/sched_process_exit/enable', '1')
            trace.write(instance / 'tracing_on', '1')
            worker = subprocess.Popen([str(args.worker.resolve()), args.require_kernel],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            result['worker_pid'] = worker.pid
            if receive_probe.receive(worker) != {'op': 'ready', 'registered_pages': 0}:
                raise RuntimeError('空 VM 未就绪')
            connection = socket.create_connection(('127.0.0.1', 37710), timeout=5)
            result['initial_tasks'] = await_tasks(9, 3)
            if len(result['initial_tasks']) != 9:
                raise RuntimeError('未创建完整的九个 DSM 线程')
            mark('request_sent')
            connection.sendall(request_frame())
            # 留出接收窗口，实际完整接收与后续顺序还必须由 trace 验证。
            time.sleep(0.05)
            result['waiting_tasks'] = tasks()
            if args.mode == 'cancel-root':
                roots = [int(pid) for pid, task in result['initial_tasks'].items()
                         if task['name'] == 'kvm-dsm/0']
                if len(roots) != 1:
                    raise RuntimeError('根线程身份不唯一')
                trace.write(instance / 'events/signal/signal_generate/filter',
                            'sig == 9 && (comm ~ "kvm-dsm/*" || comm ~ "dsm-conn/*")')
                trace.write(instance / 'events/signal/signal_generate/enable', '1')
                result['cancel_method'] = 'tgkill'
                mark('cancel_begin')
                cancel_thread(roots[0])
                result['tasks_before_registration'] = await_tasks(0, 0.5)
                mark('cancel_observed')
                # 保持 VM fd 打开：旧内核可通过补注册页面安全释放重试。
                mark('late_register')
                command(worker, 'register', {'op': 'registered', 'gfn': 2})
                result['tasks_after_registration'] = await_tasks(0, 3)
            elif args.mode == 'late-register':
                mark('late_register')
                command(worker, 'register', {'op': 'registered', 'gfn': 2})
                result['response'] = read_page(connection)
                if not result['response']['matches']:
                    raise RuntimeError('完整页面或事务号不匹配')
            mark('quit_begin')
            command(worker, 'quit', {'op': 'closed'})
            mark('quit_done')
            result['exit'] = worker.wait(timeout=3)
            result['remaining_tasks'] = await_tasks(0, 1)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            if connection is not None:
                connection.close()
            if worker is not None and worker.poll() is None:
                # 异常清理不算验收成功；若内核未响应，保留记录并交给独占 VM 恢复流程。
                worker.kill()
                try:
                    worker.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    result['errors'].append('实验进程卡在内核，需要恢复专用 VM')
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
        print(json.dumps({'mode': args.mode, 'errors': result['errors'],
                          'exit': result.get('exit'),
                          'cancelled_before_registration': result.get('tasks_before_registration') == {},
                          'trace_cleanup_complete': result['trace_cleanup_complete']}))
        # 基线的取消失败由离线检查器判定；驱动成功只代表证据收集与清理完成。
        if result['errors'] or result.get('exit') != 0 or result.get('remaining_tasks') != {}:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
