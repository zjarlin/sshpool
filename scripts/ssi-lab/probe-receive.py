#!/usr/bin/env python3
"""用真实 DSM 监听器验证空闲与半帧等待的 CPU 开销及连接关闭。"""
import argparse
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import time


def threads():
    result = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / 'comm').read_text().strip()
            if not name.startswith('dsm-conn/'):
                continue
            result[entry.name] = {
                'name': name,
                'stat': (entry / 'stat').read_text(),
                'runtime_ns': int((entry / 'schedstat').read_text().split()[0]),
                'stack': (entry / 'stack').read_text().splitlines(),
            }
        except FileNotFoundError:
            continue
    return result


def receive(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError('实验进程响应超时')
    return json.loads(process.stdout.readline())


def measure(name, seconds):
    before = threads()
    if len(before) != 8:
        raise RuntimeError(f'需要独占的八个 DSM 接收线程，实际 {len(before)}')
    started = time.monotonic_ns()
    time.sleep(seconds)
    ended = time.monotonic_ns()
    after = threads()
    if before.keys() != after.keys():
        raise RuntimeError('等待期间接收线程集合发生变化')
    for tid in before:
        first = before[tid]['stat'].rsplit(')', 1)[1].split()[19]
        last = after[tid]['stat'].rsplit(')', 1)[1].split()[19]
        if first != last or after[tid]['runtime_ns'] < before[tid]['runtime_ns']:
            raise RuntimeError('等待期间线程身份或累计时间发生变化')
    runtime = sum(after[tid]['runtime_ns'] - before[tid]['runtime_ns'] for tid in before)
    ratio = runtime / (ended - started)
    return {'phase': name, 'elapsed_ns': ended - started, 'cpu_ns': runtime,
            'cpu_equivalents': ratio, 'bounded_cpu': ratio < 0.1,
            'before': before, 'after': after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--seconds', type=int, default=3)
    parser.add_argument('--close-order', choices=['peer-first', 'vm-first'], default='peer-first',
                        help='先断开连接，或保留半帧连接并销毁 VM 以验证等待可中断')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.release() != args.require_kernel:
        parser.error('仅在指定研究内核的独占实验节点以 root 执行')
    if not 1 <= args.seconds <= 10:
        parser.error('每个等待窗口限时 1–10 秒')
    # 不与已有 QEMU、DSM 或另一探针共享全局监听器和线程统计。
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'kvm-dsm/', 'dsm-conn/', 'probe-pvclock')):
            parser.error('存在活动实验进程，拒绝并行运行')
    listeners = subprocess.check_output(['ss', '-H', '-ltn', 'sport = :37710'])
    if listeners.strip():
        parser.error('DSM 回环监听端口已占用')
    result = {'kernel': platform.release(), 'close_order': args.close_order,
              'phases': [], 'errors': []}
    with args.output.open('x') as output:
        process = subprocess.Popen([str(args.worker.resolve()), '0', '127.0.0.1', '-',
                                    args.require_kernel], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True)
        connection = None
        try:
            if receive(process) != {'op': 'ready', 'node': 0, 'nodes': 1}:
                raise RuntimeError('探针启动响应错误')
            for attempt in range(30):
                try:
                    connection = socket.create_connection(('127.0.0.1', 37710), 1)
                    break
                except ConnectionRefusedError:
                    time.sleep(0.1)
            if connection is None:
                raise RuntimeError('DSM 监听器未就绪')
            for attempt in range(30):
                if len(threads()) == 8:
                    break
                time.sleep(0.1)
            result['phases'].append(measure('idle', args.seconds))
            # 只有八个前缀字节，无法构成完整报文，不执行任何页面请求。
            connection.sendall(bytes(8))
            time.sleep(0.2)
            result['phases'].append(measure('partial_frame', args.seconds))
            if args.close_order == 'peer-first':
                connection.close()
                connection = None
            process.stdin.write('quit\n')
            process.stdin.flush()
            result['closed'] = receive(process) == {'op': 'closed'}
            result['exit'] = process.wait(timeout=10)
            result['remaining_threads'] = list(threads())
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                # 强制结束仅作异常清理，绝不把它记录为正常关闭成功。
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    result['errors'].append('内核操作未退出，需要核对实验 VM')
            output.write(json.dumps(result, indent=2) + '\n')
        passed = (len(result['phases']) == 2 and all(p['bounded_cpu'] for p in result['phases'])
                  and result.get('closed') and result.get('exit') == 0
                  and result.get('remaining_threads') == [] and not result['errors'])
        print(json.dumps({'bounded_wait_and_close': passed,
                          'phases': [{key: phase[key] for key in
                                      ('phase', 'elapsed_ns', 'cpu_ns', 'cpu_equivalents')}
                                     for phase in result['phases']],
                          'errors': result['errors']}), flush=True)
        raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
