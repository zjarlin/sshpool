#!/usr/bin/env python3
"""有界读取实验 QEMU 与 DSM 线程的内核栈和调度计数，不改变调度策略。"""
import argparse
import json
import os
from pathlib import Path
import platform
import time


def task_stat(text):
    # comm 可以含空格和括号，字段编号从最后一个右括号之后恢复。
    fields = text[text.rindex(')') + 2:].split()
    return {'state': fields[0], 'start_ticks': int(fields[19]),
            'user_ticks': int(fields[11]), 'system_ticks': int(fields[12])}


def sample_task(path):
    stat = task_stat((path / 'stat').read_text())
    runtime, wait, slices = map(int, (path / 'schedstat').read_text().split())
    stack = (path / 'stack').read_text().splitlines()
    # 再读一次身份字段，拒绝将消失后复用的 TID 拼成一个线程。
    if task_stat((path / 'stat').read_text())['start_ticks'] != stat['start_ticks']:
        raise RuntimeError('采样期间线程身份发生变化')
    return {'tid': int(path.name), 'comm': (path / 'comm').read_text().strip(),
            **stat, 'runtime_ns': runtime, 'runqueue_ns': wait,
            'slices': slices, 'stack': stack}


def sample(pid):
    tasks = list((Path('/proc') / str(pid) / 'task').iterdir())
    # DSM 服务是独立内核线程；该工具要求独占实验机，不能用于混跑多个实例。
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / 'comm').read_text().strip()
        except FileNotFoundError:
            continue
        if name.startswith(('dsm-conn/', 'kvm-dsm/')):
            tasks.append(entry)
    result = {'op': 'sample', 'monotonic_ns': time.monotonic_ns(),
              'tasks': [], 'disappeared': []}
    for task in tasks:
        try:
            result['tasks'].append(sample_task(task))
        except (FileNotFoundError, ProcessLookupError):
            result['disappeared'].append(int(task.name))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--interval', type=float, default=1)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300 or not 0.1 <= args.interval <= 5:
        parser.error('采样限时为 1–300 秒，间隔为 0.1–5 秒')
    if os.geteuid() != 0 or platform.release() != args.require_kernel:
        parser.error('需要在明确指定的实验内核上以 root 读取线程栈')
    process = Path('/proc') / str(args.pid)
    if (process / 'comm').read_text().strip() != 'qemu-system-x86':
        parser.error('PID 必须是本次实验的 QEMU')
    identity = task_stat((process / 'stat').read_text())['start_ticks']
    with args.output.open('x') as output:
        def emit(value):
            output.write(json.dumps(value, ensure_ascii=False) + '\n')
            output.flush()

        emit({'op': 'start', 'pid': args.pid, 'start_ticks': identity,
              'kernel': platform.release(), 'seconds': args.seconds,
              'interval': args.interval, 'clock_ticks': os.sysconf('SC_CLK_TCK'),
              'schedstats': Path('/proc/sys/kernel/sched_schedstats').read_text().strip()})
        deadline = time.monotonic() + args.seconds
        count = 0
        try:
            while time.monotonic() < deadline:
                if task_stat((process / 'stat').read_text())['start_ticks'] != identity:
                    raise RuntimeError('实验 PID 已被复用')
                emit(sample(args.pid))
                count += 1
                time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
        except (OSError, ValueError, RuntimeError) as error:
            emit({'op': 'error', 'message': str(error), 'samples': count})
            raise SystemExit(1) from error
        emit({'op': 'complete', 'samples': count})


if __name__ == '__main__':
    main()
