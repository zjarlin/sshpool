#!/usr/bin/env python3
"""在独占 PF28 上记录真实 QEMU 关闭窗口，保留全部 VM ioctl 与新建管理连接。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import sys
import time

spec = importlib.util.spec_from_file_location('close_probe', Path(__file__).with_name('probe-kernel-close.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--node', type=int, choices=[0, 1], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != '7.1.0-rc3-sshpool-gvm-pf28':
        parser.error('仅用于独占 PF28 x86 实验节点')
    target = Path('/proc') / str(args.pid)
    command = (target / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
    if not (target / 'comm').read_text().startswith('qemu-system-') or '-name sshpool-' not in command:
        parser.error('目标不是明确命名的 SSHPool QEMU')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已有其他跟踪')
    tasks = probe.safety.tasks()
    if not tasks or any(task['name'] != f'kvm-dsm/{args.node}' and
                        not task['name'].startswith(f'dsm-conn/{args.node}:') for task in tasks.values()):
        parser.error('DSM 线程不属于本次实验节点')
    group = f'sshpool_qemu_close_{os.getpid()}'
    instance = root / 'instances' / group
    registered = []
    result = {'kernel': platform.release(), 'node': args.node, 'qemu_pid': args.pid,
              'command': command, 'qemu_sha256': hashlib.sha256((target / 'exe').read_bytes()).hexdigest(),
              'tasks_before': tasks, 'events': [], 'errors': [],
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def mark(phase):
        result['events'].append({'phase': phase, 'time_ns': time.monotonic_ns()})
        probe.trace.write(instance / 'trace_marker', phase)

    with args.output.open('x') as output:
        try:
            instance.mkdir()
            probe.trace.write(instance / 'tracing_on', '0')
            probe.trace.write(instance / 'trace_clock', 'global')
            probe.trace.write(instance / 'buffer_size_kb', '16384')
            for kind, name, symbol in probe.PROBES:
                probe.trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            probe.trace.write(instance / 'events' / group / 'enable', '1')
            probe.trace.write(instance / 'tracing_on', '1')
            mark('capture_begin')
            print(json.dumps({'ready': True, 'pid': args.pid, 'node': args.node}), flush=True)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if not select.select([sys.stdin], [], [], 0.2)[0]:
                    continue
                if sys.stdin.readline() != 'stop\n':
                    raise ValueError('未收到明确的停止命令')
                mark('capture_end')
                result['qemu_present_after'] = target.exists()
                result['remaining_tasks'] = probe.safety.tasks()
                break
            else:
                raise ValueError('关闭观测窗口超时')
        except (OSError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                probe.trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                         for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(
                    line for line in (root / 'kprobe_profile').read_text().splitlines()
                    if line.split() and line.split()[0] in registered)
                probe.trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                probe.trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            json.dump(result, output, indent=2)
            output.write('\n')
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
