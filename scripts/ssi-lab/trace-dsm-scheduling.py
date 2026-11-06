#!/usr/bin/env python3
"""在独占实验 VM 记录 QEMU/DSM 的调度、TCP 接收与权限刷新；不修改调度策略。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import sys
import time

spec = importlib.util.spec_from_file_location('trace', Path(__file__).with_name('trace-teardown.py'))
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def task_snapshot(pid):
    root = Path('/proc') / str(pid)
    return {'comm': (root / 'comm').read_text().strip(), 'stat': (root / 'stat').read_text().strip(),
            'wchan': (root / 'wchan').read_text().strip(), 'scheduler': os.sched_getscheduler(pid),
            'priority': os.sched_getparam(pid).sched_priority, 'affinity': sorted(os.sched_getaffinity(pid))}


def heartbeat():
    return {'monotonic_ns': time.monotonic_ns(),
            'stat': '\n'.join(line for line in Path('/proc/stat').read_text().splitlines()
                              if line.startswith(('cpu', 'ctxt ', 'procs_running ', 'procs_blocked ')))}


def write_json_text(output, source):
    """按块转义跟踪文本，避免导出时同时复制数百 MiB 字符串导致实验节点 OOM。"""
    output.write('"')
    while True:
        chunk = source.read(65536)
        if not chunk:
            break
        output.write(json.dumps(chunk)[1:-1])
    output.write('"')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach-pid', type=int, required=True)
    parser.add_argument('--node', choices=['0', '1'], required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--buffer-kib', type=int, default=65536, help='每个宿主 CPU 的跟踪缓冲区，范围 8192 到 65536 KiB')
    args = parser.parse_args()
    if not 8192 <= args.buffer_kib <= 65536:
        parser.error('缓冲区超出独占实验 VM 的允许范围')
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        parser.error('只在明确指定的 x86 实验内核以 root 运行')
    target = Path('/proc') / str(args.attach_pid)
    command = (target / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
    if not (target / 'comm').read_text().startswith('qemu-system-') or '-name sshpool-' not in command:
        parser.error('目标不是显式命名的 SSHPool QEMU')
    tids = {int(path.name) for path in (target / 'task').iterdir()}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            name = (path / 'comm').read_text().strip()
        except FileNotFoundError:
            continue
        if name.startswith('qemu-system-') and int(path.name) != args.attach_pid:
            parser.error('节点上存在其他 QEMU')
        if name.startswith(('probe-dsm-', 'probe-pvclock')):
            parser.error('节点上存在其他 DSM 探针')
        if name.startswith(('dsm-conn/', 'kvm-dsm/')):
            if name != f'kvm-dsm/{args.node}' and not name.startswith(f'dsm-conn/{args.node}:'):
                parser.error('DSM 线程不属于指定节点')
            tids.add(int(path.name))
    initial = {str(pid): task_snapshot(pid) for pid in sorted(tids)}
    if sum(task['comm'].startswith('dsm-conn/') for task in initial.values()) < 8:
        parser.error('DSM 连接尚未建立')
    root = Path('/sys/kernel/tracing')
    group = f'sshpool_scheduling_{os.getpid()}'
    instance = root / 'instances' / group
    probes = [('p', 'sc_access', 'kvm_dsm_apply_access_right slot=$arg2:x64 vfn=$arg3:x64 access=$arg4:u64'),
              ('r64', 'sc_access_done', 'kvm_dsm_apply_access_right'),
              ('p', 'sc_flush', 'kvm_flush_remote_tlbs'),
              ('r64', 'sc_flush_done', 'kvm_flush_remote_tlbs'),
              ('p', 'sc_tcp', 'tcp_recvmsg sock=$arg1:x64 length=$arg3:u64 flags=$arg4:x32'),
              ('r64', 'sc_tcp_done', 'tcp_recvmsg code=$retval:s32')]
    names = {name for _, name, _ in probes}
    if any(line.split()[0] in names for line in (root / 'kprobe_profile').read_text().splitlines()):
        parser.error('同名探针已经存在')
    selected = sorted(tids)
    task_filter = ' || '.join(f'common_pid == {pid}' for pid in selected)
    filters = {
        'sched_switch': ' || '.join(f'prev_pid == {pid} || next_pid == {pid}' for pid in selected),
        'sched_wakeup': ' || '.join(f'pid == {pid}' for pid in selected),
        'sched_migrate_task': ' || '.join(f'pid == {pid}' for pid in selected),
    }
    result = {'node': int(args.node), 'kernel': platform.release(), 'qemu_pid': args.attach_pid,
              'tasks_before': initial, 'filters': filters, 'errors': [], 'heartbeats': []}
    registered = []
    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', str(args.buffer_kib))
            result['buffer_kib_per_cpu'] = int((instance / 'buffer_size_kb').read_text().strip())
            result['trace_clock'] = (instance / 'trace_clock').read_text().strip()
            result['preempt_mode'] = Path('/sys/kernel/debug/sched/preempt').read_text().strip()
            for kind, name, symbol in probes:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
                trace.write(instance / 'events' / group / name / 'filter', task_filter)
                trace.write(instance / 'events' / group / name / 'enable', '1')
            for name, condition in filters.items():
                event = instance / 'events/sched' / name
                trace.write(event / 'filter', condition)
                trace.write(event / 'enable', '1')
            result['capture_started_ns'] = time.monotonic_ns()
            trace.write(instance / 'tracing_on', '1')
            print(json.dumps({'op': 'trace_ready', 'node': int(args.node)}), flush=True)
            deadline = time.monotonic() + 360
            while time.monotonic() < deadline:
                result['heartbeats'].append(heartbeat())
                if not select.select([sys.stdin], [], [], .1)[0]:
                    continue
                if sys.stdin.readline() != 'stop\n':
                    raise ValueError('未收到明确的停止命令')
                result['exit'] = 0
                break
            else:
                raise TimeoutError('测量窗口超时')
        except (OSError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            output.write('{"trace":')
            try:
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    result['capture_stopped_ns'] = time.monotonic_ns()
                    result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                             for cpu in (instance / 'per_cpu').iterdir()}
                    result['kprobe_profile'] = '\n'.join(line for line in (root / 'kprobe_profile').read_text().splitlines()
                                                        if line.split() and line.split()[0] in registered)
                    with (instance / 'trace').open() as source:
                        write_json_text(output, source)
                else:
                    output.write('""')
            finally:
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    trace.write(instance / 'events/enable', '0')
                    instance.rmdir()
                for name in reversed(registered):
                    trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            result['tasks_after'] = {str(pid): task_snapshot(pid) for pid in selected if (Path('/proc') / str(pid)).exists()}
            for key, value in result.items():
                output.write(',' + json.dumps(key) + ':')
                json.dump(value, output)
            output.write('}\n')
    raise SystemExit(bool(result['errors']) or result.get('exit') != 0)


if __name__ == '__main__':
    main()
