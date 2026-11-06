#!/usr/bin/env python3
"""在独占实验 VM 记录宿主定时器编程、延后重装和中断；不改变定时器策略。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import shutil
import sys
import time

spec = importlib.util.spec_from_file_location('scheduling_trace', Path(__file__).with_name('trace-dsm-scheduling.py'))
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)
trace = scheduling.trace

EVENTS = ['timer/hrtimer_rearm', 'timer/tick_stop',
          'irq_vectors/local_timer_entry', 'irq_vectors/local_timer_exit',
          'irq_vectors/reschedule_entry', 'irq_vectors/reschedule_exit',
          'irq_vectors/call_function_entry', 'irq_vectors/call_function_exit',
          'irq_vectors/call_function_single_entry', 'irq_vectors/call_function_single_exit',
          'irq/irq_handler_entry', 'irq/irq_handler_exit', 'irq/softirq_entry', 'irq/softirq_exit',
          'sched/sched_switch', 'sched/sched_wakeup', 'sched/sched_migrate_task']
PROBES = [('p', 'ht_program', 'clockevents_program_event', 'dev=$arg1:x64 expires=$arg2:s64 force=$arg3:u8'),
          ('p', 'ht_lapic', 'lapic_next_event', 'delta=$arg1:u64 dev=$arg2:x64'),
          ('p', 'ht_deferred', '__hrtimer_rearm_deferred', '')]
BUFFER_KIB = 65536


def check_output_space(output, cpu_count):
    """按缓冲区八倍预留文本导出空间，另留 128 MiB；并发写盘仍可能导致导出失败。"""
    required = cpu_count * BUFFER_KIB * 1024 * 8 + 128 * 1024 * 1024
    available = shutil.disk_usage(output.parent).free
    if available < required:
        raise ValueError(f'跟踪导出空间不足：需要 {required} 字节，可用 {available} 字节')
    return {'required_free_bytes': required, 'available_free_bytes': available}


def heartbeat():
    return {'monotonic_ns': time.monotonic_ns(), 'raw_ns': time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
            'realtime_ns': time.time_ns(), 'stat': Path('/proc/stat').read_text(),
            'interrupts': Path('/proc/interrupts').read_text(), 'softirqs': Path('/proc/softirqs').read_text()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach-pid', type=int, required=True)
    parser.add_argument('--node', type=int, choices=[0, 1], required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        parser.error('只在明确指定的 x86 实验内核以 root 运行')
    target = Path('/proc') / str(args.attach_pid)
    if not (target / 'comm').read_text().startswith('qemu-system-') or b'-name\x00sshpool-' not in (target / 'cmdline').read_bytes():
        parser.error('目标不是明确命名的 SSHPool QEMU')
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
            parser.error('节点上存在其他探针')
        if name.startswith(('dsm-conn/', 'kvm-dsm/')):
            if name != f'kvm-dsm/{args.node}' and not name.startswith(f'dsm-conn/{args.node}:'):
                parser.error('DSM 线程归属不符')
            tids.add(int(path.name))
    tasks = {str(pid): scheduling.task_snapshot(pid) for pid in sorted(tids)}
    if sum(task['comm'].startswith('dsm-conn/') for task in tasks.values()) < 8:
        parser.error('DSM 尚未建立')
    root = Path('/sys/kernel/tracing')
    try:
        output_space = check_output_space(args.output, len(list((root / 'per_cpu').glob('cpu[0-9]*'))))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    group = f'sshpool_host_timers_{os.getpid()}'
    instance = root / 'instances' / group
    for event in EVENTS:
        if not (root / 'events' / event / 'format').exists():
            parser.error('缺少事件 ' + event)
    if (root / 'kprobe_events').read_text().strip():
        parser.error('节点上已有函数探针，拒绝混合实验')
    symbols = {line.split()[2] for line in Path('/proc/kallsyms').read_text().splitlines() if len(line.split()) >= 3}
    if any(symbol not in symbols for _, _, symbol, _ in PROBES):
        parser.error('缺少宿主定时器函数')
    names = {name for _, name, _, _ in PROBES}
    if any(line.split()[0] in names for line in (root / 'kprobe_profile').read_text().splitlines() if line.split()):
        parser.error('存在同名函数探针')
    registered = []
    result = {'node': args.node, 'kernel': platform.release(), 'qemu_pid': args.attach_pid,
              'output_space': output_space,
              'tasks_before': tasks, 'errors': [], 'heartbeats': [],
              'preempt_mode': Path('/sys/kernel/debug/sched/preempt').read_text().strip(),
              'timer_list_before': Path('/proc/timer_list').read_text(),
              'clocksource': Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
              'vmx_preemption_timer': Path('/sys/module/kvm_intel/parameters/preemption_timer').read_text().strip()}
    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', str(BUFFER_KIB))
            result['trace_clock'] = (instance / 'trace_clock').read_text().strip()
            result['buffer_kib_per_cpu'] = int((instance / 'buffer_size_kb').read_text().strip())
            for kind, name, symbol, fields in PROBES:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol} {fields}'.strip())
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            for event in EVENTS:
                path = instance / 'events' / event
                trace.write(path / 'enable', '1')
            result['event_formats'] = {event: (root / 'events' / event / 'format').read_text() for event in EVENTS}
            result['probe_formats'] = {name: (root / 'events' / group / name / 'format').read_text() for name in registered}
            result['capture_started_ns'] = time.monotonic_ns()
            trace.write(instance / 'tracing_on', '1')
            print(json.dumps({'op': 'trace_ready', 'node': args.node}), flush=True)
            deadline = time.monotonic() + 360
            while time.monotonic() < deadline:
                result['heartbeats'].append(heartbeat())
                if not select.select([sys.stdin], [], [], .1)[0]:
                    continue
                if sys.stdin.readline() != 'stop\n':
                    raise ValueError('未收到明确停止命令')
                result['exit'] = 0
                break
            else:
                raise TimeoutError('测量窗口超时')
        except (OSError, ValueError) as error:
            result['errors'].append(str(error))
        finally:
            try:
                output.write('{"trace":')
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    result['capture_stopped_ns'] = time.monotonic_ns()
                    result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                             for cpu in (instance / 'per_cpu').iterdir()}
                    result['kprobe_profile'] = '\n'.join(line for line in (root / 'kprobe_profile').read_text().splitlines() if line.split() and line.split()[0] in registered)
                    result['timer_list_after'] = Path('/proc/timer_list').read_text()
                    with (instance / 'trace').open() as source:
                        scheduling.write_json_text(output, source)
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
            result['tasks_after'] = {str(pid): scheduling.task_snapshot(pid) for pid in sorted(tids) if (Path('/proc') / str(pid)).exists()}
            for key, value in result.items():
                output.write(',' + json.dumps(key) + ':')
                json.dump(value, output)
            output.write('}\n')
    raise SystemExit(bool(result['errors']) or result.get('exit') != 0)


if __name__ == '__main__':
    main()
