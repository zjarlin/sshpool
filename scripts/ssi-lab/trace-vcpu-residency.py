#!/usr/bin/env python3
"""在独占实验 VM 记录 KVM 进出、宿主中断与调度；不改变抢占和中断配置。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import sys
import time

spec = importlib.util.spec_from_file_location('scheduling_trace', Path(__file__).with_name('trace-dsm-scheduling.py'))
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)
trace = scheduling.trace

EVENTS = ['kvm/kvm_entry', 'kvm/kvm_exit', 'kvm/kvm_vcpu_wakeup', 'kvm/kvm_wait_lapic_expire',
          'irq_vectors/local_timer_entry', 'irq_vectors/local_timer_exit',
          'irq_vectors/reschedule_entry', 'irq_vectors/reschedule_exit',
          'irq_vectors/call_function_entry', 'irq_vectors/call_function_exit',
          'irq_vectors/call_function_single_entry', 'irq_vectors/call_function_single_exit',
          'irq/irq_handler_entry', 'irq/irq_handler_exit', 'irq/softirq_entry', 'irq/softirq_exit',
          'sched/sched_switch', 'sched/sched_wakeup', 'sched/sched_migrate_task']


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
    group = f'sshpool_residency_{os.getpid()}'
    instance = root / 'instances' / group
    for event in EVENTS:
        if not (root / 'events' / event / 'format').exists():
            parser.error('缺少事件 ' + event)
    if (root / 'kprobe_events').read_text().strip():
        parser.error('节点上已有函数探针，本实验只使用静态跟踪点')
    task_filter = ' || '.join(f'common_pid == {pid}' for pid in sorted(tids))
    result = {'node': args.node, 'kernel': platform.release(), 'qemu_pid': args.attach_pid,
              'tasks_before': tasks, 'errors': [], 'heartbeats': [],
              'preempt_mode': Path('/sys/kernel/debug/sched/preempt').read_text().strip(),
              'clocksource': Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
              'vmx_preemption_timer': Path('/sys/module/kvm_intel/parameters/preemption_timer').read_text().strip()}
    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '65536')
            result['trace_clock'] = (instance / 'trace_clock').read_text().strip()
            result['buffer_kib_per_cpu'] = int((instance / 'buffer_size_kb').read_text().strip())
            for event in EVENTS:
                path = instance / 'events' / event
                if event.startswith('kvm/'):
                    trace.write(path / 'filter', task_filter)
                trace.write(path / 'enable', '1')
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
            output.write('{"trace":')
            try:
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    result['capture_stopped_ns'] = time.monotonic_ns()
                    result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                             for cpu in (instance / 'per_cpu').iterdir()}
                    with (instance / 'trace').open() as source:
                        scheduling.write_json_text(output, source)
                else:
                    output.write('""')
            finally:
                if instance.exists():
                    trace.write(instance / 'tracing_on', '0')
                    trace.write(instance / 'events/enable', '0')
                    instance.rmdir()
            result['trace_cleanup_complete'] = not instance.exists()
            result['tasks_after'] = {str(pid): scheduling.task_snapshot(pid) for pid in sorted(tids) if (Path('/proc') / str(pid)).exists()}
            for key, value in result.items():
                output.write(',' + json.dumps(key) + ':')
                json.dump(value, output)
            output.write('}\n')
    raise SystemExit(bool(result['errors']) or result.get('exit') != 0)


if __name__ == '__main__':
    main()
