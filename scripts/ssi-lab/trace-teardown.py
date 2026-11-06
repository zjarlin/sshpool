#!/usr/bin/env python3
"""在独占研究 VM 跟踪真实 KVM 销毁与 DSM 线程退出，不注入或修改内核执行顺序。"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess


def write(path, value):
    try:
        path.write_text(value + '\n')
    except OSError as error:
        raise OSError(f'写入 {path}: {error}') from error


def append_control(path, value):
    # Python 文本追加会先 SEEK_END，tracefs 不支持；也不能用会清空其他事件的 O_TRUNC。
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        data = (value + '\n').encode()
        if os.write(descriptor, data) != len(data):
            raise OSError(f'跟踪控制命令未完整写入：{path}')
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--receive-probe', type=Path, required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--close-order', choices=['peer-first', 'vm-first'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.release() != args.require_kernel:
        parser.error('仅允许在指定研究内核的独占实验节点以 root 执行')
    tracefs = Path('/sys/kernel/tracing')
    if not (tracefs / 'kprobe_events').is_file():
        parser.error('需要已挂载的 tracefs 与 CONFIG_KPROBE_EVENTS')
    for entry in Path('/proc').iterdir():
        try:
            name = (entry / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if name.startswith(('qemu-system-', 'kvm-dsm/', 'dsm-conn/', 'probe-pvclock')):
            parser.error('存在其他实验进程，拒绝混合多个 VM 的跟踪记录')
    ports = subprocess.check_output(['ss', '-H', '-tan',
                                     '( sport = :37710 or sport = :37711 )'])
    if ports.strip():
        parser.error('实验端口仍有 TCP 状态')

    group = f'sshpool_teardown_{os.getpid()}'
    instance = tracefs / 'instances' / group
    symbols = {row.split()[2] for row in Path('/proc/kallsyms').read_text().splitlines()
               if len(row.split()) >= 3}
    events = [('p', 'pre', 'kvm_arch_pre_destroy_vm'),
              ('r', 'pre_done', 'kvm_arch_pre_destroy_vm'),
              ('p', 'vcpu', 'kvm_arch_vcpu_destroy'),
              ('p', 'mmu', 'kvm_mmu_uninit_vm'),
              ('p', 'free', 'kvm_dsm_free'),
              ('r', 'free_done', 'kvm_dsm_free')]
    if 'kvm_dsm_stop' in symbols:
        events.extend([('p', 'stop', 'kvm_dsm_stop'), ('r', 'stop_done', 'kvm_dsm_stop')])
    if any(symbol not in symbols for _, _, symbol in events):
        parser.error('缺少跟踪所需的真实内核函数')
    names = {event for _, event, _ in events}
    if any(row.split()[0] in names for row in (tracefs / 'kprobe_profile').read_text().splitlines()
           if row.split()):
        parser.error('存在同名探针，无法唯一核对 kprobe 命中与丢失计数')
    if group in (tracefs / 'kprobe_events').read_text() or instance.exists():
        parser.error('跟踪名称已存在，拒绝覆盖')

    receive_output = args.output.with_suffix('.receive.json')
    if receive_output.exists():
        parser.error('接收探针证据已存在，拒绝覆盖')
    registered = []
    result = {'kernel': platform.release(), 'close_order': args.close_order,
              'has_stop_function': 'kvm_dsm_stop' in symbols, 'errors': []}
    # 先独占证据文件，再创建仅属于本次实验的 trace instance。
    with args.output.open('x') as output:
        try:
            instance.mkdir()
            write(instance / 'tracing_on', '0')
            write(instance / 'trace_clock', 'global')
            write(instance / 'buffer_size_kb', '256')
            for kind, event, symbol in events:
                try:
                    append_control(tracefs / 'kprobe_events', f'{kind}:{group}/{event} {symbol}')
                except OSError as error:
                    raise OSError(f'注册 {kind}:{event} {symbol}: {error}') from error
                registered.append(event)
            write(instance / 'events' / group / 'enable', '1')
            write(instance / 'events/sched/sched_process_exit/filter',
                  'comm ~ "dsm-conn/*" || comm ~ "kvm-dsm/*"')
            write(instance / 'events/sched/sched_process_exit/enable', '1')
            write(instance / 'trace', '')
            write(instance / 'tracing_on', '1')
            command = ['python3', str(args.receive_probe.resolve()),
                       '--worker', str(args.worker.resolve()),
                       '--require-kernel', args.require_kernel,
                       '--close-order', args.close_order, '--output', str(receive_output)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            write(instance / 'tracing_on', '0')
            result.update({'probe_exit': run.returncode, 'probe_stdout': run.stdout,
                           'probe_stderr': run.stderr,
                           'receive': json.loads(receive_output.read_text())})
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            # 只删除本次注册的事件和实例；保留系统其他 tracing 状态。
            if instance.exists():
                write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {
                    cpu.name: (cpu / 'stats').read_text()
                    for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(
                    line for line in (tracefs / 'kprobe_profile').read_text().splitlines()
                    if line.split() and line.split()[0] in registered)
                write(instance / 'events/enable', '0')
                instance.rmdir()
            for event in reversed(registered):
                append_control(tracefs / 'kprobe_events', f'-:{group}/{event}')
            result['trace_cleanup_complete'] = (
                not instance.exists() and group not in (tracefs / 'kprobe_events').read_text())
            output.write(json.dumps(result, indent=2) + '\n')
        if result['errors'] or result.get('probe_exit') != 0 or not result['trace_cleanup_complete']:
            raise SystemExit(1)
        print(json.dumps({'probe_exit': result['probe_exit'],
                          'has_stop_function': result['has_stop_function'],
                          'trace_cleanup_complete': result['trace_cleanup_complete']}))


if __name__ == '__main__':
    main()
