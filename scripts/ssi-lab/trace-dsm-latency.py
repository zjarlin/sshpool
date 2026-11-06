#!/usr/bin/env python3
"""包装真实页面交接工作进程，记录其 DSM 锁和传输函数的入口/返回，不改变网络参数。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('trace', Path(__file__).with_name('trace-teardown.py'))
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--worker', type=Path)
    mode.add_argument('--attach-pid', type=int)
    parser.add_argument('--node', choices=['0', '1'], required=True)
    parser.add_argument('--peer', action='append', default=[])
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        parser.error('只在指定 x86 实验内核以 root 运行')
    if args.worker and len(args.peer) != 2:
        parser.error('必须提供两个 peer 参数，单节点的第二项为减号')
    if args.attach_pid:
        target = Path('/proc') / str(args.attach_pid)
        command = (target / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        if not (target / 'comm').read_text().startswith('qemu-system-') or '-name sshpool-' not in command:
            parser.error('附加目标必须是显式命名的 SSHPool 实验 QEMU')
    for path in Path('/proc').iterdir():
        try:
            name = (path / 'comm').read_text().strip()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if args.attach_pid and name.startswith('qemu-system-') and path.name != str(args.attach_pid):
            parser.error('存在第二个 QEMU，拒绝混合跟踪')
        if args.worker and name.startswith(('qemu-system-', 'kvm-dsm/', 'dsm-conn/', 'probe-dsm-', 'probe-pvclock')):
            parser.error('已有实验进程')
    if args.worker and subprocess.check_output(['ss', '-H', '-tan', '( sport = :37710 or sport = :37711 )']).strip():
        parser.error('DSM 端口尚未回收')
    root = Path('/sys/kernel/tracing')
    group = f'sshpool_latency_{os.getpid()}'
    instance = root / 'instances' / group
    probes = [('p', 'lat_ioctl', 'kvm_vm_ioctl_dsm command=$arg2:x32'),
              ('r64', 'lat_ioctl_done', 'kvm_vm_ioctl_dsm code=$retval:s32'),
              ('p', 'lat_send', 'ktcp_send cb=$arg1:x64 length=$arg3:u64 txid=+4($arg5):u16'),
              ('r64', 'lat_sent', 'ktcp_send code=$retval:s32'),
              ('p', 'lat_receive', 'ktcp_receive cb=$arg1:x64 capacity=$arg3:u64 txid=+4($arg5):u16'),
              ('r64', 'lat_received', 'ktcp_receive code=$retval:s32'),
              ('p', 'lat_lock', 'dsm_lock slot=$arg2:x64 vfn=$arg3:x64'),
              ('r64', 'lat_locked', 'dsm_lock'),
              ('p', 'lat_killable', 'dsm_lock_killable slot=$arg1:x64 vfn=$arg2:x64'),
              ('r64', 'lat_killable_done', 'dsm_lock_killable code=$retval:s32'),
              ('p', 'lat_unlock', 'dsm_unlock slot=$arg2:x64 vfn=$arg3:x64')]
    if args.attach_pid:
        probes.extend([('p', 'lat_clock_update', 'kvm_guest_time_update'),
                       ('r64', 'lat_clock_updated', 'kvm_guest_time_update code=$retval:s32'),
                       ('p', 'lat_acquire', 'kvm_dsm_vcpu_acquire_page gfn=$arg3:x64 write=$arg4:u8'),
                       ('r64', 'lat_acquired', 'kvm_dsm_vcpu_acquire_page code=$retval:s32'),
                       ('p', 'lat_fault', 'ivy_kvm_dsm_page_fault'),
                       ('r64', 'lat_faulted', 'ivy_kvm_dsm_page_fault code=$retval:s32')])
    names = {name for _, name, _ in probes}
    if any(row.split()[0] in names for row in (root / 'kprobe_profile').read_text().splitlines()):
        parser.error('同名事件已存在')
    registered = []
    worker = None
    result = {'node': int(args.node), 'kernel': platform.release(), 'errors': []}
    with args.output.open('x') as output:
        try:
            instance.mkdir()
            trace.write(instance / 'tracing_on', '0')
            trace.write(instance / 'trace_clock', 'global')
            trace.write(instance / 'buffer_size_kb', '32768' if args.attach_pid else '2048')
            for kind, name, symbol in probes:
                trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                registered.append(name)
            trace.write(instance / 'events' / group / 'enable', '1')
            if args.attach_pid:
                trace.write(instance / 'events/kvm/kvm_page_fault/enable', '1')
            result['capture_started_ns'] = time.monotonic_ns()
            trace.write(instance / 'tracing_on', '1')
            if args.attach_pid:
                result['qemu_pid'] = args.attach_pid
                print(json.dumps({'op': 'trace_ready', 'node': int(args.node)}), flush=True)
                if not select.select([sys.stdin], [], [], 360)[0] or sys.stdin.readline() != 'stop\n':
                    raise ValueError('未收到明确的窗口停止命令')
                result['exit'] = 0
            else:
                worker = subprocess.Popen([str(args.worker.resolve()), args.node, *args.peer, args.require_kernel])
                result['worker_pid'] = worker.pid
                result['exit'] = worker.wait(timeout=180)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            result['errors'].append(str(error))
        finally:
            if worker is not None and worker.poll() is None:
                worker.kill()
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    result['errors'].append('工作进程仍在内核中，必须核对专用 VM 的恢复状态')
            if instance.exists():
                trace.write(instance / 'tracing_on', '0')
                result['capture_stopped_ns'] = time.monotonic_ns()
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {cpu.name: (cpu / 'stats').read_text()
                                         for cpu in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(row for row in (root / 'kprobe_profile').read_text().splitlines()
                                                    if row.split() and row.split()[0] in registered)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    raise SystemExit(bool(result['errors']) or result.get('exit') != 0)


if __name__ == '__main__':
    main()
