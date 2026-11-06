#!/usr/bin/env python3
"""在暂停的研究 QEMU 中触发诊断命令，记录真实 KVM 映射错误及完整内核跟踪。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import time

spec = importlib.util.spec_from_file_location('trace', Path(__file__).with_name('trace-teardown.py'))
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
PROBES = [('p', 'qm_enter', 'kvm_vm_ioctl ioctl=$arg2:x32 write=+u0($arg3):u8 unpin=+u1($arg3):u8 hva=+u8($arg3):x64 length=+u16($arg3):u64'),
          ('r128', 'qm_return', 'kvm_vm_ioctl code=$retval:s64')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--require-sha256', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--qmp', type=Path, required=True)
    parser.add_argument('--mode', type=int, choices=range(5), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
            args.require_kernel != '7.1.0-rc3-sshpool-gvm-pf24' or
            platform.release() != args.require_kernel):
        parser.error('只允许独占 PF24 研究内核和 root')
    process = Path(f'/proc/{args.pid}')
    executable = (process / 'exe').resolve(strict=True)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    arguments = (process / 'cmdline').read_bytes().split(b'\0')
    if digest != args.require_sha256 or b'-S' not in arguments or b'-local-cpu' not in arguments:
        parser.error('运行时哈希或暂停分布式实例参数不符')
    if b'SSHPOOL_LAB_MAP_PROBE=1' not in (process / 'environ').read_bytes().split(b'\0'):
        parser.error('没有显式启用诊断入口')
    root = Path('/sys/kernel/tracing')
    if (root / 'kprobe_events').read_text().strip() or list((root / 'instances').iterdir()):
        parser.error('已经存在跟踪')
    group = f'sshpool_qemu_map_{os.getpid()}'
    instance = root / 'instances' / group
    result = {'kernel': platform.release(), 'qemu_sha256': digest, 'pid': args.pid,
              'mode': args.mode, 'errors': [], 'events': []}
    registered = []

    def mark(phase):
        result['events'].append({'phase': phase, 'time_ns': time.monotonic_ns()})
        trace.write(instance / 'trace_marker', phase)

    with args.output.open('x') as output:
        try:
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(15)
                peer.connect(str(args.qmp))
                with peer.makefile('rb') as incoming:
                    greeting = json.loads(incoming.readline())
                    if 'QMP' not in greeting:
                        raise ValueError('不是 QMP 服务')

                    def command(name, values=None):
                        request = {'execute': name, 'id': name}
                        if values is not None:
                            request['arguments'] = values
                        peer.sendall((json.dumps(request) + '\n').encode())
                        while True:
                            line = incoming.readline()
                            if not line:
                                return None
                            reply = json.loads(line)
                            if reply.get('id') == name:
                                if 'error' in reply:
                                    raise ValueError(str(reply['error']))
                                return reply.get('return')

                    if command('qmp_capabilities') != {}:
                        raise ValueError('QMP 协商失败')
                    result['status'] = command('query-status')
                    if result['status']['running'] or result['status']['status'] not in ('paused', 'prelaunch'):
                        raise ValueError('客体没有暂停')
                    instance.mkdir()
                    trace.write(instance / 'tracing_on', '0')
                    trace.write(instance / 'trace_clock', 'global')
                    trace.write(instance / 'buffer_size_kb', '4096')
                    for kind, name, symbol in PROBES:
                        trace.append_control(root / 'kprobe_events', f'{kind}:{group}/{name} {symbol}')
                        registered.append(name)
                    trace.write(instance / 'events' / group / 'enable', '1')
                    trace.write(instance / 'tracing_on', '1')
                    mark('case_begin')
                    try:
                        result['command_return'] = command('human-monitor-command', {'command-line': f'ssi_map_probe {args.mode}'})
                        result['command_transport'] = {'kind': 'eof' if result['command_return'] is None else 'reply'}
                    except ConnectionResetError as error:
                        # 诊断从命令内部退出进程，QMP 可表现为复位；仍须核对进程退出和原生证据。
                        result['command_return'] = None
                        result['command_transport'] = {'kind': 'reset', 'errno': error.errno}
                    mark('command_ended')
                    deadline = time.monotonic() + 10
                    while process.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    result['qemu_remaining'] = process.exists()
                    if result['qemu_remaining']:
                        raise ValueError('诊断实例未退出')
                    mark('process_ended')
        except (OSError, ValueError, KeyError) as error:
            result['errors'].append(str(error))
        finally:
            if instance.exists():
                trace.write(instance / 'tracing_on', '0')
                result['trace'] = (instance / 'trace').read_text()
                result['trace_stats'] = {p.name: (p / 'stats').read_text() for p in (instance / 'per_cpu').iterdir()}
                result['kprobe_profile'] = '\n'.join(line for line in (root / 'kprobe_profile').read_text().splitlines()
                                                     if line.split() and line.split()[0] in registered)
                trace.write(instance / 'events/enable', '0')
                instance.rmdir()
            for name in reversed(registered):
                trace.append_control(root / 'kprobe_events', f'-:{group}/{name}')
            result['trace_cleanup_complete'] = not instance.exists() and group not in (root / 'kprobe_events').read_text()
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ('mode', 'errors', 'qemu_remaining', 'trace_cleanup_complete')}))
    raise SystemExit(bool(result['errors']))


if __name__ == '__main__':
    main()
