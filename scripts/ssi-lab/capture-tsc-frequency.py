#!/usr/bin/env python3
"""在独占的原版 Linux 实验 VM 采集三个频率请求，保留实际退出与前后状态。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=15).stdout


def snapshot(kernel):
    files = [Path(name) for name in (
        '/etc/fstab', '/etc/default/grub', '/boot/grub/grub.cfg', '/boot/grub/grubenv',
        '/etc/ssh/sshd_config', '/proc/cmdline', '/proc/sys/net/ipv4/ip_local_port_range',
        f'/boot/vmlinuz-{kernel}', f'/boot/config-{kernel}')]
    for pattern in ('netplan/*.yaml', 'ssh/sshd_config.d/*.conf', 'default/grub.d/*.cfg'):
        files.extend(Path('/etc').glob(pattern))
    modules = {}
    for name in ('kvm', 'kvm_intel'):
        filename = Path(command(['modinfo', '-F', 'filename', name]).strip())
        modules[name] = {'sha256': sha(filename.read_bytes()),
                         'srcversion': command(['modinfo', '-F', 'srcversion', name]).strip(),
                         'vermagic': command(['modinfo', '-F', 'vermagic', name]).strip()}
        files.extend(Path(f'/sys/module/{name}/parameters').glob('*'))
    processes, kvm_fds = [], []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            comm = (proc / 'comm').read_text().strip()
            if comm.startswith(('qemu', 'kvm-dsm')) or comm in ('probe-tsc', 'tsc-vcpu'):
                processes.append({'pid': int(proc.name), 'comm': comm})
            for fd in (proc / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                except FileNotFoundError:
                    continue
                if target == '/dev/kvm' or 'kvm-vm' in target or 'kvm-vcpu' in target:
                    kvm_fds.append({'pid': int(proc.name), 'fd': fd.name, 'target': target})
        except (FileNotFoundError, ProcessLookupError):
            continue
    identities = {name: sha(Path(path).read_bytes().strip()) for name, path in {
        'machine': '/etc/machine-id', 'dmi': '/sys/class/dmi/id/product_uuid',
        'boot': '/proc/sys/kernel/random/boot_id'}.items()}
    return {
        'kernel': kernel, 'version': platform.version(), 'architecture': platform.machine(),
        'identity_sha256': identities, 'modules': modules,
        'files_sha256': {str(path): sha(path.read_bytes()) for path in sorted(set(files))},
        'firewall_sha256': sha(command(['nft', '--stateless', 'list', 'ruleset']).encode()),
        'clocksource': Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
        'allowed_cpus': sorted(os.sched_getaffinity(0)), 'processes': processes, 'kvm_fds': kvm_fds,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.machine() != 'x86_64' or platform.release() != args.require_kernel:
        print('拒绝：架构或内核与显式要求不符', file=sys.stderr)
        return 2
    binary = args.binary.resolve()
    if sha(binary.read_bytes()) != args.binary_sha256:
        raise ValueError('二进制哈希不符')
    before = snapshot(args.require_kernel)
    if before['processes'] or before['kvm_fds']:
        raise ValueError('实验节点仍有 KVM 或研究进程')
    data = {'schema': 1, 'source_sha256': sha(args.source.read_bytes()),
            'capture_sha256': sha(Path(__file__).read_bytes()), 'binary_sha256': args.binary_sha256,
            'before': before, 'runs': [], 'started_unix_ns': time.time_ns()}
    # 独占创建输出，失败也保留本轮已经取得的记录；不能覆盖旧实验。
    with args.output.open('x') as output:
        try:
            for mode in ('native', 'faster', 'slower'):
                started = time.monotonic_ns()
                result = subprocess.run([str(binary), args.require_kernel, mode],
                                        capture_output=True, text=True, timeout=15)
                data['runs'].append({'mode': mode, 'exit': result.returncode,
                                     'stdout': result.stdout, 'stderr': result.stderr,
                                     'elapsed_ns': time.monotonic_ns() - started})
                if result.returncode:
                    raise RuntimeError(f'{mode} 探针失败，保留输出并停止后续运行')
        finally:
            data['after'] = snapshot(args.require_kernel)
            data['finished_unix_ns'] = time.time_ns()
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.write('\n')
    if data['after'] != before:
        raise ValueError('前后状态不一致，请检查保留的记录')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
