#!/usr/bin/env python3
"""在独占 PF24 双节点中运行真实块设备客体，按协调器指令查询原生 DSM 引用。"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('pending', Path(__file__).with_name('probe-virtio-pending.py'))
pending = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pending)
RESEARCH = '7.1.0-rc3-sshpool-gvm-pf24'


def emit(data):
    print(json.dumps(data), flush=True)


def capture(args, process, record):
    pending.flush.wait_socket(process, args.directory / 'serial.sock')
    with socket.socket(socket.AF_UNIX) as serial, socket.socket(socket.AF_UNIX) as peer:
        serial.settimeout(0.2)
        serial.connect(str(args.directory / 'serial.sock'))
        pending.flush.wait_socket(process, args.directory / 'qmp.sock')
        peer.settimeout(30)
        peer.connect(str(args.directory / 'qmp.sock'))
        with peer.makefile('rb') as incoming:
            record['greeting'] = json.loads(incoming.readline())
            if 'QMP' not in record['greeting']:
                raise ValueError('不是 QMP 服务')
            monitor = pending.flush.Monitor(peer, incoming, record)
            monitor.command('qmp_capabilities')
            emit({'ready': True, 'node': args.node, 'pid': process.pid})

            def receive():
                try:
                    data = serial.recv(65536)
                except socket.timeout:
                    return
                if not data:
                    raise EOFError('串口提前关闭')
                record['serial'] += data.decode(errors='replace')
                with (args.directory / 'serial.log').open('ab') as output:
                    output.write(data)

            def wait_text(marker):
                deadline = time.monotonic() + 180
                while marker not in record['serial']:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise TimeoutError('没有客体标记 ' + marker)
                    receive()

            def snapshot(phase):
                start = len(record['qmp'])
                entry = {'phase': phase, 'time_ns': time.monotonic_ns(),
                         'qmp_start': start, 'status': monitor.command('query-status'),
                         'blocks': monitor.command('query-block')}
                realized = monitor.command('qom-get', {'path': '/machine/peripheral/ssi-disk',
                                                       'property': 'realized'})
                entry['realized'] = realized
                if realized:
                    entry['queue'] = monitor.command('x-query-virtio-queue-status',
                        {'path': pending.VIRTIO_PATH, 'queue': 0})
                entry['pins'] = []
                for _ in range(2 if args.pin_query == 'native' else 0):
                    raw = monitor.command('human-monitor-command', {'command-line': 'ssi_device_pins'})
                    pins = json.loads(raw)
                    if pins.get('ret') != 0 or pins.get('version') != 1 or pins.get('error') != 0 or pins.get('reserved') != 0:
                        raise ValueError('原生引用查询失败 ' + raw)
                    entry['pins'].append(pins)
                entry['qmp_end'] = len(record['qmp'])
                entry['threads'] = [{'tid': int(task.name), 'name': (task / 'comm').read_text().strip()}
                                    for task in sorted(Path(f'/proc/{process.pid}/task').iterdir())]
                record['snapshots'].append(entry)
                return entry

            while True:
                available = select.select([sys.stdin, serial], [], [], 180)[0]
                if not available:
                    raise TimeoutError('协调器指令超时')
                if serial in available:
                    receive()
                if sys.stdin not in available:
                    continue
                line = sys.stdin.readline()
                if not line:
                    raise EOFError('协调器提前关闭')
                request = json.loads(line)
                record['actions'].append({'request': request, 'time_ns': time.monotonic_ns()})
                op = request['op']
                value = None
                if op == 'wait_ready':
                    wait_text('SSI_BLOCK_READY')
                elif op == 'write':
                    if args.node != 0:
                        raise ValueError('只允许节点零发起客体写入')
                    serial.sendall(b'write\n')
                    wait_text('SSI_BLOCK_WRITE_BEGIN')
                elif op == 'wait_write':
                    wait_text('SSI_BLOCK_WRITE_OK')
                elif op == 'snapshot':
                    value = snapshot(request['phase'])
                elif op == 'status':
                    value = monitor.command('query-status')
                elif op == 'qmp':
                    name = request['name']
                    if name not in ('stop', 'cont', 'system_reset', 'qom-set'):
                        raise ValueError('未允许的管理动作')
                    arguments = None
                    if name == 'qom-set':
                        arguments = {'path': '/machine/peripheral/ssi-disk', 'property': 'realized', 'value': False}
                    value = monitor.command(name, arguments)
                elif op in ('quit', 'wait_exit', 'crash'):
                    if (op in ('quit', 'crash')) != (args.node == 0):
                        raise ValueError('只能由节点零关闭双节点实例')
                    if op == 'quit':
                        try:
                            monitor.command('quit')
                            record['quit_transport'] = 'reply'
                        except ConnectionResetError:
                            record['quit_transport'] = 'reset'
                        except EOFError:
                            record['quit_transport'] = 'eof'
                    elif op == 'crash':
                        # 只杀死本次新建的 QEMU 子进程，作为显式记录的断连注入。
                        record['injected_fault'] = 'SIGKILL'
                        process.kill()
                    process.wait(timeout=40)
                    record['exit_observed_ns'] = time.monotonic_ns()
                    emit({'op': op, 'ok': True, 'exit': process.returncode})
                    return
                else:
                    raise ValueError('未知协调器动作')
                emit({'op': op, 'ok': True, 'value': value})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'firmware', 'guest-kernel', 'initramfs', 'directory'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('require-sha256', 'require-kernel', 'guest-kernel-sha256', 'initramfs-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--node', type=int, choices=(0, 1), required=True)
    parser.add_argument('--peers', nargs=2, required=True)
    parser.add_argument('--error', type=int, choices=(0, 5, 28), required=True)
    parser.add_argument('--pin-query', choices=('native', 'none'), default='native')
    args = parser.parse_args()
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or
            args.require_kernel != RESEARCH or platform.release() != RESEARCH):
        parser.error('只允许指定 PF24 的独占实验 VM')
    addresses = [ipaddress.IPv4Address(value) for value in args.peers]
    if addresses[0] == addresses[1] or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        parser.error('需要不同节点和可用 KVM')
    for path, expected in ((args.qemu, args.require_sha256), (args.guest_kernel, args.guest_kernel_sha256),
                           (args.initramfs, args.initramfs_sha256)):
        if not path.is_absolute() or pending.digest(path) != expected:
            parser.error('运行时文件路径或哈希不符')
    if not args.firmware.is_absolute() or not args.firmware.is_dir():
        parser.error('固件目录不符')
    try:
        config = pending.prepare(args)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    command = pending.command(args)
    command += ['-name', 'sshpool-device-probe,debug-threads=on']
    command[command.index('-cpu') + 1] = 'qemu64,-x2apic,+tsc-adjust,enforce'
    command[command.index('-smp') + 1] = '4,sockets=2,cores=2,threads=1'
    command += ['-local-cpu', f'cpus=2,start={args.node * 2},iplist=' + ' '.join(args.peers)]
    record = {'schema': 1, 'kernel': platform.release(), 'node': args.node, 'command': command,
              'qemu_sha256': args.require_sha256, 'guest_kernel_sha256': args.guest_kernel_sha256,
              'initramfs_sha256': args.initramfs_sha256, 'capture_sha256': pending.digest(Path(__file__)),
              'qmp': [], 'snapshots': [], 'actions': [], 'serial': '', 'injected_errno': args.error,
              'blkdebug_config': config, 'pin_query': args.pin_query,
              'errors': [], 'forced_cleanup': False}
    process = None
    with (args.directory / 'stdout.log').open('xb') as out, (args.directory / 'stderr.log').open('xb') as err:
        try:
            process = subprocess.Popen(command, stdout=out, stderr=err,
                                       env=os.environ | {'SSHPOOL_LAB_DEVICE_PINS': '1'})
            record['pid'] = process.pid
            capture(args, process, record)
        except (OSError, ValueError, EOFError, KeyError, subprocess.TimeoutExpired) as error:
            record['errors'].append(str(error))
        finally:
            if process is not None and process.poll() is None:
                record['forced_cleanup'] = True
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            record['qemu_exit'] = None if process is None else process.returncode
    record['stderr'] = (args.directory / 'stderr.log').read_text()
    with (args.directory / 'disk.raw').open('rb') as image:
        image.seek(pending.OFFSET)
        data = image.read(pending.LENGTH)
    record['payload_matches'] = data == b'\x5a' * pending.LENGTH
    record['payload_zero'] = data == b'\0' * pending.LENGTH
    record['disk_sha256'] = pending.digest(args.directory / 'disk.raw')
    (args.directory / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    emit({'finished': True, 'node': args.node, 'errors': record['errors'], 'exit': record['qemu_exit']})
    raise SystemExit(bool(record['errors']))


if __name__ == '__main__':
    main()
