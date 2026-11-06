#!/usr/bin/env python3
"""用真实 Linux 客体写入独立实验盘，记录错误暂停后的 virtio 请求生命周期。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import time

spec = importlib.util.spec_from_file_location('flush', Path(__file__).with_name('probe-shutdown-flush.py'))
flush = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flush)
VIRTIO_PATH = '/machine/peripheral/ssi-disk/virtio-backend'
OFFSET = 1024 * 1024
LENGTH = 4096


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(args):
    directory = args.directory
    if (not directory.is_absolute() or directory.parent.resolve() != directory.parent or
            any(c in str(directory) for c in (',', ':', '\n', '\r'))):
        raise ValueError('需要真实父目录下且不含 QEMU 分隔符的新绝对路径')
    directory.mkdir(mode=0o700)
    with (directory / 'disk.raw').open('xb') as out:
        out.truncate(flush.DISK_BYTES)
    config = ''
    if args.error:
        config = ('[inject-error]\nevent = "pwritev"\n'
                  f'errno = "{args.error}"\niotype = "write"\n'
                  'once = "on"\nimmediately = "on"\n')
    (directory / 'blkdebug.conf').write_text(config)
    return config


def command(args):
    directory = args.directory
    result = [str(args.qemu), '-machine', 'pc,accel=kvm,kernel-irqchip=split',
              '-cpu', 'qemu64,-x2apic', '-smp', '2', '-m', '256',
              '-nodefaults', '-display', 'none', '-monitor', 'none',
              '-L', str(args.firmware), '-kernel', str(args.guest_kernel),
              '-initrd', str(args.initramfs),
              '-append', 'console=ttyS0 rdinit=/init nokaslr panic=0 nox2apic',
              '-serial', 'unix:' + str(directory / 'serial.sock') + ',server=on,wait=on',
              '-qmp', 'unix:' + str(directory / 'qmp.sock') + ',server=on,wait=off',
              '-drive', 'if=none,id=ssi-probe,format=raw,cache=writeback,werror=stop,rerror=stop,file=blkdebug:' +
              str(directory / 'blkdebug.conf') + ':' + str(directory / 'disk.raw'),
              '-device', 'virtio-blk-pci,drive=ssi-probe,id=ssi-disk,serial=sshpool-pending-lab,'
              'disable-modern=on,vectors=0,num-queues=1']
    for event in ('virtqueue_pop', 'virtqueue_fill', 'virtio_blk_handle_write',
                  'virtio_blk_rw_complete', 'virtio_blk_req_complete', 'vm_stop_flush_all'):
        result += ['-trace', 'enable=' + event]
    return result


def capture(args, process, record):
    flush.wait_socket(process, args.directory / 'serial.sock')
    with socket.socket(socket.AF_UNIX) as serial, socket.socket(socket.AF_UNIX) as peer:
        serial.settimeout(0.2)
        serial.connect(str(args.directory / 'serial.sock'))
        flush.wait_socket(process, args.directory / 'qmp.sock')
        peer.settimeout(20)
        peer.connect(str(args.directory / 'qmp.sock'))
        with peer.makefile('rb') as incoming:
            record['greeting'] = json.loads(incoming.readline())
            if 'QMP' not in record['greeting']:
                raise ValueError('不是 QMP 服务')
            monitor = flush.Monitor(peer, incoming, record)
            monitor.command('qmp_capabilities')

            def receive():
                try:
                    data = serial.recv(65536)
                except socket.timeout:
                    return
                if not data:
                    raise EOFError('串口提前关闭')
                record['serial'] += data.decode(errors='replace')

            def wait_text(marker):
                deadline = time.monotonic() + 90
                while marker not in record['serial']:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise TimeoutError('客体没有输出 ' + marker)
                    receive()

            def snapshot(phase, queue=True):
                entry = {'phase': phase, 'time_ns': time.monotonic_ns(),
                         'status': monitor.command('query-status'),
                         'blocks': monitor.command('query-block')}
                if queue:
                    entry['devices'] = monitor.command('x-query-virtio')
                    entry['queue'] = monitor.command('x-query-virtio-queue-status',
                                                    {'path': VIRTIO_PATH, 'queue': 0})
                else:
                    entry['realized'] = monitor.command('qom-get',
                        {'path': '/machine/peripheral/ssi-disk', 'property': 'realized'})
                    try:
                        entry['devices'] = monitor.command('x-query-virtio')
                    except ValueError:
                        # 只有原生接口明确报告没有 virtio 设备才接受销毁后的空集合。
                        reply = record['qmp'][-1]['responses'][-1]
                        expected = {'class': 'GenericError', 'desc': 'No virtio devices found'}
                        if reply.get('error') != expected or entry['realized'] is not False:
                            raise
                        entry['devices'] = []
                record['snapshots'].append(entry)
                return entry

            wait_text('SSI_BLOCK_READY')
            initial = snapshot('ready')
            if not initial['status']['running'] or initial['queue']['inuse'] != 0:
                raise ValueError('写入前设备状态不符')
            serial.sendall(b'write\n')
            wait_text('SSI_BLOCK_WRITE_BEGIN')
            if args.error:
                deadline = time.monotonic() + 30
                while True:
                    status = monitor.command('query-status')
                    if status['status'] == 'io-error':
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError('真实写入没有触发错误暂停')
                    receive()
            else:
                wait_text('SSI_BLOCK_WRITE_OK')
            snapshot('after_write')
            monitor.command('stop')
            snapshot('after_stop')
            record['action'] = args.action
            if args.action == 'reset':
                monitor.command('system_reset')
                snapshot('after_reset')
            elif args.action == 'unrealize':
                monitor.command('qom-set', {'path': '/machine/peripheral/ssi-disk',
                                           'property': 'realized', 'value': False})
                snapshot('after_unrealize', queue=False)
            elif args.action == 'resume':
                monitor.command('cont')
                wait_text('SSI_BLOCK_WRITE_OK')
                monitor.command('stop')
                snapshot('after_resume')
            snapshot('before_quit', queue=args.action != 'unrealize')
            try:
                monitor.command('quit')
                record['quit_transport'] = 'reply'
            except ConnectionResetError:
                record['quit_transport'] = 'reset'
            except EOFError:
                record['quit_transport'] = 'eof'
    process.wait(timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'firmware', 'guest-kernel', 'initramfs', 'directory'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('require-sha256', 'require-kernel', 'guest-kernel-sha256', 'initramfs-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--error', type=int, choices=(0, 5, 28), required=True)
    parser.add_argument('--action', choices=('quit', 'reset', 'unrealize', 'resume'), required=True)
    args = parser.parse_args()
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or
            args.require_kernel != flush.STOCK or platform.release() != args.require_kernel):
        parser.error('只允许指定原版内核的独占 x86 Linux 实验 VM')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        parser.error('当前用户不能使用 KVM')
    for path, expected in ((args.qemu, args.require_sha256),
                           (args.guest_kernel, args.guest_kernel_sha256),
                           (args.initramfs, args.initramfs_sha256)):
        if not path.is_absolute() or digest(path) != expected:
            parser.error('运行时文件路径或哈希不符')
    if not args.firmware.is_absolute() or not args.firmware.is_dir():
        parser.error('需要明确的固件绝对路径')
    try:
        config = prepare(args)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    record = {'schema': 1, 'kernel': platform.release(), 'qemu_sha256': args.require_sha256,
              'guest_kernel_sha256': args.guest_kernel_sha256, 'initramfs_sha256': args.initramfs_sha256,
              'capture_sha256': digest(Path(__file__)), 'qmp': [], 'snapshots': [], 'serial': '',
              'injected_errno': args.error, 'blkdebug_config': config, 'image_bytes': flush.DISK_BYTES,
              'write_offset': OFFSET, 'write_bytes': LENGTH, 'errors': [], 'forced_cleanup': False,
              'directory_created_exclusively': True, 'dsm_observed': False}
    invocation = command(args)
    record['command'] = invocation
    process = None
    started = time.monotonic_ns()
    with (args.directory / 'stdout.log').open('xb') as out, (args.directory / 'stderr.log').open('xb') as err:
        try:
            process = subprocess.Popen(invocation, stdout=out, stderr=err)
            record['pid'] = process.pid
            capture(args, process, record)
        except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as error:
            record['errors'].append(str(error))
        finally:
            if process is not None and process.poll() is None:
                record['forced_cleanup'] = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            record['qemu_exit'] = None if process is None else process.returncode
    record['elapsed_ns'] = time.monotonic_ns() - started
    record['stderr'] = (args.directory / 'stderr.log').read_text()
    with (args.directory / 'disk.raw').open('rb') as source:
        source.seek(OFFSET)
        payload = source.read(LENGTH)
    record['disk_sha256'] = digest(args.directory / 'disk.raw')
    record['payload_sha256'] = hashlib.sha256(payload).hexdigest()
    record['payload_matches'] = payload == b'\x5a' * LENGTH
    record['payload_zero'] = payload == b'\0' * LENGTH
    (args.directory / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record.get(k) for k in ('injected_errno', 'action', 'qemu_exit', 'errors', 'forced_cleanup')}))
    raise SystemExit(bool(record['errors']))


if __name__ == '__main__':
    main()
