#!/usr/bin/env python3
"""在新建的隔离测试盘上注入 blkdebug 刷盘错误，保存真实 QMP、跟踪和退出状态。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import socket
import stat
import subprocess
import sys
import time

STOCK = '6.8.0-147-generic'
RESEARCH = '7.1.0-rc3-sshpool-gvm-pf24'
DISK_BYTES = 64 * 1024 * 1024
WRITE_BYTES = 65536
WRITE_COMMAND = 'qemu-io ssi-probe "write -P 0x5a 0 64k"'
READ_COMMAND = 'qemu-io ssi-probe "read -P 0x5a 0 64k"'


class Monitor:
    """逐条记录原始请求与对应回复，不把 QMP 受理当作最终关机成功。"""
    def __init__(self, peer, incoming, record):
        self.peer = peer
        self.incoming = incoming
        self.record = record

    def command(self, name, arguments=None):
        request = {'execute': name, 'id': len(self.record['qmp'])}
        if arguments is not None:
            request['arguments'] = arguments
        entry = {'request': request, 'responses': []}
        self.record['qmp'].append(entry)
        self.peer.sendall((json.dumps(request) + '\n').encode())
        while True:
            line = self.incoming.readline()
            if not line:
                raise EOFError('QMP 在对应回复前关闭')
            reply = json.loads(line)
            entry['responses'].append(reply)
            if reply.get('id') == request['id']:
                break
        if 'error' in reply:
            raise ValueError('QMP 失败：' + str(reply['error']))
        return reply.get('return')


def wait_socket(process, path):
    deadline = time.monotonic() + 120
    while not path.exists():
        if process.poll() is not None:
            raise ValueError('QEMU 在 QMP 就绪前退出')
        if time.monotonic() >= deadline:
            raise TimeoutError('QMP 启动超时')
        time.sleep(0.1)


def prepare(args, digest):
    directory = args.directory
    # blkdebug 和 drive 参数使用冒号与逗号分隔，目录不能改变参数解析边界。
    if (not directory.is_absolute() or directory.parent.resolve() != directory.parent or
            any(char in str(directory) for char in (',', ':', '\n', '\r'))):
        raise ValueError('需要真实父目录下且不含 QEMU 参数分隔符的新绝对路径')
    directory.mkdir(mode=0o700)
    image = directory / 'disk.raw'
    with image.open('xb') as output:
        output.truncate(DISK_BYTES)
    config = ''
    if args.error:
        config = ('[inject-error]\nevent = "flush_to_disk"\n'
                  f'errno = "{args.error}"\niotype = "flush"\nimmediately = "on"\n')
    (directory / 'blkdebug.conf').write_text(config)
    record = {'kernel': platform.release(), 'qemu_sha256': digest,
              'paired': args.peers is not None, 'node': args.node, 'injected_errno': args.error,
              'directory_created_exclusively': True, 'image_bytes': DISK_BYTES,
              'write_bytes': WRITE_BYTES, 'blkdebug_config': config,
              'qmp': [], 'errors': [], 'forced_cleanup': False}
    return record


def qemu_command(args):
    directory = args.directory
    paired = args.peers is not None
    cpu = 'qemu64,-x2apic,+tsc-adjust,enforce' if paired else 'qemu64,-x2apic'
    topology = '4,sockets=2,cores=2,threads=1' if paired else '2'
    command = [str(args.qemu), '-machine', 'pc,accel=kvm,kernel-irqchip=split',
               '-cpu', cpu, '-smp', topology, '-m', '256' if paired else '64',
               '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
               '-S', '-no-reboot', '-L', str(args.firmware),
               '-qmp', 'unix:' + str(directory / 'qmp.sock') + ',server=on,wait=off',
               '-trace', 'enable=vm_stop_flush_all', '-trace', 'enable=blk_co_pwritev',
               '-drive', 'if=none,id=ssi-probe,format=raw,cache=writeback,file=blkdebug:' +
               str(directory / 'blkdebug.conf') + ':' + str(directory / 'disk.raw'),
               '-device', 'virtio-blk-pci,drive=ssi-probe,id=ssi-disk,disable-modern=on,vectors=0']
    if paired:
        command += ['-local-cpu', f'cpus=2,start={args.node * 2},iplist=' + ' '.join(args.peers)]
    return command


def capture(args, record, process):
    wait_socket(process, args.directory / 'qmp.sock')
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(30)
        peer.connect(str(args.directory / 'qmp.sock'))
        with peer.makefile('rb') as incoming:
            record['greeting'] = json.loads(incoming.readline())
            if 'QMP' not in record['greeting']:
                raise ValueError('不是 QMP 服务')
            monitor = Monitor(peer, incoming, record)
            monitor.command('qmp_capabilities')
            status = monitor.command('query-status')
            if status != {'status': 'prelaunch', 'running': False}:
                raise ValueError('诊断要求客体从未运行')
            monitor.command('query-block')
            monitor.command('human-monitor-command', {'command-line': WRITE_COMMAND})
            monitor.command('human-monitor-command', {'command-line': READ_COMMAND})
            monitor.command('query-blockstats')
            record['prepared_ns'] = time.monotonic_ns()
            print(json.dumps({'ready': True, 'node': args.node, 'pid': process.pid}), flush=True)
            action = 'quit'
            if args.peers:
                if not select.select([sys.stdin], [], [], 120)[0]:
                    raise TimeoutError('没有收到配对协调器命令')
                action = sys.stdin.readline().strip()
                expected = 'wait' if args.node else 'quit'
                if action != expected:
                    raise ValueError('配对实例只能由节点零请求关闭')
            record['action'] = action
            record['action_ns'] = time.monotonic_ns()
            if action == 'quit':
                try:
                    monitor.command('quit')
                    record['quit_transport'] = {'kind': 'reply'}
                except ConnectionResetError as error:
                    # 失败停止可能早于 QMP 回复发送；仍须核对实际刷盘跟踪和进程退出。
                    record['quit_transport'] = {'kind': 'reset', 'errno': error.errno}
                except EOFError:
                    record['quit_transport'] = {'kind': 'eof'}
    process.wait(timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--require-sha256', required=True)
    parser.add_argument('--require-kernel', required=True)
    parser.add_argument('--firmware', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--error', type=int, choices=(0, 5, 28), required=True)
    parser.add_argument('--node', type=int, choices=(0, 1), default=0)
    parser.add_argument('--peers', nargs=2)
    args = parser.parse_args()
    if (platform.machine() != 'x86_64' or platform.system() != 'Linux' or
            args.require_kernel not in (STOCK, RESEARCH) or platform.release() != args.require_kernel):
        parser.error('只允许指定原版或 PF24 的独占 x86 Linux 实验 VM')
    if args.peers and args.require_kernel != RESEARCH:
        parser.error('配对实例需要 PF24')
    if not args.qemu.is_absolute() or not args.firmware.is_dir():
        parser.error('需要明确的 QEMU 与固件目录')
    digest = hashlib.sha256(args.qemu.read_bytes()).hexdigest()
    if digest != args.require_sha256:
        parser.error('运行时哈希不匹配')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        parser.error('当前用户不能使用 KVM')
    try:
        record = prepare(args, digest)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    command = qemu_command(args)
    record['command'] = command
    record['capture_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    process = None
    started = time.monotonic_ns()
    with (args.directory / 'stdout.log').open('xb') as out, (args.directory / 'stderr.log').open('xb') as err:
        try:
            process = subprocess.Popen(command, stdout=out, stderr=err)
            record['pid'] = process.pid
            capture(args, record, process)
        except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as error:
            record['errors'].append(str(error))
        finally:
            if process is not None and process.poll() is None:
                # 只清理本探针自己创建的进程；发生强制清理的记录必须拒绝验收。
                record['forced_cleanup'] = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            record['qemu_exit'] = None if process is None else process.returncode
    record['elapsed_ns'] = time.monotonic_ns() - started
    record['stdout'] = (args.directory / 'stdout.log').read_text()
    record['stderr'] = (args.directory / 'stderr.log').read_text()
    image = args.directory / 'disk.raw'
    record['image_regular'] = stat.S_ISREG(image.stat().st_mode)
    record['image_size_after'] = image.stat().st_size
    with image.open('rb') as source:
        payload = source.read(WRITE_BYTES)
    record['data_sha256'] = hashlib.sha256(payload).hexdigest()
    record['data_matches'] = payload == b'\x5a' * WRITE_BYTES
    (args.directory / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('node', 'injected_errno', 'qemu_exit', 'errors', 'forced_cleanup')}), flush=True)
    raise SystemExit(bool(record['errors']))


if __name__ == '__main__':
    main()
