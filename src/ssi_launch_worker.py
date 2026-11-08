"""SSI 实验启动器的远端半边：封存输入、等待双方准入、监督本次 QEMU。"""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
LIMIT = 256 * 1024 * 1024
LIBC = ctypes.CDLL(None, use_errno=True)


def parent_death(parent):
    """单线程 helper 的 fork 子进程在 exec 前绑定父进程死亡信号，并关闭设置窗口竞态。"""
    if LIBC.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(125)
    if os.getppid() != parent:
        os._exit(125)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def freeze(source, label):
    """摘要来自实际复制的字节；封存后只能从同一个 fd 执行或读取。"""
    path = source['path']
    require(Path(path).is_absolute(), 'input path must be absolute')
    # FIFO 必须先以非阻塞方式打开，才能在 fstat 处拒绝，避免永久占用运行锁。
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= LIMIT, 'input must be a bounded regular file')
        descriptor = os.memfd_create('sshpool-ssi-' + label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                require(size <= LIMIT, 'input grew beyond limit')
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    require(written > 0, 'short memfd write')
                    view = view[written:]
            after = os.fstat(stream.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed while copying')
            require(size == before.st_size and digest.hexdigest() == source['sha256'], 'input hash mismatch: ' + label)
            os.fchmod(descriptor, 0o500 if label == 'qemu' else 0o400)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
            require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == SEALS, 'memfd seals missing')
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor, {'sha256': digest.hexdigest(), 'bytes': size, 'seals': SEALS}
        except BaseException:
            os.close(descriptor)
            raise


class Channel:
    """有界 JSONL 输入；收到半行后也继续使用单调时钟截止时间。"""
    def __init__(self):
        self.buffer = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(sys.stdin, selectors.EVENT_READ)

    def read(self, seconds):
        deadline = time.monotonic() + seconds
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError('control message deadline expired')
            chunk = os.read(sys.stdin.fileno(), 4096)
            if not chunk:
                raise EOFError('controller disconnected')
            self.buffer.extend(chunk)
            require(len(self.buffer) <= 65536, 'control message too large')
        line, _, rest = self.buffer.partition(b'\n')
        self.buffer = bytearray(rest)
        value = json.loads(line)
        require(isinstance(value, dict), 'control message must be an object')
        return value


def private_directory(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            'runtime directory must be private and owned by current user')


def approve(prepared, peers):
    """两端独立复核同一个准入决定，拒绝重复、过期或替换自身报告。"""
    require(isinstance(peers, list) and len(peers) == 2 and [p['node'] for p in peers] == [0, 1],
            'commit requires two distinct ordered peers')
    require(peers[prepared['node']] == prepared, 'commit changed local prepared report')
    require(all(p['run_id'] == prepared['run_id'] and p['plan_sha256'] == prepared['plan_sha256'] and
                p['kernel'] == prepared['kernel'] for p in peers), 'commit belongs to another run or kernel')
    require(peers[0]['machine_id_sha256'] != peers[1]['machine_id_sha256'], 'duplicate machine identity')
    for name in ('qemu', 'guest_kernel', 'initramfs'):
        require(peers[0]['images'][name] == peers[1]['images'][name], 'incompatible sealed image: ' + name)


def main():
    channel = Channel()
    request = channel.read(30)
    run_id, node = request['run_id'], request['node']
    require(re.fullmatch(r'[0-9a-f]{32}', run_id) and type(node) is int and node in (0, 1), 'invalid run identity')
    require(request['schema'] == 1, 'unknown startup protocol')
    settings = request['settings']
    peer = settings['peers'][node]
    require(settings['require_kernel'] == '7.1.0-rc3-sshpool-gvm-pf24' and
            platform.release() == settings['require_kernel'] and platform.machine() == 'x86_64',
            'dedicated x86_64 PF24 kernel required')
    identity = hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest()
    require(identity == peer['machine_id_sha256'], 'machine identity mismatch')
    root = Path.home() / '.sshpool-ssi'
    private_directory(root)
    directory = root / run_id
    directory.mkdir(mode=0o700)
    lock = os.open(root / 'runtime.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    require(stat.S_ISREG(os.fstat(lock).st_mode) and os.fstat(lock).st_uid == os.getuid(), 'invalid runtime lock')
    descriptors = []
    process = None
    prepared = None
    report = {'schema': 1, 'run_id': run_id, 'node': node, 'directory': str(directory),
              'qemu_started': False, 'qemu_exit': None, 'forced_cleanup': [], 'errors': [],
              'events': [], 'started_ns': time.monotonic_ns()}

    def emit(event, data):
        value = {'schema': 1, 'run_id': run_id, 'node': node, 'event': event, 'data': data}
        report['events'].append({'event': event, 'time_ns': time.monotonic_ns(), 'data': data})
        (directory / 'events.json').write_text(json.dumps(report['events'], indent=2) + '\n')
        try:
            print(json.dumps(value), flush=True)
        except BrokenPipeError:
            # 控制通道关闭不影响本次子进程的回收和磁盘上的最终记录。
            pass

    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        names = subprocess.check_output(['ps', '-eo', 'comm='], text=True).splitlines()
        require(not any(name.strip().startswith(('qemu-system-', 'kvm-dsm/', 'dsm-conn/')) for name in names),
                'another SSI experiment is active')
        ports = ' or '.join(f'{side} = :{port}' for side in ('sport', 'dport')
                            for port in (37710, 37711, 40000, 40001))
        require(not subprocess.check_output(['ss', '-H', '-tan', f'( {ports} )']).strip(), 'SSI ports still occupied')
        require(Path('/sys/module/kvm_intel/parameters/enable_apicv').read_text().strip() == 'N', 'APICv must be disabled')
        require(Path(peer['firmware']).is_absolute() and Path(peer['firmware']).is_dir(), 'firmware directory missing')
        images = {}
        for name in ('qemu', 'guest_kernel', 'initramfs'):
            descriptor, images[name] = freeze(peer[name], name)
            descriptors.append(descriptor)
        prepared = {'node': node, 'run_id': run_id, 'plan_sha256': request['plan_sha256'],
                    'machine_id_sha256': identity, 'kernel': platform.release(), 'images': images,
                    'token': secrets.token_hex(32), 'directory': str(directory)}
        emit('prepared', prepared)
        decision = channel.read(30)
        require(decision['run_id'] == run_id and decision['node'] == node, 'stale decision')
        if decision['op'] == 'abort':
            report['errors'].append('controller rejected preparation: ' + decision['reason'])
        else:
            require(decision['op'] == 'commit', 'expected commit or abort')
            approve(prepared, decision['peers'])
            paths = [f'/proc/self/fd/{fd}' for fd in descriptors]
            command = [paths[0], '-name', f'sshpool-ssi-{run_id}-{node},debug-threads=on',
                       '-machine', 'pc,accel=kvm,kernel-irqchip=split', '-cpu', 'qemu64,-x2apic,+tsc-adjust,enforce',
                       '-smp', '4,sockets=2,cores=2,threads=1', '-m', '256', '-nodefaults',
                       '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                       '-L', peer['firmware'], '-kernel', paths[1], '-initrd', paths[2],
                       '-append', 'console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic',
                       '-local-cpu', f"cpus=2,start={node * 2},iplist={' '.join(settings['addresses'])}"]
            port = settings['ssh_port']
            if port is not None:
                backend = 'user,id=sshpool,restrict=on'
                if node == 0:
                    backend += f',hostfwd=tcp:127.0.0.1:{port}-:22'
                command += ['-netdev', backend, '-device',
                            'virtio-net-pci,disable-modern=on,vectors=0,netdev=sshpool,mac=52:54:00:53:53:01']
            with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
                parent = os.getpid()
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                           pass_fds=(*descriptors, lock), start_new_session=True,
                                           preexec_fn=lambda: parent_death(parent),
                                           env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C', 'LC_ALL': 'C'})
            report['qemu_started'] = True
            report['qemu_pid'] = process.pid
            # 子进程执行的是已封存的 ELF；原路径被替换也不能改变本次实例。
            actual = os.stat(f'/proc/{process.pid}/exe')
            pinned = os.fstat(descriptors[0])
            require((actual.st_dev, actual.st_ino) == (pinned.st_dev, pinned.st_ino), 'executed inode differs from sealed QEMU')
            emit('started', {'pid': process.pid, 'sealed_executable': True, 'images': images})
            deadline = time.monotonic() + settings['run_seconds']
            lease = time.monotonic() + 10
            while process.poll() is None:
                require(all((directory / (name + '.log')).stat().st_size <= 16 * 1024 * 1024
                            for name in ('stdout', 'stderr')), 'guest log exceeded 16 MiB')
                require(time.monotonic() < deadline, 'guest run deadline expired')
                require(time.monotonic() < lease, 'controller lease expired')
                try:
                    message = channel.read(0.2)
                except TimeoutError:
                    continue
                require(message['run_id'] == run_id and message['node'] == node and
                        message['token'] == prepared['token'], 'stale runtime control message')
                require(message['op'] == 'keepalive', 'controller stopped this run: ' + message.get('reason', 'stop'))
                lease = time.monotonic() + 10
    except Exception as error:
        report['errors'].append(str(error))
    finally:
        if process is not None and process.poll() is None:
            for action in (signal.SIGTERM, signal.SIGKILL):
                report['forced_cleanup'].append(action.name)
                try:
                    os.killpg(process.pid, action)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    continue
            # 不释放锁并谎报清理成功；不可中断的内核任务必须由实验恢复通道处理。
            if process.poll() is None:
                emit('cleanup_pending', {'pid': process.pid})
                process.wait()
        if process is not None:
            report['qemu_exit'] = process.returncode
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(lock)
        report['finished_ns'] = time.monotonic_ns()
        for name in ('stdout', 'stderr'):
            path = directory / (name + '.log')
            if path.exists():
                report[name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        emit('finished', {key: value for key, value in report.items() if key != 'events'})
    return int(bool(report['errors'] or report['forced_cleanup'] or report['qemu_exit'] != 0))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, EOFError, TimeoutError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
