"""在真实 Linux memfd 上验证替换竞态和封条；不模拟内核执行语义。"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

worker = None
if sys.platform == 'linux':
    source = Path(__file__).resolve().parents[2] / 'src/ssi_launch_worker.py'
    spec = importlib.util.spec_from_file_location('launch_worker', source)
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)


@unittest.skipUnless(sys.platform == 'linux', 'requires real Linux memfd seals')
class LaunchWorkerTest(unittest.TestCase):
    def test_parent_killed_releases_child_and_inherited_lock(self):
        script = '''
import fcntl, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
import ssi_launch_worker as worker
lock = os.open(sys.argv[2], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
parent = os.getpid()
child = subprocess.Popen(['/bin/sleep', '60'], pass_fds=(lock,),
                         start_new_session=True, preexec_fn=lambda: worker.parent_death(parent))
print(child.pid, flush=True)
os.read(0, 1)
'''
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'runtime.lock'
            helper = subprocess.Popen([sys.executable, '-c', script, str(source.parent), str(lock_path)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            child = None
            try:
                child = int(helper.stdout.readline())
                with lock_path.open('rb') as lock:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    helper.kill()
                    helper.wait(timeout=5)
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                self.fail('orphan still holds runtime lock')
                            time.sleep(0.02)
                    status = Path(f'/proc/{child}/status')
                    while status.exists():
                        try:
                            if 'State:\tZ' in status.read_text():
                                break
                        except FileNotFoundError:
                            break
                        if time.monotonic() >= deadline:
                            self.fail('orphan did not finish after releasing its lock')
                        time.sleep(0.02)
            finally:
                if helper.poll() is None:
                    helper.kill()
                helper.wait(timeout=5)
                helper.stdin.close()
                helper.stdout.close()
                if child is not None and Path(f'/proc/{child}').exists():
                    os.kill(child, 9)

    def test_parent_change_during_installation_prevents_exec(self):
        result = subprocess.run(['/bin/true'], preexec_fn=lambda: worker.parent_death(-1), timeout=5)
        self.assertEqual(result.returncode, 125)

    def test_replacing_source_cannot_replace_executed_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'runtime'
            source.write_bytes(Path('/bin/true').read_bytes())
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            descriptor, report = worker.freeze({'path': str(source), 'sha256': digest}, 'qemu')
            try:
                replacement = Path(directory) / 'replacement'
                replacement.write_bytes(Path('/bin/false').read_bytes())
                replacement.replace(source)
                result = subprocess.run([f'/proc/self/fd/{descriptor}'], pass_fds=(descriptor,), timeout=10)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(report['sha256'], digest)
                self.assertEqual(report['seals'], 15)
                with self.assertRaises(PermissionError):
                    os.write(descriptor, b'changed')
                with self.assertRaises(PermissionError):
                    os.ftruncate(descriptor, 0)
            finally:
                os.close(descriptor)

    def test_wrong_hash_or_symlink_cannot_leave_a_prepared_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input'
            source.write_bytes(b'input')
            before = set(os.listdir('/proc/self/fd'))
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                worker.freeze({'path': str(source), 'sha256': '0' * 64}, 'qemu')
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            link = Path(directory) / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                worker.freeze({'path': str(link), 'sha256': hashlib.sha256(b'input').hexdigest()}, 'qemu')

    def test_commit_cannot_replay_or_change_local_preparation(self):
        image = {'sha256': 'a' * 64, 'bytes': 4, 'seals': 15}
        first = {'node': 0, 'run_id': 'current', 'plan_sha256': 'plan', 'kernel': 'kernel',
                 'machine_id_sha256': 'first', 'images': {name: image for name in ('qemu', 'guest_kernel', 'initramfs')}}
        second = copy.deepcopy(first)
        second.update(node=1, machine_id_sha256='second')
        worker.approve(first, [first, second])
        for fault in ('version', 'run', 'local', 'duplicate'):
            peers = copy.deepcopy([first, second])
            if fault == 'version':
                peers[1]['images']['qemu']['sha256'] = 'b' * 64
            elif fault == 'run':
                peers[1]['run_id'] = 'previous'
            elif fault == 'local':
                peers[0]['kernel'] = 'different'
            else:
                peers[1]['node'] = 0
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                worker.approve(first, peers)


if __name__ == '__main__':
    unittest.main()
