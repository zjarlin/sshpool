#!/usr/bin/env python3
"""在独立 Linux 构建目录制作带 OpenSSH 的无磁盘实验客体，不安装或启动服务。"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess

ISO_SHA256 = '93ccf2243ee4fc19c78063774f92ff3d328390bae76bda5bfeaf42db46ce5059'
PACKAGES = [
    'busybox-1.37.0-r20.apk',
    'busybox-binsh-1.37.0-r20.apk',
    'musl-1.2.5-r13.apk',
    'libcrypto3-3.5.9-r0.apk',
    'zlib-1.3.2-r1.apk',
    'openssh-server-10.0_p1-r11.apk',
    'openssh-server-common-10.0_p1-r11.apk',
    'openssh-sftp-server-10.0_p1-r11.apk',
]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def extract_member(archive, member, target):
    with target.open('wb') as output:
        subprocess.run(['bsdtar', '-xOf', str(archive), member], stdout=output, check=True)


def write_file(root, relative, content, mode=0o644):
    target = root / relative
    target.write_text(content)
    target.chmod(mode)


def build(args):
    for tool in ('bsdtar', 'unsquashfs', 'ssh-keygen', 'cpio', 'gzip', 'readelf'):
        if shutil.which(tool) is None:
            raise SystemExit(f'缺少构建工具：{tool}')
    if sha256(args.iso) != ISO_SHA256:
        raise SystemExit('需要 SHA-256 匹配的 Alpine virt 3.22.8 x86_64 官方 ISO')
    public_key = args.authorized_key.read_text().strip()
    if len(public_key.splitlines()) != 1 or not public_key.startswith(('ssh-ed25519 ', 'ssh-rsa ', 'ecdsa-sha2-')):
        raise SystemExit('只能显式导入一个 SSH 公钥，不能传入私钥或 authorized_keys 选项')
    subprocess.run(['ssh-keygen', '-l', '-f', str(args.authorized_key)], check=True)
    program = args.proof.read_bytes()
    if program[:5] != b'\x7fELF\x02' or program[18:20] != b'\x3e\x00':
        raise SystemExit('测试程序必须是静态链接的 x86_64 ELF；请使用文档中的构建命令')
    headers = subprocess.check_output(['readelf', '--program-headers', str(args.proof)], text=True)
    if 'INTERP' in headers:
        raise SystemExit('测试程序仍依赖动态加载器，请用 -static 重新构建')

    # 新目录是唯一写入范围；镜像含实验 SSH 主机私钥，不得上传公开仓库。
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    root = output / 'root'
    root.mkdir()
    packages = output / 'packages'
    packages.mkdir()
    for name in PACKAGES:
        package = packages / name
        extract_member(args.iso, 'apks/x86_64/' + name, package)
        subprocess.run(['bsdtar', '-xf', str(package), '-C', str(root), '--no-same-owner', '--exclude', '.*'], check=True)
    extract_member(args.iso, 'boot/vmlinuz-virt', output / 'guest-vmlinuz')
    extract_member(args.iso, 'boot/modloop-virt', output / 'modloop')
    listing = subprocess.check_output(['unsquashfs', '-ll', str(output / 'modloop')], text=True)
    # 此固定发行版内建 virtio PCI 总线，网络模块按依赖顺序单独导入。
    module_names = ('failover.ko', 'net_failover.ko', 'virtio_net.ko')
    members = []
    for name in module_names:
        paths = [line.split()[-1] for line in listing.splitlines() if line.endswith('/' + name)]
        if len(paths) != 1:
            raise SystemExit(f'需要唯一的网络模块：{name}')
        members.append(paths[0].removeprefix('squashfs-root/'))
    modules = output / 'modules'
    subprocess.run(['unsquashfs', '-no-progress', '-processors', '1', '-d', str(modules), str(output / 'modloop'), *members], check=True)

    for directory in ('proc', 'sys', 'dev', 'run', 'tmp', 'root/.ssh', 'etc/ssh', 'lib/modules', 'var/empty'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / 'root').chmod(0o700)
    (root / 'root/.ssh').chmod(0o700)
    (root / 'var/empty').chmod(0o755)
    (root / 'tmp').chmod(0o1777)
    for member in members:
        shutil.copyfile(modules / member, root / 'lib/modules' / Path(member).name)
    shutil.copyfile(args.proof, root / 'bin/ssi-proof')
    (root / 'bin/ssi-proof').chmod(0o755)
    shutil.copyfile(Path(__file__).with_name('guest-ssh-init.sh'), root / 'init')
    (root / 'init').chmod(0o755)
    write_file(root, 'etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nsshd:x:22:22:sshd:/var/empty:/bin/false\n')
    write_file(root, 'etc/group', 'root:x:0:\nsshd:x:22:\n')
    write_file(root, 'etc/shadow', 'root:*:0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n', 0o600)
    write_file(root, 'root/.ssh/authorized_keys', public_key + '\n', 0o600)
    write_file(root, 'etc/ssh/sshd_config', '''Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers root
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp /usr/lib/ssh/sftp-server
''')
    key = root / 'etc/ssh/ssh_host_ed25519_key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    shutil.copyfile(key.with_suffix('.pub'), output / 'guest-host-key.pub')

    # cpio 头统一声明为客体 root，构建过程本身不需要 root，也不挂载宿主目录。
    files = b'.\0' + b''.join(str(path.relative_to(root)).encode() + b'\0' for path in sorted(root.rglob('*')))
    archive = output / 'guest.cpio'
    with archive.open('wb') as packed:
        subprocess.run(['cpio', '--null', '-o', '--format=newc', '--owner=0:0'], input=files, cwd=root, stdout=packed, check=True)
    image = output / 'guest-ssh-initramfs.cpio.gz'
    with image.open('wb') as compressed:
        subprocess.run(['gzip', '-1', '-c', str(archive)], stdout=compressed, check=True)
    image.chmod(0o600)
    for path in (output / 'guest-vmlinuz', image):
        print(f'{sha256(path)}  {path.name}')
    subprocess.run(['ssh-keygen', '-l', '-f', str(output / 'guest-host-key.pub')], check=True)
    print(f'构建完成：{output}；仅用于隔离实验，未启动客体。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--authorized-key', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.iso = args.iso.resolve()
    build(args)


if __name__ == '__main__':
    main()
