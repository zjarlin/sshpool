#!/usr/bin/env python3
"""在当前 macOS 登录会话安装 SSHPool；配置和节点凭据保留在用户私有目录。"""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True, type=Path)
parser.add_argument('--state', type=Path, default=Path.home() / '.sshpool')
args = parser.parse_args()
state = args.state.resolve()
if not (state / 'config.toml').exists():
    raise SystemExit('Run sshpool init first')
source = args.binary.resolve()
binary = state / 'sshpool'
staged = state / 'sshpool.next'
shutil.copy2(source, staged)
staged.chmod(0o755)
staged.replace(binary)
limactl = shutil.which('limactl')
if limactl is None:
    raise SystemExit('limactl not found')
launcher = state / 'serve.sh'
import shlex
launcher.write_text('#!/bin/sh\nset -eu\nexport PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\n' + shlex.quote(limactl) + ' start -y sshpool\nexec ' + shlex.quote(str(binary)) + ' --home ' + shlex.quote(str(state)) + ' serve\n')
launcher.chmod(0o700)
label = 'io.github.zjarlin.sshpool'
folder = Path.home() / 'Library/LaunchAgents'
folder.mkdir(parents=True, exist_ok=True)
plist = folder / (label + '.plist')
if plist.exists():
    # 只卸载本脚本管理的专用服务，升级前保留 plist。
    shutil.copy2(plist, state / 'launch-agent.previous.plist')
    subprocess.run(['launchctl', 'bootout', f'gui/{os.getuid()}/{label}'], check=False)
config = dict(Label=label, ProgramArguments=['/bin/sh', str(launcher)], RunAtLoad=True, KeepAlive=True, ThrottleInterval=10,
              WorkingDirectory=str(state), StandardOutPath=str(state / 'service.stdout.log'), StandardErrorPath=str(state / 'service.stderr.log'))
with plist.open('wb') as stream:
    plistlib.dump(config, stream)
subprocess.run(['launchctl', 'bootstrap', f'gui/{os.getuid()}', str(plist)], check=True)
print(f'Installed {label}. SSH: 127.0.0.1:2222; API: 127.0.0.1:8877')
