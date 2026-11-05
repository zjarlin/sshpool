#!/bin/sh
set -eu
# 只创建独立 Lima 虚拟机，不共享宿主目录，不调整已有虚拟机。
command -v limactl >/dev/null 2>&1 || { echo 'Install Lima first: brew install lima' >&2; exit 1; }
if limactl list sshpool --format '{{.Name}}' 2>/dev/null | grep -qx sshpool; then
    limactl start -y sshpool
else
    limactl start -y --name=sshpool --vm-type=vz --cpus=4 --memory=6 --disk=40 --mount-none --containerd=none --ssh-port=2223 template:ubuntu
fi
printf '%s\n' 'Linux workspace ready. Follow docs/deployment.md to install the client and pin SSH host keys.'
