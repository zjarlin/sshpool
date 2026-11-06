#!/usr/bin/env bash
# 运行一个隔离的双节点、无磁盘客体；必须先部署配对内核与运行时。
set -euo pipefail
node=${1:?usage: run-node.sh NODE_INDEX NODE0_IPV4 NODE1_IPV4}
peer0=${2:?missing node 0 address}
peer1=${3:?missing node 1 address}
case "$node" in
    0|1) ;;
    *) echo 'NODE_INDEX must be 0 or 1' >&2; exit 2 ;;
esac
# 监听之外的关闭中连接也可能阻止研究内核重新绑定，不能只检查 LISTEN。
occupied=$(ss -H -tan '( sport = :37710 or sport = :37711 or sport = :40000 or sport = :40001 )')
if [[ -n "$occupied" ]]; then
    echo '实验端口仍有 TCP 状态；等待连接回收后重新检查，不要强行复用。' >&2
    printf '%s\n' "$occupied" >&2
    exit 1
fi
python3 - "$peer0" "$peer1" <<'PY'
import fcntl
import ipaddress
import os
import sys

addresses = [ipaddress.IPv4Address(value) for value in sys.argv[1:]]
if addresses[0] == addresses[1]:
    raise SystemExit('需要两个不同的节点地址')
with os.fdopen(os.open('/dev/kvm', os.O_RDWR), 'rb') as device:
    if fcntl.ioctl(device.fileno(), 0xAE03, 249) != 1:
        raise SystemExit('内核没有启用 KVM_CAP_X86_DSM=249')
    vm = fcntl.ioctl(device.fileno(), 0xAE01, 0)
    os.close(vm)
PY
if [[ $(cat /sys/module/kvm_intel/parameters/enable_apicv) != N ]]; then
    echo 'GiantVM requires kvm_intel.enable_apicv=0' >&2
    exit 1
fi
runtime=${RUNTIME_DIR:-$HOME/ssi}
qemu=${QEMU:-$runtime/qemu-system-x86_64}
bios=${BIOS:-$runtime/pc-bios}
initramfs=${INITRAMFS:-$runtime/guest-initramfs.cpio.gz}
kernel=${GUEST_KERNEL:-$runtime/guest-vmlinuz}
duration=${RUN_SECONDS:-900}
ssh_port=${SSH_PORT:-0}
if [[ ! "$duration" =~ ^[1-9][0-9]{0,3}$ ]] || (( duration > 3600 )); then
    echo 'RUN_SECONDS must be between 1 and 3600' >&2
    exit 2
fi
network=()
if [[ "$ssh_port" != 0 ]]; then
    if [[ ! "$ssh_port" =~ ^[1-9][0-9]{3,4}$ ]] || (( ssh_port < 1024 || ssh_port > 65535 )); then
        echo 'SSH_PORT must be 0 or between 1024 and 65535' >&2
        exit 2
    fi
    # 只在主节点回环暴露入口；用户网络隔离客体与宿主 LAN。
    backend='user,id=sshpool,restrict=on'
    if [[ "$node" == 0 ]]; then
        backend+=",hostfwd=tcp:127.0.0.1:$ssh_port-:22"
    fi
    network=(-netdev "$backend" -device virtio-net-pci,disable-modern=on,vectors=0,netdev=sshpool,mac=52:54:00:53:53:01)
fi
# 控制串口调试日志的最大体积；超时只终止本次实验进程。
ulimit -f 131072
exec timeout --kill-after=5 "$duration" "$qemu" \
    -name "sshpool-ssi-node$node",debug-threads=on \
    -machine pc,accel=kvm,kernel-irqchip=split \
    -cpu qemu64,-x2apic \
    -smp 4 -m 256 \
    -nodefaults -display none -serial stdio -monitor none -no-reboot \
    -L "$bios" -kernel "$kernel" \
    -initrd "$initramfs" \
    "${network[@]}" \
    -append 'console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic' \
    -local-cpu "cpus=2,start=$((node * 2)),iplist=$peer0 $peer1"
