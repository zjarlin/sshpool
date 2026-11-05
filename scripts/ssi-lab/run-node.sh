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
# 控制串口调试日志的最大体积；超时只终止本次实验进程。
ulimit -f 131072
exec timeout --kill-after=5 900 "$qemu" \
    -name "sshpool-ssi-node$node",debug-threads=on \
    -machine pc,accel=kvm,kernel-irqchip=split \
    -cpu qemu64,-x2apic \
    -smp 4 -m 256 \
    -nodefaults -display none -serial stdio -monitor none -no-reboot \
    -L "$bios" -kernel "$runtime/guest-vmlinuz" \
    -initrd "$runtime/guest-initramfs.cpio.gz" \
    -append 'console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic' \
    -local-cpu "cpus=2,start=$((node * 2)),iplist=$peer0 $peer1"
