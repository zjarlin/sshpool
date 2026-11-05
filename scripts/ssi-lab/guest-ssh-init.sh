#!/bin/sh
# 无磁盘实验客体：只接收显式导入的公钥，运行时文件全部留在客体内存。
set -eu
/bin/busybox --install -s /bin
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs tmpfs /run
hostname sshpool-ssi-guest
insmod /lib/modules/failover.ko
insmod /lib/modules/net_failover.ko
insmod /lib/modules/virtio_net.ko
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
echo "SSH_GUEST_READY kernel=$(uname -r) cpus=$(nproc)"
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
