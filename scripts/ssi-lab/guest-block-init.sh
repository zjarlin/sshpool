#!/bin/sh
# 只写探针新建的指定序列号实验盘，不挂载已有文件系统或启用网络。
set -eu
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
test "$(cat /sys/block/vda/serial)" = sshpool-pending-lab
test "$(cat /sys/block/vda/size)" = 131072
test "$(wc -c < /payload)" = 4096
echo SSI_BLOCK_READY
read -r action < /dev/console
test "$action" = write
echo SSI_BLOCK_WRITE_BEGIN
if dd if=/payload of=/dev/vda bs=4096 count=1 seek=256 oflag=direct conv=fsync; then
    echo SSI_BLOCK_WRITE_OK
else
    echo SSI_BLOCK_WRITE_FAILED
fi
# 保持客体存活，生命周期动作由宿主 QMP 统一发起和记录。
while :; do sleep 60; done
