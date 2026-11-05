#!/usr/bin/env bash
# 在独立 Linux 构建环境中交叉编译实验宿主内核；不安装、不重启任何节点。
set -euo pipefail

source_dir=${1:?usage: build-host-kernel.sh SOURCE_DIR OUTPUT_DIR}
output_dir=${2:?usage: build-host-kernel.sh SOURCE_DIR OUTPUT_DIR}
mkdir -p "$output_dir"
source_dir=$(realpath "$source_dir")
output_dir=$(realpath "$output_dir")
export ARCH=x86_64
export CROSS_COMPILE=${CROSS_COMPILE-x86_64-linux-gnu-}
jobs=${JOBS:-4}

make -C "$source_dir" O="$output_dir" x86_64_defconfig
config="$source_dir/scripts/config"
"$config" --file "$output_dir/.config" \
    --set-str LOCALVERSION -sshpool-gvm-pf1 \
    --disable LOCALVERSION_AUTO \
    --enable KVM --enable KVM_INTEL \
    --enable KVM_DSM_IRQ_FORWARD --enable KVM_DSM \
    --enable HYPERVISOR_GUEST --enable PARAVIRT --enable VMWARE_VMCI \
    --enable VMWARE_PVSCSI --enable VMXNET3 \
    --enable SCSI --enable BLK_DEV_SD --enable EXT4_FS \
    --enable EFI --enable EFI_STUB --enable EFI_PARTITION \
    --enable DEVTMPFS --enable DEVTMPFS_MOUNT \
    --enable BLK_DEV_INITRD --enable RD_GZIP --enable RD_ZSTD \
    --enable IKCONFIG --enable IKCONFIG_PROC \
    --enable NF_TABLES --enable NF_TABLES_INET \
    --disable DEBUG_INFO --disable DEBUG_INFO_BTF \
    --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
    --disable DRM --disable SOUND --disable WLAN --disable WIRELESS \
    --disable MODULE_SIG --set-str SYSTEM_TRUSTED_KEYS ""
make -C "$source_dir" O="$output_dir" olddefconfig
for option in KVM KVM_INTEL KVM_DSM_IRQ_FORWARD KVM_DSM VMWARE_PVSCSI VMXNET3 EXT4_FS; do
    grep -qx "CONFIG_${option}=y" "$output_dir/.config"
done
make -C "$source_dir" O="$output_dir" -j"$jobs" bzImage modules
make -s -C "$source_dir" O="$output_dir" kernelrelease
