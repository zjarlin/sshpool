# GiantVM 双节点实验工具

这些工具只用于独立实验 VM，不是 SSHPool 的生产 SSI 后端。先阅读 [实验记录](../../docs/ssi-lab.md)，再阅读 [严格 SSI 验收](../../docs/ssi-feasibility.md)。两台节点位于同一台 ESXi 的测试不能证明物理故障容错或不同物理机的性能相加。

入口顺序：`build-host-kernel.sh` 构建宿主内核，`guest-proof.c` 构建无磁盘测试客体的 PID 1，`run-node.sh` 在两个节点各运行一个 QEMU，最终共同承载一个 Linux 客体。脚本不访问 SSH 密钥、不创建 ESXi VM、不接触公司数据，也不自动安装或重启宿主。

## 固定源码

| 组件 | 提交 |
| --- | --- |
| GVM-kernel `upstream/7.1-rc3` | `6317a6badf4f5a42e8ff7f6881b3a9199e6c0b54` |
| GVM-qemu `main` | `da3f3b05d23ba714a3e961f80c059c376007d7d7` |

TCP 版本不能与共享内存分支混配。使用上游源码地址，不使用未经核验的预编译二进制。两个节点必须具有相同 QEMU、客体内核和 initramfs 哈希。

```sh
git init GVM-kernel
git -C GVM-kernel remote add origin https://github.com/GiantVM/GVM-kernel.git
git -C GVM-kernel fetch --depth 1 origin 6317a6badf4f5a42e8ff7f6881b3a9199e6c0b54
git -C GVM-kernel checkout --detach FETCH_HEAD
git init GVM-qemu
git -C GVM-qemu remote add origin https://github.com/GiantVM/GVM-qemu.git
git -C GVM-qemu fetch --depth 1 origin da3f3b05d23ba714a3e961f80c059c376007d7d7
git -C GVM-qemu checkout --detach FETCH_HEAD
git -C GVM-kernel rev-parse HEAD
git -C GVM-qemu rev-parse HEAD
```

## 两个本地修正

`qemu-single-node-routing.patch` 修复单节点启动时，因路由 mutex 已初始化却没有第二节点连接，访问 `req_files[1]` 导致的段错误；只由分布式主节点广播路由。当前上游函数仍硬编码第二节点，本实验仅覆盖两个节点。

`kernel-page-reference.patch` 将直接缺页处理的成功与重试路径统一到一次页引用释放。原成功路径遗漏清理，重试路径先经 `kvm_mmu_finish_page_fault()` 释放一次，再调用 `kvm_release_page_unused()` 重复释放。实验发现 GUP 页引用异常和宿主进程崩溃；修正的验证范围见实验记录，不能据此声称整个内核已安全。

```sh
patch -d GVM-qemu -p1 < scripts/ssi-lab/qemu-single-node-routing.patch
patch -d GVM-kernel -p1 < scripts/ssi-lab/kernel-page-reference.patch
```

`.patch` 是上游 GPL 源码的修改：内核补丁为 GPL-2.0-only，QEMU 补丁为 GPL-2.0-or-later，许可证正文在 [COPYING.GPL-2.0](COPYING.GPL-2.0)。其余本目录原创脚本与测试程序遵循仓库 MIT。SSHPool 的 MIT 不改变 Linux/QEMU 的许可证。

## 构建

Ubuntu 上准备编译器、`make bc flex bison libssl-dev libelf-dev cpio python3-venv ninja-build pkg-config libglib2.0-dev libpixman-1-dev libslirp-dev`。ARM Linux 交叉构建还需 `gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu libc6-dev-amd64-cross`。

```sh
# 在 ARM Linux 构建环境中生成 x86_64 宿主内核。
JOBS=4 bash scripts/ssi-lab/build-host-kernel.sh GVM-kernel kernel-out
# x86_64 原生构建时设置 CROSS_COMPILE=，不要在繁忙业务宿主构建。

cd GVM-qemu
./configure --target-list=x86_64-softmmu --enable-kvm \
  --without-default-features --enable-pixman --enable-vnc --enable-slirp \
  --disable-rdma --disable-werror --disable-docs --disable-guest-agent --disable-tools
ninja -C build -j1 qemu-system-x86_64
```

QEMU 在 Ubuntu 24.04 x86_64 节点原生编译，避免交叉链接到更高版本 glibc。分发时带上同一源码树的 `pc-bios/`，并检查 `ldd` 没有缺失依赖。

宿主安装必须使用独立暂存目录，再将具名的新内核、配置、System.map 和对应模块目录复制到目标位置；**不要把含 `lib/` 的 tar 包直接解压到 `/`**，这会替换 Ubuntu 的 `/lib -> usr/lib` 链接。保留原内核，配置原内核为默认，用 `grub-reboot` 一次性选择研究内核。只允许在已核对归属的实验 VM 上执行安装与重启。

`CONFIG_KVM_DSM_IRQ_FORWARD=y`、`CONFIG_KVM_DSM=y`、可用 `/dev/kvm`、`KVM_CAP_X86_DSM=249` 返回 1，均须实际检查。`kvm_intel.enable_apicv=0` 必须生效；内建 KVM 通过内核命令行设置。实验内核缩减了设备支持，不等同于 Ubuntu 全功能发行版内核。

## 无磁盘客体

使用未修改的 Ubuntu `6.8.0-147-generic` 客体内核，测试程序静态链接为 `/init`；它要求 4 个在线 CPU，逐线程设置 CPU 亲和性，在同一 PID 中进行算术、32 MiB 共享内存和原子计数校验。只上线 2 个 CPU 必须失败。这里不包含 Docker、数据库、网络和可写磁盘。

```sh
x86_64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static -pthread \
  scripts/ssi-lab/guest-proof.c -o guest-proof
mkdir -p guest-root/dev guest-root/proc
cp guest-proof guest-root/init
(cd guest-root && find . -print0 | cpio --null -o --format=newc | gzip -1) \
  > guest-initramfs.cpio.gz
```

每个实验节点的 `~/ssi/` 放置 `qemu-system-x86_64`、`pc-bios/`、`guest-vmlinuz`、`guest-initramfs.cpio.gz` 和 `run-node.sh`。通过防火墙仅允许另一个实验节点访问 TCP `37710–37711` 和 `40000–40001`；这些上游实验协议没有本项目实现的认证与加密。例中地址是文档保留地址，实际地址只放私有配置：

```sh
# 节点 0
bash ~/ssi/run-node.sh 0 192.0.2.10 192.0.2.11 > run-node0.log 2>&1
# 节点 1，同时启动
bash ~/ssi/run-node.sh 1 192.0.2.10 192.0.2.11 > run-node1.log 2>&1
```

每边分配本地 2 个 vCPU，客体总共 4 个、256 MiB。运行时不使用 `-shm-path`，不挂磁盘，最多运行 900 秒。固定传统 APIC，是因为本次配对内核缺少 x2APIC ICR 的转发路径，默认 x2APIC 导致远端 CPU 启动超时。

验收需同时有客体 `PROOF_PASS cpus=4 shared_counter=512 memory_verified_bytes=33554432`、两个节点本地 vCPU 的执行记录、输入文件哈希及宿主内核日志。即使程序通过，也仅证明这个小规模测试；不证明内存容量超过任一节点、性能相加、物理故障恢复或数据库事务安全。

用 `python3 scripts/ssi-lab/check-proof.py run-node0.log` 检查客体结果。PID 1 在失败后也会关机，因此 QEMU 退出状态为 0 不能替代此检查。节点侧用 `ps -eLo pid,tid,comm,time` 核对 `CPU 0/KVM` 到 `CPU 3/KVM` 的执行归属；脚本启用了线程名称。
