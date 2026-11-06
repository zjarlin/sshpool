# GiantVM 双节点实验工具

这些工具只用于独立实验 VM，不是 SSHPool 的生产 SSI 后端。先阅读 [实验记录](../../docs/ssi-lab.md)，再阅读 [严格 SSI 验收](../../docs/ssi-feasibility.md)。两台节点位于同一台 ESXi 的测试不能证明物理故障容错或不同物理机的性能相加。

入口顺序：`build-host-kernel.sh` 构建宿主内核，`guest-proof.c` 构建无磁盘测试客体的 PID 1，`run-node.sh` 在两个节点各运行一个 QEMU，最终共同承载一个 Linux 客体。脚本不访问 SSH 密钥、不创建 ESXi VM、不接触公司数据，也不自动安装或重启宿主。

## 固定源码

| 组件 | 提交 |
| --- | --- |
| GVM-kernel `upstream/7.1-rc3` | `6317a6badf4f5a42e8ff7f6881b3a9199e6c0b54` |
| GVM-qemu `main` | `da3f3b05d23ba714a3e961f80c059c376007d7d7` |

TCP 版本不能与共享内存分支混配。使用上游源码地址，不使用未经核验的预编译二进制。两个节点必须具有相同 QEMU、客体内核和 initramfs 哈希。

`run-node.sh` 需要 `ss`（Linux 的 iproute2），在创建 VM 前检查实验端口的全部 TCP 状态，包括 TIME-WAIT。前次连接尚未回收时拒绝启动；这项检查不能替代内核错误传播或解决并发启动竞态。跨节点设备完成边界的新探针、实验补丁及重启失败记录见 [设备顺序实验](../../docs/ssi-device-order.md)。

`probe-dsm-startup.c` 验证占用端口时 ioctl 的真实错误、同一空 VM 重试与重复启停后的端口释放；`check-startup.py` 核对完整操作顺序。PF8 候选补丁、真实 QEMU 错误传播及剩余销毁风险见 [启动与回收实验](../../docs/ssi-startup.md)。它不提供全局启动事务或正常关闭协议。

`trace-teardown.py` 在独立 trace instance 中记录真实 DSM 线程退出与 KVM 销毁顺序，`check-teardown.py` 同时检查事件顺序、线程身份与丢失计数。PF9 的预销毁停止补丁及对照证据见 [关闭顺序实验](../../docs/ssi-teardown.md)。

`probe-dsm-request.c` 保持空 VM 打开并按命令延迟注册一页内存；`probe-request-cancel.py` 发送完整读页请求，跟踪接收、线程定向信号与退出；`check-request-cancel.py` 检查无需补注册的取消和正常读页对照。PF10 的限定修复见 [请求取消实验](../../docs/ssi-request-cancel.md)，不覆盖页面锁等待与异常报文资源回收。

`probe-request-safety.py` 在 PF11 上发送十五类异常请求，并用受控对端制造同页锁竞争；`check-request-safety.py` 从真实分配/释放、锁、SRCU 和线程事件重算验收。先看 [异常请求与页面锁实验](../../docs/ssi-request-safety.md)，再运行探针；不能把异常超长帧发送给未修复的旧内核。

`probe-dsm-latency.c` / `.py` 在真实 KVM 页面交接的 ioctl 内计时，`trace-dsm-latency.py` 配对页面锁和网络调用，`check-dsm-latency.py` 重算顺序/并发数据与耗时。附加 QEMU 的窗口另记录客体缺页位置，入口和返回落在窗口外的调用单独报告。使用与限制见 [延迟定位](../../docs/ssi-latency.md)；不得将空闲监听等待当作响应延迟。

性能实验先用 `check-esxi-resources.py` 只读检查指定 VM、父资源池与限速计数，避免将管理层 CPU 限速误判为内核缺陷。再用 `trace-dsm-scheduling.py` / `check-dsm-scheduling.py` 分解 DSM 等待，必须拒绝跟踪丢失且保留窗口边界未知时间。具体用法及证据边界见 [调度与资源预检](../../docs/ssi-scheduling.md)。

`trace-vcpu-residency.py` 记录 KVM、宿主中断和调度，`check-vcpu-residency.py` 检查完整性与 KVM 区间；`check-timer-progress.py` 复用同一记录，逐 CPU 分析定时器空档内是否仍有大量 VM 退出及调度切换。频繁退出不代表 DSM 或客体有进度，跟踪点的中断标志也不能外推到整个窗口。用法与实测见 [KVM 停顿实验](../../docs/ssi-vcpu-residency.md)。

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

## 本地修正

`qemu-single-node-routing.patch` 修复单节点启动时，因路由 mutex 已初始化却没有第二节点连接，访问 `req_files[1]` 导致的段错误；只由分布式主节点广播路由。当前上游函数仍硬编码第二节点，本实验仅覆盖两个节点。

`kernel-page-reference.patch` 将直接缺页处理的成功与重试路径统一到一次页引用释放。原成功路径遗漏清理，重试路径先经 `kvm_mmu_finish_page_fault()` 释放一次，再调用 `kvm_release_page_unused()` 重复释放。实验发现 GUP 页引用异常和宿主进程崩溃；修正的验证范围见实验记录，不能据此声称整个内核已安全。

`kernel-dsm-permissions.patch` 保留 KVM 对客体权限的记账：直接映射记录 `ACC_ALL`，实际硬件页表权限再与本次 DSM 授权取交集。它也在 DSM 模式禁止没有逐页获取授权的邻页预取；没有删除或屏蔽原有权限告警。该补丁在页引用修正之后应用，新构建版本为 `7.1.0-rc3-sshpool-gvm-pf2`。

```sh
patch -d GVM-qemu -p1 < scripts/ssi-lab/qemu-single-node-routing.patch
patch -d GVM-kernel -p1 < scripts/ssi-lab/kernel-page-reference.patch
patch -d GVM-kernel -p1 < scripts/ssi-lab/kernel-dsm-permissions.patch
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

## 反复转移页面的测试

`guest-stress.c` 使用与前述程序相同的静态构建和 initramfs 打包方法。将产物另外保存为 `guest-stress-initramfs.cpio.gz`，保留原始对照程序。它要求四 CPU、4 KiB 页面，两次 `mmap/munmap` 分配，每次对 4 MiB 内存进行八轮改写和全量校验。相邻页面由不同 CPU 写入，每轮改变写入方；每个 CPU 都以置换顺序读取全部页面，另有共享原子计数验证。

```sh
INITRAMFS="$HOME/ssi/guest-stress-initramfs.cpio.gz" \
  bash ~/ssi/run-node.sh 0 192.0.2.10 192.0.2.11 > stress-node0.log 2>&1
# 另一个节点使用相同 INITRAMFS，并把 NODE_INDEX 设置为 1。
python3 scripts/ssi-lab/check-stress.py stress-node0.log
python3 -m unittest discover -s scripts/ssi-lab -p 'test_*.py'
```

`GUEST_KERNEL` 可以显式选择另一份已核对哈希的发行版内核；默认仍为 `~/ssi/guest-vmlinuz`。更换内核或 initramfs 后必须先跑普通单节点对照。每次冷启动必须重新创建两边 QEMU，并保存各自退出码、线程时间、文件哈希和宿主内核日志；不要拼接多次运行的输出以凑成成功记录。4 MiB 测试只覆盖页面交接与一致性，不证明超单节点内存容量或长期稳定性。

## 内存中的 OpenSSH 工作区

`build-ssh-guest.py` 在新的 Linux 构建目录提取官方 Alpine virt 3.22.8 x86_64 ISO 中的内核、模块、BusyBox、OpenSSH 和运行库。先核对固定 ISO 哈希，构建不需要 root，不读取宿主业务文件。除了前述工具，还需要 `libarchive-tools squashfs-tools openssh-client binutils`。

```sh
python3 scripts/ssi-lab/build-ssh-guest.py \
  --iso alpine-virt-3.22.8-x86_64.iso \
  --authorized-key /path/to/explicit-client-key.pub \
  --proof /path/to/static-x86_64-guest-stress \
  --output /path/to/new-private-directory
```

输出含实验 SSH 主机私钥，应留在权限为 0700 的私有目录，不能提交到 GitHub。复制相同 `guest-vmlinuz` 和 `guest-ssh-initramfs.cpio.gz` 到两节点，并通过已认证管理通道核对 `guest-host-key.pub`。客户端配置 `HostKeyAlias` 和专用 `UserKnownHostsFile`；不要使用 `StrictHostKeyChecking=no`。同一个客体的主机密钥相同是预期行为。

两边设置相同 `GUEST_KERNEL`、`INITRAMFS`、`SSH_PORT=22230` 和 `RUN_SECONDS=1800` 后调用 `run-node.sh`。只有节点零在 `127.0.0.1:22230` 接收转发，节点一不创建监听；两边 QEMU 的 PCI 设备布局保持一致。客体使用 QEMU 受限用户网络，仅接受显式 SSH 转发，不默认访问局域网。客户端通过节点零 `ProxyJump` 连接回环端口，shell 必须报告客体的内核、主机名与四 CPU。

`guest-ssh-init.sh` 只运行 OpenSSH，关闭密码认证。`/bin/ssi-proof` 是同进程共享内存测试；SFTP 目标可用 `/tmp`。当前工作区关机即丢失，既没有持久磁盘，也没有 Docker 或数据库服务。`RUN_SECONDS` 范围为 1–3600，到时仅停止本次 QEMU 实验，不关闭宿主。

启动日志可先运行 `python3 scripts/ssi-lab/check-ssh-boot.py guest.log --host-log node0-kernel.log --host-log node1-kernel.log`。它会拒绝带内核告警、RCU 停顿或时钟/网络错误的就绪记录，但不替代完整 SSH、SFTP、执行归属与关机验收。宿主日志必须覆盖本轮全过程，不应截取掉告警。

2026-11-05 的双节点 SSH 完整验收仍失败。早期实验认证后出现 RCU 停顿和宿主脏页记账告警；后续 PF5 已通过 SSH 中的四线程测试和 SFTP 往返，但仍有时钟偏移且未完成正常关机。候选补丁和应用顺序在 [experiments](experiments/README.md)，不要加入上面的默认构建步骤。

## 设备接口探针

`probe-dsm-device.py` 在显式指定的研究内核上直接创建真实 KVM VM，验证 DSM 写入的脏页位图、内存槽/地址别名清理及 dirty ring 互斥。没有 vCPU 或磁盘，不依赖 QEMU，也没有伪造 ioctl 返回值。每项只有在 VM fd 成功关闭后才标为通过。

```sh
timeout --kill-after=5 45 python3 scripts/ssi-lab/probe-dsm-device.py \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf5
```

只适用于可重置的隔离 VM。PF2 实测在关闭 VM 时进入无法被 timeout 杀死的内核循环，需恢复实验 VM；这是已知缺陷，不是超时工具提供的安全隔离。两个节点的 PF5 五组测试均通过，具体覆盖范围与尚未测试的别名写入、并发和取消路径见 [设备内存记录](../../docs/ssi-device-memory.md)。该探针不在普通 CI 中运行，CI 不具备配套研究内核。

## 跨 CPU 时钟探针

`guest-clock.c` 静态编译后通过现有 SFTP 放入无磁盘客体运行；`check-clock.py` 核对 32 个有序采样与四个定时器记录。它检测 TSC 和三类应用时钟倒退、定时器提前返回，不代替启动 watchdog、长期漂移或宿主错误检查。使用方式、成功与失败的真实证据见 [时钟实验](../../docs/ssi-clock.md)。启动偏移候选仍在 `experiments/`，不进入默认构建路径。

`probe-pvclock.c` 和 `probe-pvclock.py` 直接创建仅执行 HLT 的 KVM 实例，强制跨节点转移时钟页后核对内核写入的新版本。PF5 复现更新丢失，PF6 的受控交接通过；使用方式和限制见 [pvclock 实验](../../docs/ssi-pvclock.md)。该探针不在普通 CI 中执行，CI 只编译它并重新核对已保存的真实接口记录。

## DSM 接收等待与性能采样

`probe-receive.py` 复用上面的 C 二进制，测量真实 KVM DSM 监听器在空闲、八字节半帧和 socket 关闭时的行为。额外指定 `--close-order vm-first` 可在保留半帧连接时销毁 VM，验证接收等待可中断。实验防火墙必须允许回环到 TCP 37710，不需要开放外部来源。它会拒绝正在运行其他实验的节点；需要 root 读取内核线程栈，不能在业务宿主运行。

`profile-threads.py` 对指定 QEMU 及独占节点上的 DSM 线程采样，`summarize-profile.py` 核对生命周期和累计 CPU 时间。原始数据、候选接收补丁和验证边界见 [传输实验](../../docs/ssi-transport.md)。默认构建流程不自动应用候选。

可用 `check-clock.py guest.log --max-timer-ms 250` 对本轮四个定时器额外施加延迟门槛；省略参数时仍只验证计时单调性及不提前返回。`check-ssh-boot.py` 现在也拒绝丢失 RTC 中断和因读取间隔太长而跳过 watchdog 的记录。

## 固定页面与关闭入口

`probe-pins.py` 只允许独占 PF22 对照或 PF23 候选内核，分别运行 `--mode service|lifecycle|active|rollback --require-kernel <精确内核名> --output <新文件>`。PF22 仅允许 service 对照，PF23 覆盖全部四种场景。`check-pins.py <记录.json>` 从真实 ioctl 和内核事件核对引用、释放及关闭拒绝。先读 [固定页面实验](../../docs/ssi-pin-lifecycle.md)；有引用时拒绝封闭不等于后台设备已停止或 DSM 可以最终断连。

## 远端取页期间解除固定

`probe-pin-release.py` 只允许独占 PF23 对照或 PF24 候选，使用 `--mode dependency|pending|pending-write|empty|rollback|duplicate --require-kernel <精确内核名> --output <新文件>`。PF23 只允许 dependency，PF24 覆盖全部六种场景。`check-pin-release.py <记录.json>` 核对解除先于远端响应、暂存保护、回滚、重复解除与活动操作的槽保护，使用方式和失败记录见 [解除进展实验](../../docs/ssi-pin-release.md)。

## QEMU 设备映射失败

`probe-qemu-map.py` 对显式启用诊断的暂停双节点实例执行真实 QEMU map/unmap，捕获 KVM 原生 ioctl；`check-qemu-map.py <记录.json>` 核对返回、控制流、引用与失败退出。需要精确 PF24 内核、实际 PID、QMP 路径和二进制哈希。普通候选不含诊断入口。先读 [映射失败实验](../../docs/ssi-qemu-map-failure.md)，不能把直接 API 诊断当成真实设备 reset/unrealize 或完整关闭验收。

## 最终刷盘错误

`probe-shutdown-flush.py` 只在新目录创建独立测试盘，通过原生 HMP 写读和 blkdebug 注入 EIO/ENOSPC，保存块层跟踪、QMP 和实际退出码；`check-shutdown-flush.py <记录.json>` 区分单节点与配对故障传播。原版内核仅用于单节点，配对要求 PF24。完整参数、失败记录和未覆盖的客体 DMA/掉电语义见 [关闭刷盘实验](../../docs/ssi-shutdown-flush.md)。

探针使用回环 37710/37711，临时例外必须同时允许回环目标端口和源端口，避免随机客户端端口落入实验防火墙受保护段而拦截返回包。仅允许 `lo` 与 `127.0.0.0/8`，执行前核对所有方向的 TCP 状态为空，执行后恢复精确原规则。它不需要外网或业务网段的新权限，不应在业务宿主运行。
