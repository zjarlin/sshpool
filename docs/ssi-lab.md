# GiantVM 双节点实验记录

日期：2026-11-05。该记录针对严格 SSI 研究，不是已有 SSH 任务调度器的验收，也不是生产部署报告。

后续更新：[PF5 设备实验](ssi-device-memory.md) 发现并修复了 PF2 尚未覆盖的脏页和页映射清理缺陷；[SSH 工作区](ssi-workspace.md) 已完成一次跨节点 SSH 内存测试与 SFTP 往返，仍未通过时钟和正常关机门槛。下文的历史测试结果不构成 PF2 的生产稳定性保证。

**本轮结果：一个原版 Ubuntu Linux 客体跨两个实验节点运行，同一 PID 的四线程计算、32 MiB 共享内存校验和原子计数通过。** 两个节点都是真实 KVM 执行端，但位于同一台 ESXi；尚未形成可登录的 SSI 工作机，也未运行 Docker、数据库或故障恢复测试。

## 环境与证据边界

在已授权 ESXi 上新建两个 Ubuntu 24.04.5 x86_64 实验 VM，每个 2 vCPU、1 GiB 内存、10 GiB 薄置备独立磁盘，CPU 上限 2000 MHz，启用嵌套虚拟化。创建前确认宿主资源余量，不复用或改动业务 VM。实验只使用新磁盘和自制测试数据，不挂公司目录或数据库卷。

两台 VM 位于**同一个物理 ESXi**。它们可以验证跨 Linux/KVM 实例的网络协议、远端 vCPU 和一致性实现；不能证明跨物理宿主性能、物理故障容错或 Apple Silicon 与 x86 混合执行。入口 Mac 只承担控制与一次性交叉编译，客体运行在 ESXi 的实验节点中。

完整原始日志、ESXi 清单、地址、SSH 公钥及配置留在本地私有实验目录；公开仓库只保留不含私人地址和凭据的摘录。复现脚本和许可证说明见 [scripts/ssi-lab](../scripts/ssi-lab/README.md)。

## 固定版本与准备完成项

| 项目 | 现场结果 |
| --- | --- |
| ESXi | 7.0.3，支持嵌套硬件虚拟化 |
| 两节点原内核 | Ubuntu `6.8.0-147-generic` |
| 普通 KVM | 两节点 API 12，`KVM_CREATE_VM` 成功 |
| 原内核 DSM | `KVM_CHECK_EXTENSION(249) = 0` |
| GVM 内核基线 | `6317a6badf4f5a42e8ff7f6881b3a9199e6c0b54` |
| GVM QEMU 基线 | `da3f3b05d23ba714a3e961f80c059c376007d7d7` |
| 定制宿主内核 | `7.1.0-rc3-sshpool-gvm`，启用两个 DSM 选项 |
| 定制内核 DSM | 两节点 `KVM_CHECK_EXTENSION(249) = 1`，创建 VM 成功 |
| APICv | 两节点实际参数为 `N` |
| 配对 ABI | DSM capability 249；旧式转发退出 45/46/47 的定义一致 |
| 实验通信 | TCP DSM 与中断通路建立；防火墙仅放行另一个实验节点 |
| 回退 | 默认保留 Ubuntu 原内核，研究内核通过 `grub-reboot` 一次性启动 |

下载归档 SHA-256：

```text
GVM-kernel: d23b0408220fe9b5b7d45e1e6a99eb2f753bb975768b96be66d93aea1b1e0b1c
GVM-qemu:   5c3e2dddb7235cf40a1f630a36f4c58e4d030a944c1338876a5580c6b9b83d2c
```

## 故障与针对性修正

### QEMU 单节点启动崩溃

同一构建在普通 KVM 上启动 4 vCPU、256 MiB 的 Ubuntu 客体时，进入用户态前发生段错误。GDB 现场定位：

```text
SIGSEGV in ioapic_router_forwarding
interrupt-router.c:1051: QEMUFile *io_connect_file = req_files[1];
kvm_irqchip_commit_routes → ioapic_update_kvm_routes → ioapic_mem_write
```

路由 mutex 在单节点模式下也初始化，但连接数组未创建。`qemu-single-node-routing.patch` 限制为分布式主节点才广播路由。修正后单节点对照通过：同一个 PID 1、4 个线程各固定到 CPU 0/1/2/3、32 MiB 共享内存、原子计数 512，退出状态 0，客体正常关机。**这次通过只是单节点对照。**

### DSM 页引用生命周期异常

首次双节点运行在 BIOS 阶段出现 `KVM_RUN: Bad address`。远端宿主日志出现：

```text
WARNING: mm/gup.c:143 at try_grab_folio
follow_page_pte → get_user_pages_unlocked → hva_to_pfn → direct_page_fault
BUG: Bad rss-counter state ... MM_FILEPAGES val:-1
BUG: Bad rss-counter state ... MM_ANONPAGES val:1
```

随后宿主 `sshd`、shell 和错误报告进程也发生段错误。已保存现场并回退两个实验 VM；回退后 SSH 正常，`openssh-server`、`libc6`、`libssl3t64`、`bash` 的 `dpkg -V` 校验没有输出差异。

源码中的 `direct_page_fault()` 成功路径没有执行页引用释放；重试路径先由 `kvm_mmu_finish_page_fault()` 释放，再由 `kvm_release_page_unused()` 重复释放。`kernel-page-reference.patch` 统一这两条清理路径，构建版本为 `7.1.0-rc3-sshpool-gvm-pf1`。修正后客体进入用户态，宿主在本轮后续测试中保持可登录，未再观察到 GUP 引用警告与宿主进程段错误。这是本实验范围内的结果，不是整个内核的内存安全证明。

仍观察到 `access mismatch under direct page (expected 7, got 5)` 警告；上游把 DSM 访问权限直接传入 KVM 的客体权限记账，尚待独立审计。没有通过删除警告来掩盖该问题。

### x2APIC 使远端 CPU 未上线

页引用修正后的首次启动仍只有 CPU 0/1 在线：

```text
CPU2 failed to report alive state
CPU3 failed to report alive state
smp: Brought up 1 node, 2 CPUs
```

本版本只在传统 APIC MMIO 写路径发出 DSM 转发请求；x2APIC ICR 写路径没有等价转发。客体默认启用 x2APIC，导致远端 AP 未正确启动。最终启动脚本显式设置 `-cpu qemu64,-x2apic` 与客体 `nox2apic`，没有改写客体内核或应用。

测试程序也收紧为**必须 4 个在线 CPU**。早期日志中的 `PROOF_PASS cpus=2` 只验证了退化到主节点的两线程运算，不能作为跨机应用成功证据。

## 最终跨节点结果与剩余门槛

最终运行的客体证据摘录如下，完整公开摘录与文件哈希见 [evidence/ssi-20261105.txt](evidence/ssi-20261105.txt)：

```text
smp: Brought up 1 node, 4 CPUs
PROOF_START pid=1 online_cpus=4 bytes=33554432
PROOF_THREAD pid=1 tid=105 requested_cpu=0 observed_cpu=0 checksum=9881296914831760266
PROOF_THREAD pid=1 tid=106 requested_cpu=1 observed_cpu=1 checksum=14269900721331050332
PROOF_THREAD pid=1 tid=107 requested_cpu=2 observed_cpu=2 checksum=5704288491290152150
PROOF_THREAD pid=1 tid=108 requested_cpu=3 observed_cpu=3 checksum=5860889749692592215
PROOF_PASS cpus=4 shared_counter=512 memory_verified_bytes=33554432
PROOF_EXIT status=0
reboot: Power down
```

这里客体输出的“1 node”是一个客体 NUMA 节点，不表示只有一个底层执行节点。宿主线程采样显示：节点零的 CPU 0/1 有累计执行时间，CPU 2/3 为 0；节点一正好相反。没有把程序拆成两个 SSH 作业，也没有用 TCG 软件仿真。两个 QEMU 最终均以状态 0 退出。

该次从启动到采样到测试通过约 11 分钟，普通单节点对照约 1 秒进入测试。嵌套虚拟化、每节点 2000 MHz CPU 上限、TCP DSM、一致性流量和完整 Ubuntu 初始化都影响结果，不能凭此次测试确定每项开销占比。客体时钟出现调整，不能拿客体日志秒数直接充当可靠性能基准。**当前证据不支持“总算力略小于所有机器之和”。**

程序只读写 32 MiB，远小于单节点 1 GiB 宿主内存。这验证了小工作集共享访问，没有验证跨机内存容量相加。两个节点均无 swap；仍需更大工作集、随机访问、压力和恢复测试。

`scripts/ssi-lab/check-proof.py` 对最终真实日志检查通过，对先前降级到两个 CPU 的真实日志明确拒绝。它检查客体结果，不能独自证明节点归属；必须结合线程采样、启动参数和两节点文件哈希。

实验结束后，两台宿主已重新启动到 `6.8.0-147-generic`，SSH 正常，没有残留 QEMU/DSM 进程；源码、修正内核和日志保留。后续需要通过一次性引导重新进入研究内核。已有业务 VM、生产数据库和入口服务未修改。

当前严格产品目标仍以 [110-pooled-linux.feature](../features/110-pooled-linux.feature) 和 [120-stateful-recovery.feature](../features/120-stateful-recovery.feature) 为准：单实例超过任一节点的驻留内存、未修改业务镜像、持久化 I/O、PostgreSQL/Redis 事务恢复、网络分区隔离、物理节点故障恢复、跨 ISA 和性能基线均不能由上述准备工作推导为完成。

## 同日继续：权限修正与页面交接测试

上述 `pf1` 记录保留为历史结果。继续审计确认，`direct_map()` 把 DSM 权限直接交给 `mmu_set_spte()`，后者不仅构造硬件映射，也把这些权限写进客体权限的反向映射记录。直接映射的客体权限应为 `ACC_ALL`，因此出现 `expected 7, got 5`。另一个问题是邻页预取通过普通 GUP 后直接创建 SPTE，未逐页经过 DSM 获取与锁定。

`kernel-dsm-permissions.patch` 把两种权限分开：保留原来的客体权限用于记账，仅在构造硬件映射时与 DSM 权限取交集；DSM 模式禁用未经逐页授权的邻页预取。没有删除告警。两节点实际构建、启动的版本为 `7.1.0-rc3-sshpool-gvm-pf2`，内核哈希为 `8a7460f98785c260b90180c47314628bf5d985285c64e3161627c0814eec8026`。

新增 `guest-stress.c` 是静态用户态程序：在同一个地址空间分配 4 MiB，由四个固定 CPU 交错写相邻页面；每轮更换写入方，每个 CPU 都用不同遍历顺序检查全部页面的每个字。每次分配运行八轮并核对原子计数 4096，释放后再分配一次。该测试仍是小工作集，不是容量相加或长期压力验收。

普通单节点对照和首轮双节点实验均通过，首轮两个 QEMU 退出状态均为 0，宿主日志没有 `WARNING:`、`BUG:`、权限不匹配、引用计数或进程段错误。公开原始输出摘录及两边 vCPU 执行采样见 [压力测试证据](evidence/ssi-stress-20261105.txt)，单节点对照另存为 [control](evidence/ssi-stress-control-20261105.txt)。这些警告扫描的通过范围仅限所保存的实验日志，不能替代内核形式化验证或长期运行。

`check-stress.py` 要求完整的轮次、计数、同 PID、线程与 CPU 覆盖及退出记录；Rust CI 同时运行该检查器的 Python 回归测试。一次复跑中，串口把完整的 `workqueue: ... hogged CPU ...` 内核消息插进了用户态的一行中间。检查器只重组这种精确识别的诊断交错，原始日志不变，缺字段、缺轮次、错误计数和其他残缺输出仍然失败。

使用同一份 Ubuntu 内核和压力测试 initramfs 连续重新创建客体共三次，全部通过，两边每次均退出 0；每次保存两节点线程样本、精确文件哈希和宿主本次启动日志，均未检出上述告警。第二、三轮由入口单调时钟采样得到总耗时约 345 秒、474 秒，采样间隔 30 秒，包含开关机与收集开销。这是客体重新启动，宿主没有清空缓存或重启；不能作为严格性能对比。关闭后两宿主内存可用量恢复，也没有残留 QEMU。三次有限测试不等于长期内存安全或生产可用性验证。

另用临时 `pf3` 内核仅给 DSM 两端 TCP 连接设置 `TCP_NODELAY`，同一测试通过且总耗时约 436 秒（采样间隔 5 秒）。该值仍在前两次波动范围内，不能认定有明确性能收益；没有把这个候选改动纳入默认构建，后续回到 `pf2`。仍需对 DSM 交接、调度、时钟与网络等待分别测量，不能把慢启动简单归因于 Nagle，也不能承诺性能接近各机器之和。
