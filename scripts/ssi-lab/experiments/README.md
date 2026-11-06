# 未通过完整验收的设备与时钟候选补丁

本目录不是默认安装路径，不能部署到业务宿主。QEMU 补丁为 GPL-2.0-or-later，Linux 内核补丁为 GPL-2.0-only，正文见上级目录的 `COPYING.GPL-2.0`。PF2 历史内存测试不等于稳定性保证，后续探针已复现其设备脏页与映射销毁缺陷。

固定上游提交仍是 `da3f3b05d23ba714a3e961f80c059c376007d7d7`。在已应用 `qemu-single-node-routing.patch` 的独立源码目录使用 `patch -p1 < qemu-virtio-dsm-cache.patch`，重新构建并另存二进制，保留原始运行时。

## 改动与已观察结果

`address_space_cache_init()` 原先为 DSM RAM 保留本地直接指针，virtio 队列读取与完成索引写回可能绕过 DSM 页面获取。候选补丁在 TCP DSM 模式取消该直接指针，并让 virtio 的标量队列访问走已有的字节读写接口；这些接口的慢路径调用 `KVM_DSM_MEMCPY`。单节点和共享内存模式不取消直接指针。

本次只研究 virtio 队列缓存。其他设备的标量访问、DMA pin/unpin、错误传播、脏页跟踪和设备复位尚未系统验证，不能把这一修改称为完整设备一致性实现。

- 单节点对照：SSH、同进程内存测试、1 MiB SFTP 往返及正常关机通过。
- 双节点：成功认证一次并返回客体主机名；随后客体 RCU 停顿，后续 SSH 与 SFTP 握手超时。
- 宿主在设备访问时出现 `mark_page_dirty_in_slot` 告警，调用链含 `__kvm_write_guest_page`、`ivy_kvm_dsm_page_fault` 和 `kvm_vm_ioctl_dsm`。
- 两边到运行时限后终止，没有完成正常客体关机。**完整验收失败。**

运行二进制 SHA-256 为 `a2d0a9c4eaf74e72e044ff229b6cbbc9d1a7aeeb36ac8d8799f30e91ade8e7fc`。脱敏记录和测试边界见 [SSH 设备实验](../../../docs/evidence/ssi-ssh-network-20261105.txt)。这些结果既不能确定 RCU 停顿的根因，也不能证明补丁已经修复整个网络路径。

## 客体对照构建

诊断使用原版 Ubuntu `6.8.0-147-generic` 客体内核（哈希见证据），保留由上级 `build-ssh-guest.py` 生成的 Alpine 用户态、OpenSSH、主机密钥和测试程序。这个 Ubuntu 内核内建 `VIRTIO/ VIRTIO_PCI/ VIRTIO_NET/ FAILOVER/ NET_FAILOVER`。

在新建私有构建目录复制生成器的 `root/`，将其中 `/init` 的三行 `insmod` 替换为 `test -d /sys/module/virtio_net`，其后输出 `SSH_INIT_NETWORK_BUILTIN`；其他初始化步骤不变。用文档中的 `cpio --owner=0:0 --format=newc` 和 `gzip -1` 重新打包，给两节点分发完全相同的镜像与内核。原 Alpine 模块未加载，未修改发行版内核。镜像中含 SSH 私钥，不能发布。

以上是早期 virtio 缓存实验。不能以关闭 watchdog 或删除 WARN 来验收。

## PF5 设备写入和反向映射

新增三个候选补丁：

- `kernel-dsm-device-writes.patch`：DSM 位图模式支持没有运行中 vCPU 的设备写入，MEMCPY 记录脏页并返回复制错误；DSM 与 dirty ring 两种启用顺序互斥。
- `kernel-dsm-rmap.patch`：DSM 编码页号的 bit 1 不再被普通 KVM 反向映射当成锁位，查询保留原值，清理使用 DSM 自身 mutex。
- `qemu-dma-unpin.patch`：按完整映射 `len` 解除固定，不能只解除实际传输 `access_len`。

固定源码提交与上级 README 相同。内核先应用默认的页引用、权限补丁，再按下面顺序应用；不要把研究内核设为默认引导项：

```sh
patch -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-device-writes.patch
patch -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-rmap.patch
# 按上级构建脚本生成配置，将 LOCALVERSION 设为 -sshpool-gvm-pf5 后单独构建。

# QEMU 已应用上级单节点路由补丁。
patch -d GVM-qemu -p1 < scripts/ssi-lab/experiments/qemu-virtio-dsm-cache.patch
patch -d GVM-qemu -p1 < scripts/ssi-lab/experiments/qemu-dma-unpin.patch
```

两节点 PF5 实际接口探针的五项测试均通过，单节点完整对照通过；双节点 SSH 四线程测试和 SFTP 往返也通过。时钟门槛仍失败，900 秒限时终止导致正常关机未验证，因此继续作为实验补丁保存。所有地址别名的脏位传播、用户缓冲区异常、并发内存槽变动、DMA 取消及设备复位仍未全部覆盖。

精确哈希、重现与已知限制见 [设备内存实验](../../../docs/ssi-device-memory.md) 和 [PF5 SSH 输出](../../../docs/evidence/ssi-ssh-pf5-20261105.txt)。后续先解决时钟与生命周期，重复完整实验，再考虑持久磁盘和数据库。

## TSC offset 冷启动候选

在上述 QEMU 补丁之后应用 `qemu-clock-offset.patch`，另存二进制。两边必须先核对同一候选哈希，再共同启动；它扩展了原 KVMCLOCK 消息，与旧版本不兼容。默认 `run-node.sh` 没有自动应用此补丁。实验配置额外使用 `-cpu qemu64,-x2apic,+tsc-adjust,enforce` 和 `-smp 4,sockets=2,cores=2,threads=1`，外层限时为 1800 秒。

```sh
patch -d GVM-qemu -p1 < scripts/ssi-lab/experiments/qemu-clock-offset.patch
ninja -C GVM-qemu/build -j2 qemu-system-x86_64
```

该候选同步原生同频 TSC 初始偏移和 KVM 纳秒时钟，支持一次冷启动。最短 RTT 采样不能保证长期同步，也不支持暂停恢复、迁移、重连或故障接管。实测单节点完整对照通过，双节点有限时钟探针通过，但启动 watchdog 仍记录 kvm-clock 零读数，**不是已完成的时钟修复**。真实内核和新协议的所有拒绝分支仍需故障注入验证。算法、哈希与其余结果见 [时钟实验](../../../docs/ssi-clock.md)。

## PF6：pvclock 页面写权限

在 PF5 内核补丁之后应用 `kernel-dsm-pvclock.patch`，另行构建 `-sshpool-gvm-pf6`。它在 KVM pvclock 的缓存写入之前取得 DSM 页面写权限，覆盖正常完成和缓存刷新失败的释放路径。默认构建脚本仍不自动应用这些候选补丁。

同一真实 KVM 探针在 PF5 双节点中 8/8 丢失更新，在 PF6 中 8/8 保留新版本及同页记录。修改范围、精确哈希、重现方法和未覆盖的并发/Xen/Hyper-V 缓存路径见 [pvclock 实验](../../../docs/ssi-pvclock.md)。该结果不等于所有时钟、设备和关闭错误已经解决。

## PF7：接收等待

在 PF6 后应用 `kernel-dsm-receive-wait.patch`，另行构建 `-sshpool-gvm-pf7`。它让任意请求接收者和半帧读者等待 socket；指定事务空读仍让出接收锁并退避，保留多读者分流。协议格式、错误报告与所有权操作保持原样。没有应用 TCP_NODELAY 或关闭 watchdog，尚未实现显式关闭握手和故障恢复。真实探针与客体结果见 [传输实验](../../../docs/ssi-transport.md)。

## MMIO 写完成确认

在时钟候选 QEMU 之后应用 `qemu-mmio-completion.patch`，另存运行时。它等待远端完成设备模拟操作后再恢复发送端 vCPU；时钟启动握手中的路由协议版本同时升为 2。默认构建不自动应用。完成确认不等于磁盘刷盘、DMA 完成或数据库事务提交，PIO 和双向设备回调仍需单独研究。

`qemu-edu-delay.patch` 是独立诊断补丁，可分别应用于原时钟候选和完成确认候选；只有显式设置 `SSHPOOL_LAB_EDU_DELAY_US=50000` 才延迟指定 EDU 寄存器的远端写入。它不伪造返回值，不应部署到普通工作区。串口和 stderr 必须分开保存。精确边界、故障记录与复现见 [设备顺序实验](../../../docs/ssi-device-order.md)。

## PF11：请求容量与可取消页锁

在 PF8 启动、PF9 销毁顺序、PF10 缺失槽取消补丁之后应用 `kernel-dsm-request-safety.patch`。它为接收调用传入实际容量、在复制前拒绝超长载荷、验证请求字段并统一回收异常分支；接收处理器使用可取消页锁。两个节点的直接异常请求和同页锁竞争通过独立探针，事务缓存和超长失效响应等分支尚未完成动态验证。精确构建来源与限制见 [请求安全实验](../../../docs/ssi-request-safety.md)。

## PF14：无 PLE 宿主上的显式 PAUSE 拦截

在 PF11 后应用 `kernel-dsm-pause-exit.patch`，单独构建 `-sshpool-gvm-pf14`。诊断开关 `kvm_intel.dsm_force_pause_exit=1` 默认关闭，仅针对已启用 DSM、没有 PLE 且支持 PAUSE 拦截的 VM。它显式覆盖该 VM 的禁止 PAUSE 退出策略，在进入客体前设置控制位；退出处理使用实际 CPL，覆盖用户态指令。普通 VM 不启用此路径。

PF12、PF13 是未实际启用拦截的中间候选，不是补丁依赖。公开补丁直接从 PF11 重放到 PF14。实验包括真实退出事件、用户态进度、同内核开关对照与无跟踪运行，并保留缓冲溢出、建连超时和工作区未通过的结果。证据、额外退出开销及边界见 [KVM 停顿实验](../../../docs/ssi-vcpu-residency.md)。默认安装流程不自动应用此候选。

## PF15：宿主定时器延期重装

在 PF14 后应用 `kernel-dsm-host-timer-rearm.patch`，单独构建 `-sshpool-gvm-pf15`。它在 x86 KVM 返回、重新开启中断前调用已有 `hrtimer_rearm_deferred()`，影响该配置下的普通 KVM 返回路径，因此另有单节点回归；不是只针对 DSM 的开关。两侧完整跟踪与两次无跟踪三轮时钟测试见 [宿主定时器实验](../../../docs/ssi-host-timers.md)。RTC、watchdog、关闭协议以及所有业务持久化门槛仍未完成。默认安装流程不应用此候选，不应部署到业务宿主。

## 分布式 PIO 合并缓冲

在已有 MMIO 完成确认 QEMU 上应用 `qemu-dsm-pio-coalescing.patch` 并另存二进制。它只在分布式拓扑下停止注册本地合并 PIO 区域，避免 RTC 索引写入本地缓冲而数据读取转发远端；普通单节点保留原行为。用 PF15 做独立时间基准和注册调用对照，见 [RTC 实验](../../../docs/ssi-rtc.md)。未增加通用 PIO 写完成协议，未修复合并 MMIO；默认流程不应用此候选。

## PF16：固定页面重试的副本集合

在 PF15 后应用 `kernel-dsm-copyset-retry.patch` 并构建独立的 `-sshpool-gvm-pf16` 内核。请求因页面固定返回重试时不再清空副本集合，所有权转移检查保留。两节点各自的真实 KVM 单页对照，以及两个 QEMU 组成一个客体的两次工作区回归见 [副本集合重试实验](../../../docs/ssi-copyset-retry.md)。其他固定模式、错误传播、正常关闭与业务持久化仍未通过；默认流程不自动应用。

## PF17：故障传播到 VM 管理层

在 PF16 后应用 `kernel-dsm-failure-propagation.patch` 并构建独立的 `-sshpool-gvm-pf17` 内核。首次请求故障锁存为 VM 失败，中止已建立连接、取消服务线程并通过标准 KVM 接口向管理端返回错误。两节点分别执行的真实 KVM/合成对端对照和真实 QEMU 回归见 [故障传播实验](../../../docs/ssi-failure-propagation.md)。这改变了 PF11 允许错误线程退出后继续使用同一 VM 的行为。正常关闭握手、TCP 建连中的故障、黑洞分区与恢复仍未验收；默认流程不应用。

## 分布式 QEMU 的致命执行错误

在已有 `qemu-dsm-pio-coalescing.patch` 候选上应用 `qemu-dsm-failure-exit.patch`，另存二进制并在两端核对同一哈希。旧版的 KVM 执行错误触发 CPU 状态转储，转储再次读取失效 KVM 并递归报错，双节点真实注入中两端均段错误。新候选在分布式拓扑的该错误出口直接返回失败退出码，保留普通单节点路径。这是 fail-stop，不执行客体文件系统或数据库的安全关闭，不代表正常 DSM 关闭握手、自动恢复或持久化验收。证据保留旧版失败的完整重复日志。

## 关闭前的路由排空屏障

在故障退出候选后应用 `qemu-router-drain.patch`，另存运行时并在两端使用同一版本。路由协议升为 3：保留关机原因与退出码，关机通知后仍服务已有请求；主线程停止 vCPU 和排空块层后，核对两端的版本、节点与本次序号，再关闭连接。屏障阶段的截止时间为 15 秒，不覆盖更早的 vCPU 停止或块层等待。普通单节点跳过分布式屏障。

真实内存客体对照、异常帧及未完成范围见 [路由排空实验](../../../docs/ssi-router-drain.md)。内核仍为 PF17，DSM 关闭继续报连接重置，不能以 QEMU 屏障或退出码零验收整个关闭协议。默认流程不应用，不挂载业务数据。

## PF18：内核入站连接屏障

在 PF17 后应用 `kernel-dsm-inbound-drain.patch`，构建独立的 `-sshpool-gvm-pf18` 内核。它为接收流添加原子登记和在途请求计数，收到类型 3 标记后等此前请求完成响应、释放页锁与 SRCU，再回带版本和关联序号的确认。新标记不会由现有 QEMU 自动发送；仅由专用直接探针覆盖。EOF 的错误语义保持不变。

这个阶段尚未停止整机的新外部请求，也没有协调其他连接的反向取页。五秒期限只覆盖标记已经进入处理器后的排空等待，不覆盖半帧接收、八线程全占满、TCP 建连或确认发送。证据和后续关闭协议见 [内核排空实验](../../../docs/ssi-kernel-drain.md)。默认构建流程不应用，不部署到业务宿主。

## PF19：排空前的流内故障顺序

在 PF18 后应用 `kernel-dsm-drain-fault-order.patch`，构建独立的 `-sshpool-gvm-pf19` 内核。接收函数在释放分发锁前锁存已发现的故障，防止下一处理线程越过坏帧确认后续标记。正常主动停止的 EINTR/EPIPE 保留原取消语义。该竞态来自源码审查；两个节点的坏帧加标记实验验证修复后的拒绝行为，不冒充旧版稳定复现。PF19 补充探针、工作区回归及剩余整机关闭缺口同见 [内核排空实验](../../../docs/ssi-kernel-drain.md)。

## PF20：VM/vCPU ioctl 准入屏障

在 PF19 后应用 `kernel-dsm-ioctl-admission.patch`，单独构建 `-sshpool-gvm-pf20`。它封闭普通 VM/vCPU ioctl 的入口并统计完整调用，控制查询和等待不计入自己等待的操作；已准入调用与页面服务继续完成。十组真实 KVM 探针及客体回归见 [入口准入实验](../../../docs/ssi-ioctl-admission.md)。现有 QEMU 尚不调用新接口；后台设备、跨调用 DMA pin、完整出站事务和最终网络关闭仍未协调，不能把此屏障成功当作整机可以关闭。默认流程不自动应用。

## PF21/PF22：出站事务与缓存消费

PF20 后依次应用 `kernel-dsm-exchange-accounting.patch` 和 `kernel-dsm-exchange-id-exhaustion.patch`，构建后缀 `-sshpool-gvm-pf22`。PF21 增加完整出站计数、连接内的活跃事务登记、缓存消费及状态查询；PF22 修复编号耗尽时重复取得保留编号的无限循环。**不要只应用 PF21 作为最终候选。** 这两个补丁和 `idr-exhaustion.c` 为 GPL-2.0-only，默认流程不应用。

先看 [事务与缓存实验](../../../docs/ssi-exchange-accounting.md)，再看 [探针](../probe-exchanges.py) 与 [检查器](../check-exchanges.py)。证据保留 PF21 的边界失败，区分缓存成功消费和故障丢弃。`idr-exhaustion.c` 使用 Linux 原有 IDR 用户态测试环境及从候选源提取的函数，锁为单线程替身；不能当作大规模 KVM 并发或网络验证。QEMU 尚不使用新状态接口，最终 DSM CLOSE/ACK、设备排空和持久化仍未实现。

## PF23：固定引用与关闭准入

PF22 后应用 `kernel-dsm-pin-lifecycle.patch`，构建独立 `-sshpool-gvm-pf23`。跟踪跨 ioctl 的读写固定引用和在途固定调用，有引用时拒绝封闭普通入口并保留解除通道；错误解除不减计数，部分固定失败只回滚本次新增引用，固定期间保护内存槽。补丁为 GPL-2.0-only，默认流程不应用。使用方式、对照证据和未完成的设备关闭协议见 [固定页面生命周期](../../../docs/ssi-pin-lifecycle.md)。

## PF24：等待取页时解除旧引用

PF23 后应用 `kernel-dsm-pin-release.patch`，单独构建 `-sshpool-gvm-pf24`。用独立引用锁与暂存计数保护整段提交，解除路径避开持有网络等待的全局 DSM 锁和页面锁；在途固定令牌在引用为零时也保护槽。补丁为 GPL-2.0-only，ABI 不变，默认流程不应用。两节点对照、六类探针和未完成的全程取消与设备关闭见 [解除进展实验](../../../docs/ssi-pin-release.md)。
