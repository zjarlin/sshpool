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
