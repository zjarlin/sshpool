# SSI 时钟与 pvclock 实验

2026-11-05 UTC 至 11-06 本地时间。两台专用 x86 实验 VM 仍在同一物理 ESXi 上。没有部署 Ceph，没有接入业务磁盘或数据库。当前成果不代表异构主机的 CPU/RAM 合池或故障恢复。

## 基线：正常关机已观察到，时钟仍失败

PF5 宿主与 DMA unpin QEMU 的后续双节点实验保留原运行时，仅把客体配置改为两个 socket 并暴露 `tsc-adjust`。它通过了 SSH 四线程页面交接与 1 MiB SFTP 收发、删除，客体执行 `poweroff -f` 后串口进入 S5，两边 QEMU 都退出 0。实际耗时 742 秒，没有触发 1800 秒外层超时。

这补齐了此前未完成的正常关机观察，但完整场景仍失败：

- 时钟探针从 CPU 0 移到 CPU 2 时，TSC 从 `1101274420672` 回退到 `1101154532972`，约 50 毫秒。
- 客体 watchdog 报告 TSC 相对 kvm-clock 偏差约 78 毫秒，并标记 TSC 不稳定。
- 关机阶段宿主记录 `ktcp_receive ret -104/-4` 与 DSM 服务退出错误。这些仍是日志门槛失败项，没有被忽略或归类为无害。

同一探针的单节点对照完成 32 次采样和四次定时器检查。完整读数见 [单节点采样](evidence/ssi-clock-control-20261105.txt)，失败读数、挂载、工作负载和退出结果见 [双节点基线](evidence/ssi-clock-baseline-20261105.txt)。客体只用 initramfs 和 tmpfs；SFTP 文件不持久化，不能视为 Docker 或数据库磁盘验收。

## 启动偏移候选

原 GVM 路径只交换一个 KVM 纳秒读数并加一次 RTT/2。`KVM_SET_CLOCK` 不会同步不同 KVM 实例的 vCPU TSC offset，因此 Linux 可以看到来自两套 TSC 初始时刻的计数器。

`experiments/qemu-clock-offset.patch` 使用官方 `KVM_VCPU_TSC_OFFSET` 和 `KVM_GET_CLOCK` 接口：

1. 在 vCPU 启动前核对原生频率与 offset 属性，将本实例所有 vCPU 的 offset 设置为同一值并读回确认。
2. 源节点发布 KVM 时钟、宿主 TSC、初始 offset 与频率。路由线程只读取 VM 时钟和已发布的数据，不等待运行中 vCPU 或 BQL。
3. 目标节点完成 16 次往返采样，选择最短一次；用目标 TSC 中点计算源与目标 offset 差异，同时初始化 KVM 纳秒时钟。
4. `KVM_SET_CLOCK` 的 REALTIME 只引用目标宿主自己的采样时间，用于补偿本机 ioctl 间隔，没有假设两台宿主墙钟已同步。

候选只支持一次冷启动、相同原生 TSC 频率和可靠的宿主 TSC 快照。显式 TSC 缩放、能力缺失、频率不匹配、超出 5 毫秒的最短往返或再次恢复会报错。新协议与原 QEMU 不兼容，**必须预先核对两节点候选二进制哈希一致**；版本字段不能代替传输超时、身份认证或协议握手。

网络中点只是估计，RTT/2 是在读数有效、请求时间顺序和频率前提下的初始不确定范围，不是长期同步保证。它不处理漂移、暂停后追时、节点重连、故障接管或 guest 主动修改 TSC。不能根据打印出 `SSI_CLOCK_TARGET` 就标记时钟场景通过。

## 新发现与下一步

第一次候选双节点运行的最短往返为 57120 ns，估计初始不确定范围为 28560 ns。随后完成了八轮跨 CPU 时钟采样、四个定时器、SSH 内存压力测试、1 MiB SFTP 和客体主动关机，两边 QEMU 退出 0，总耗时约 958 秒。候选二进制 SHA-256 为 `6f70ff7676f3ff711924e5c933ade1ee41b74932eaea0c4078c295b052ccf1b4`，完整脱敏记录见 [候选证据](evidence/ssi-clock-offset-20261105.txt)。

仍不能宣布修复成功：启动 watchdog 记录 `kvm-clock wd_now=0`，关闭阶段仍有 DSM 连接错误。CPU 3 的 20 ms 睡眠实际耗时约 1.88 秒，探针只是没有提前返回，不能标为实时性或调度延迟通过。迁移采样间隔很长，也可能掩盖小于调度延迟的时钟偏差。当前只有一次双节点候选运行，重复启动与长期漂移尚未验收。

内核 `kvm_setup_guest_pvclock()` 通过 `gfn_to_pfn_cache` 中的宿主指针直接写入版本、时间和 flags；当前函数及缓存层没有显式 DSM 所有权获取。客体允许从另一 vCPU 读取这些记录，而多个记录可能共享一个页面。这是需要独立复现的缓存一致性风险，**尚不能仅凭源码和这次日志认定它是唯一根因**。

后续先为两个 KVM 实例交替更新同一 pvclock 页编写真实接口探针，再验证带奇偶版本的 DSM 更新路径。需要同时检查无撕裂、无零读数、跨 CPU 单调性和定时器，不能通过隐藏 watchdog、关闭 clocksource 检查或强设 `tsc=reliable` 获得通过。

## 运行探针

```sh
x86_64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static \
  scripts/ssi-lab/guest-clock.c -o guest-clock
# 通过已校验主机密钥的 SSH/SFTP 上传到隔离客体后执行。
ssh <isolated-guest> /tmp/guest-clock > clock.log
python3 scripts/ssi-lab/check-clock.py clock.log
python3 scripts/ssi-lab/check-ssh-boot.py node0-serial.log \
  --host-log node0-host.log --host-log node1-host.log
```

探针要求四个 CPU，同一线程按 `0,2,1,3` 顺序迁移八轮，读取串行化 TSC、MONOTONIC、MONOTONIC_RAW、BOOTTIME，并在最后一轮逐 CPU 检查 20 ms 睡眠没有提前返回。它不设置最大延迟通过门槛，实际延迟原样输出；不验证实时调度、长期漂移或频率精度。任何一次倒退均返回失败。

新增规格见 [160-ssi-clock.feature](../features/160-ssi-clock.feature)。`140-ssi-workspace.feature` 的完整 SSH 场景与时钟稳定场景仍未通过。

保存日志后，两台专用实验节点均正常重启回原版 `6.8.0-147-generic`。已核对管理 SSH、`/lib -> usr/lib`、无 QEMU/DSM 残留和无待执行的 GRUB 一次性启动项；公司数据、业务 VM 和隧道配置未改动。

## PF6 后续实验

下一轮真实 KVM 探针已经复现 pvclock 在页面归远端后仍写本地副本的缺陷。增加 DSM 写权限获取后，两次新建双节点实例均通过受控页面交接。完整客体测试未再观察到旧的零读数和 TSC 不稳定告警，但 RTC 读取失败、watchdog 跳过检查、最高约 6.97 秒的定时器延迟及关闭连接错误仍存在。修复与证据见 [pvclock 页面实验](ssi-pvclock.md)，本页的旧记录保留用于前后对照。
