# 共享 Linux 客体的 SSH 工作区实验

2026-11-05。本实验继续验证 `140-ssi-workspace.feature`，使用官方 Alpine Linux `6.12.115-0-virt` 内核与 OpenSSH `10.0_p1`。原 Rust 任务调度器没有因此变成 SSI 产品；这里是独立的 GiantVM 实验客体。

## 镜像与隔离

从固定 SHA-256 的 Alpine virt 3.22.8 x86_64 ISO 提取内核、网络模块、BusyBox、OpenSSH、SFTP 与运行库。唯一自定义初始化程序负责挂载客体自己的 proc/sys/dev/tmpfs、配置 QEMU 用户网络并启动 sshd，不修改发行版内核或 OpenSSH。

- 不挂载磁盘、宿主目录、Docker socket 或公司数据。
- 客体根目录与 `/tmp` 都在内存，关机后文件消失。
- 只导入操作者显式指定的公钥，关闭密码与键盘交互认证。
- 每次构建生成实验 SSH 主机密钥；通过已认证构建通道核对公钥后写专用 known_hosts，客户端始终启用严格校验。
- 节点零只监听回环 `127.0.0.1:22230`，客户端通过已有管理 SSH 跳转。QEMU 用户网络启用 `restrict=on`，不把客体直接接到公司 LAN。
- 运行有固定最长时间，当前不是长期在线服务，不承诺已有会话故障后续接。

构建和运行入口见 [实验工具](../scripts/ssi-lab/README.md)。镜像中含实验 SSH 主机私钥，不上传公开仓库；公开的是生成脚本与脱敏验收记录。

## 已完成的单节点对照

在 `pf2` 宿主上用普通 KVM 启动 4 vCPU、256 MiB 客体，通过原生 OpenSSH 公钥登录，得到：

```text
sshpool-ssi-guest
6.12.115-0-virt
4
uid=0(root) gid=0(root) groups=0(root)
rootfs on / type rootfs
proc on /proc type proc
sysfs on /sys type sysfs
devtmpfs on /dev type devtmpfs
devpts on /dev/pts type devpts
tmpfs on /dev/shm type tmpfs
tmpfs on /tmp type tmpfs
tmpfs on /run type tmpfs
```

SSH 会话内执行 `/bin/ssi-proof`：同 PID 四线程、两次分配、每次八轮页面交接与原子计数 4096，检查器通过。使用 OpenSSH 的 SFTP 传输 1 MiB 确定性数据并取回，`cmp` 一致，SHA-256 为 `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`。仅删除该实验文件，随后在客体执行关机，QEMU 正常退出。e1000 与后续 virtio 两份镜像均分别通过该单节点对照，当前 virtio 会话输出见 [SSH 对照证据](evidence/ssi-ssh-control-20261105.txt)。**这一段是单节点对照，不能当成跨节点 SSH 验收。**

首次镜像因构建环境的 umask 使 `/var/empty` 可被组写入，OpenSSH 拒绝启动；生成器已显式设为 0755，并去掉该 Alpine 构建不支持的 `UsePAM` 配置。没有通过关闭主机密钥或权限检查来绕过错误。

当前镜像文件 SHA-256：

```text
guest-vmlinuz:
8ce908a8cb28d55adcacacf8a16609fa400e07a8826f0084ae5b13b8cb91b9ab
guest-ssh-initramfs.cpio.gz:
80e34ee3564b9e84921d5f36c012244dd7de2d5a0de2565bbd0d044266ec62fc
```

initramfs 包含每次新生成的主机密钥，因此不同构建不会得到相同哈希；同一次构建分发给两节点的文件必须相同。

## 双节点与剩余门槛

双节点使用早期 e1000 镜像（哈希 `542db1b4ba902f7c0e2dcbebd3804d17da0ae843d53700d1d82f9d44272fe315`），上线四个 vCPU 并进入 `/init`，但完整 SSH 验证失败。Alpine 客体启动期间记录到 `hrtimer_forward` 的计时器队列告警，且 TSC 检查报告偏移；e1000 随后因 EEPROM 校验失败清空 MAC 地址，`ip link` 无法启用设备，PID 1 退出导致客体 panic。原始日志已保留，不能将这一轮标记为成功。

单节点对照没有上述网络错误。当前生成器改用发行版内建的 virtio PCI 总线和原版 `failover/net_failover/virtio_net` 模块，QEMU 选择 legacy virtio 与传统 INTx 中断，继续独立验证。没有忽略 EEPROM 校验或把无效 MAC 强行改回。宿主没有出现此前的页引用或权限告警，但这不能证明客体计时和调度正确，也不能据此部署数据库。

后续必须验收从 SSH 会话启动的同一进程确实在两节点执行、文件传输闭环、客体时钟与计时器行为。Docker、持久磁盘、数据库、跨物理机、超单节点驻留内存和故障恢复仍然没有通过。

## 后续网络实验：首次登录成功，完整场景仍失败

同日继续测试的结果如下；脱敏输出见 [网络实验记录](evidence/ssi-ssh-network-20261105.txt)。

| 组合 | 单节点 | 双节点 |
| --- | --- | --- |
| Alpine 内核 + virtio | SSH、内存测试、SFTP 通过 | 启动出现四 CPU 软锁死及 `hrtimer_forward` 告警，SSH 未通过 |
| Ubuntu 内核 + virtio、原 QEMU | SSH、内存测试、SFTP、关机通过 | 四 CPU 上线、sshd 监听，但 virtio 控制队列报错，SSH 握手超时 |
| Ubuntu 内核 + virtio、候选 QEMU 补丁 | SSH、内存测试、SFTP、关机通过 | SSH 认证成功并返回主机名；之后 RCU 停顿，压力测试与 SFTP 均未完成 |

Ubuntu 对照使用此前内存测试的原版 `6.8.0-147-generic` 内核和同一 Alpine 用户态；该内核内建网络驱动，因此不加载 Alpine 模块。这里是缩小问题范围的对照，不是宣布旧内核已经解决稳定性。

发现 virtio 队列缓存直接使用本地 RAM 指针，存在绕过 DSM 获取的路径。独立候选补丁已构建并实测，但只保存在 [experiments](../scripts/ssi-lab/experiments/README.md)，不加入默认补丁集。双节点中还观察到宿主 `mark_page_dirty_in_slot` 告警、客体 TSC 不稳定和 RCU 停顿。首次登录的输出只有 `hostname`，没有完整的内核/CPU/压力测试结果，不能标为四线程 SSH 场景通过，也不能认定停顿由压力测试触发。

两边运行到 900 秒限时终止，管理 SSH 进程退出 255，不能等同于客体正常关机。保存原始日志后，已确认两节点没有 QEMU 残留，并重启回原版 `6.8.0-147-generic`：管理 SSH 可用、`/lib -> usr/lib` 保持完整、GRUB 无待执行的一次性启动项。业务 VM、现有数据库与公司目录未参与实验。

新增 `check-ssh-boot.py` 检查唯一内核/四 CPU/sshd 就绪顺序，并拒绝内核告警、TSC 偏移、RCU 停顿、网络和 DSM 错误。`--host-log` 可重复传入两节点本轮日志。它只是一道日志门槛；即便通过，仍需要完整 SSH 会话、双节点执行证据、SFTP 往返、正常关机和人工核查日志完整性。

当前最先需要解决的是设备访问一致性、非 vCPU 写入的脏页记账和时钟/RCU 停顿，然后才有条件继续持久磁盘、Docker、数据库与故障恢复。

## PF5：跨节点 SSH 工作负载和 SFTP 通过，完整场景仍未通过

同日进一步定位并修复了 DSM 页号与新版 KVM 锁位冲突，以及无 vCPU 设备写入遗漏 dirty bitmap；细节和真实接口探针见 [设备内存实验](ssi-device-memory.md)。QEMU 候选同时修正了短 DMA 后解除固定范围不足的问题。三个新补丁仍放在实验目录。

PF5 两节点使用一致哈希的运行时启动同一个四 CPU 客体，普通 SSH 会话完整返回主机名、`6.8.0-147-generic`、`nproc=4`；同一 PID 的四线程完成两次内存分配、每次八轮页面交接，原子计数均为 4096。两节点采样确认分别执行 vCPU 0/1 和 2/3。1 MiB 文件通过 SFTP 上传、下载、删除，回取内容与原始数据逐字节一致。SSH 与 SFTP 客户端均退出 0。原始输出的脱敏摘录见 [PF5 SSH 证据](evidence/ssi-ssh-pf5-20261105.txt)。

本轮没有再次观察到 RCU 停顿、virtio 控制队列失败或宿主脏页 WARN，但这不等于所有竞态已消除。启动仍报告 276692586 个周期的 TSC warp，日志检查器明确拒绝。后续关机请求未能在 900 秒运行上限前完成，两边由 timeout 终止，管理 SSH 退出 255，宿主记录到终止期间的 `ktcp_receive ret -4`。**没有正常关机证据，不把它写成双节点完整验收通过。**

当前可复现的进展是跨节点客体内的 SSH 计算与网络文件传输。剩余优先项为 TSC/pvclock 协调、完整关机、重复冷启动与设备错误路径，之后才能评估持久磁盘、Docker、数据库和故障恢复。PF2 的既有小测试记录保留，但新增探针已经证明其映射清理和设备脏页存在缺陷，不能把 PF2 当作稳定部署基线。

保存证据后，两实验节点已正常重启回 `6.8.0-147-generic`，核对管理 SSH、`/lib -> usr/lib`、GRUB 无待执行启动项和无 QEMU/DSM 残留。业务 VM、公司文件和现有 sub2api/数据库未改动。
