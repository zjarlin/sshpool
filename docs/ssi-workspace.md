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
