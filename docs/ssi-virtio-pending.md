# 真实 virtio 写入错误与关闭状态

真实 Linux 客体写盘失败后，QEMU 的最终刷盘仍可能成功。上一轮只检查 `vm_shutdown()` 的返回值，因此会在请求尚未完成、磁盘内容未写入时退出零。本轮在最终刷盘之后检查各 BlockBackend 保留的 I/O 状态；仍为 `failed` 或 `nospace` 时向 stderr 报错并退出一。正常写入和成功重试保留退出零。

先看 [场景](../features/150-ssi-device-memory.feature)，再看 [候选补丁](../scripts/ssi-lab/experiments/qemu-shutdown-iostatus.patch)、[采集器](../scripts/ssi-lab/probe-virtio-pending.py)、[检查器](../scripts/ssi-lab/check-virtio-pending.py) 和 [实际证据](evidence/ssi-virtio-pending-20261106.json)。补丁应用在 `qemu-shutdown-flush-error.patch` 之后，许可 GPL-2.0-or-later，默认构建仍不自动启用。

## 实际链路与结果

两台同一 ESXi 上的独占 VM 均保持原版 `6.8.0-147-generic` 内核，每次只运行一个 QEMU。客体使用真实 Ubuntu Linux 内核及内置 virtio-blk 驱动，无网络、无宿主目录挂载。每次探针独占新目录及新建的 64 MiB 稀疏文件，客体检查磁盘序列号和大小，再从偏移 1 MiB 处以直接 I/O 写入 4 KiB 的 `0x5a`，随后执行 fsync。并未写入任何已有磁盘。

块层为 `raw → blkdebug → file`，写回缓存保持 flush 有效。原生 `pwritev` 事件只注入一次 EIO 或 ENOSPC，设备错误策略为 `stop`。原生 virtqueue、virtio 请求跟踪及 QMP `BLOCK_IO_ERROR` 证明请求经过了客体驱动、描述符和设备处理器；没有通过 HMP 直接写 BlockBackend。

每台 VM 分别执行旧版和候选的五类场景，共 20 次有效实验。节点零注入 EIO，节点一注入 ENOSPC，均保留各自的无故障对照。

| 动作 | 设备及数据观察 | 旧版退出码 | 候选退出码 |
| --- | --- | ---: | ---: |
| 正常写入后关闭 | 客体写入/fsync 返回成功，队列 inuse 为零，文件内容匹配 | 0 | 0 |
| 错误后暂停并关闭 | `io-error`，一个请求仍未完成，目标内容仍为零 | 0 | 1 |
| 错误后复位并关闭 | inuse 清零，但后端错误保留；目标内容仍为零 | 0 | 1 |
| 错误后销毁设备并关闭 | 设备不再可查询，后端错误保留；目标内容仍为零 | 0 | 1 |
| 错误后继续运行 | 同一请求重试成功，inuse 清零、状态回到 ok、内容匹配 | 0 | 0 |

以上各次最终 `vm_stop_flush_all` 均返回零。候选错误退出不是因为最后一次 flush 失败，而是保留了尚未恢复的设备错误。复位只能取消请求，不能把未写入的数据变成已持久化。销毁通过管理接口 `qom-set realized=false` 发起，不代表客体 ACPI 热拔插已验收。

`blk_iostatus` 只保留后端现有的分类状态，无法还原所有历史错误的精确 errno。成功 `cont` 会清除旧状态并重试；显式删除后端、其他错误策略、多个设备并发、重试中再次停止等情况尚未验收。本轮不新增永久错误日志，也不声称覆盖所有历史 I/O 错误。

## 复现与采集边界

客体 init 源码为 [guest-block-init.sh](../scripts/ssi-lab/guest-block-init.sh)。从已核对来源的 Alpine BusyBox/musl 构建目录只复制 `bin/busybox`、`lib/ld-musl-x86_64.so.1` 及 `lib/libc.musl-x86_64.so.1` 到新暂存目录，建立 `bin/sh → busybox` 和空的 `dev`、`proc`、`sys`，将脚本保存为可执行的 `/init`，将 4096 字节 `0x5a` 保存为 `/payload`，使用 newc cpio 和 gzip 打包。本次重打包的成员及哈希已记录；没有复制源镜像中的 SSH 密钥、用户凭据或公司数据。客体内核须内置 virtio PCI 和块设备驱动。

```sh
python3 probe-virtio-pending.py \
  --qemu /lab/qemu-system-x86_64-iostatus-1 \
  --require-sha256 <候选实际SHA256> --require-kernel 6.8.0-147-generic \
  --firmware /lab/pc-bios --guest-kernel /lab/guest-vmlinuz \
  --guest-kernel-sha256 <客体内核实际SHA256> \
  --initramfs /lab/guest-block-initramfs.cpio.gz \
  --initramfs-sha256 <镜像实际SHA256> \
  --error 5 --action quit --directory /lab/new-case
```

`--error` 为 `0|5|28`，`--action` 为 `quit|reset|unrealize|resume`。探针先核对内核、运行时哈希与 KVM 权限，拒绝已有目录或能改变 QEMU 参数解析的目录名。成功采集不等于功能通过：检查器还核对实际退出码、设备错误、原始 QMP 与快照的一致性、原生请求及磁盘内容。超时、进程被强制清理或缺失事件均拒绝验收。

三个早期采集失败均保留：一次使用错误的 sysfs 序列号路径，客体拒绝写入并 panic；一次 `-no-reboot` 把 QMP reset 变成关闭；一次销毁后误把“没有 virtio 设备”的原生查询结果当成采集故障。后两者修正采集器后重跑，未改动被测设备实现。另有一个因缺失 `blk_name` 声明产生编译告警的候选被拒绝，未执行；补齐正确 API 头文件后编译无告警。最终补丁零 fuzz 重放与实际编译源码一致。

## 尚不能推出的结论

本轮真实客体设备路径已覆盖，但**没有启用双节点 DSM，也没有读取 DSM pin ABI**。inuse 清零或设备消失，不等于页固定引用已释放。尤其 unrealize 是否遗漏 `s->rq` 清理仍需原生 DSM 引用观察，不能凭本次结果直接宣称泄漏或已修复。

本轮只修改并验证独立实验候选，未进行该候选的完整双节点工作区回归。下一步需要在 PF24 实验环境中观察真实请求的页引用，再验证生产者停止、KVM 封闭和全局 CLOSE/ACK。上一轮双节点的 `ktcp_receive` 关闭错误仍未解决。

文件读回不证明宿主断电持久性，独立实验文件也不是分布式存储副本。Ceph、跨物理容量聚合、Docker、PostgreSQL、Redis、sub2api 和故障接管均未交付。新增物理主机仍仅为 SSH/KVM 预检候选。实验结束再次核对两台原版内核、原引导文件、防火墙及无残留 QEMU/DSM/跟踪任务；本轮未更换宿主内核，也没有触碰业务主机或业务盘。
