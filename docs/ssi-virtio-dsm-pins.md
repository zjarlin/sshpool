# 真实 virtio 请求的 DSM 引用与暂停边界

在两个 PF24 实验节点组成的同一 Linux 客体中，已经复现并修复了 virtio-blk 管理销毁遗漏重试请求的问题：写入 EIO 后设备消失，旧版仍持有两个读引用和一个写引用；候选在销毁前排空并取消重试请求，原生 KVM 查询确认引用归零。ENOSPC 交换两台实验 VM 的逻辑角色后也通过。**两台 VM 仍属于同一物理 ESXi；尚未实现跨物理容量聚合、Ceph、数据库或接管。**

先看 [场景](../features/150-ssi-device-memory.feature)，再看 [引用清理补丁](../scripts/ssi-lab/experiments/qemu-virtio-blk-unrealize.patch)、[暂停补丁](../scripts/ssi-lab/experiments/qemu-remote-pause.patch)、[采集器](../scripts/ssi-lab/probe-virtio-dsm-pins.py)、[检查器](../scripts/ssi-lab/check-virtio-dsm-pins.py) 和 [原始回复及实测证据](evidence/ssi-virtio-dsm-pins-20261107.json)。QEMU 补丁为 GPL-2.0-or-later，只用于独占研究环境，不进入默认安装。

## 原生观测与实际修复

PF24 的 VM ioctl 要求调用者与 QEMU 属于同一个内存地址空间，因此外部进程即便取得 VM fd，也不能直接代替 QEMU 查询。单独的 [诊断补丁](../scripts/ssi-lab/experiments/qemu-device-pins-probe.patch) 在 QEMU 内执行只读 `KVM_DSM_PIN_STATUS`。它要求显式环境变量、精确 PF24 内核、KVM、四个总 vCPU／两个本地 vCPU，且无 SHM；查询不改变引用。普通候选已去掉此诊断入口。

每个生命周期快照保存两次独立查询及对应的完整 QMP 区间。检查器要求返回成功、ABI 版本一、活动固定操作为零、错误与保留字段为零，再核对读写计数。查询失败不等于零引用。实际 guest virtio 驱动、原生请求 trace、`BLOCK_IO_ERROR`、队列 `inuse`、磁盘内容和进程退出码共同验证该链路。

旧 `virtio_blk_device_unrealize()` 只调用 `blk_drain()`，没有处理 `s->rq` 中保留的失败请求。候选把已有 reset 路径的“排空后遍历重试队列、detach、释放”提取为共用函数，供 reset 和 unrealize 调用；必须在销毁 virtqueue 和互斥量之前完成。reset 原有的 dataplane 停止断言和写缓存恢复仍保留在 reset 中。

客体沿用真实 Linux 及内置 virtio-blk 驱动，无网络或宿主目录挂载；每台节点每次新建独立目录与 64 MiB 稀疏文件。逻辑节点零拥有活动块设备，在偏移 1 MiB 处直接写入 4096 字节并 fsync；节点一的 virtqueue 未配置，其磁盘一直为零。**这两份文件不是存储副本。**

| 实验 | 错误后的原生引用 | 销毁后／关闭前 | 实际退出 |
| --- | --- | --- | --- |
| 已修暂停、未修销毁的 EIO 对照 | 读 2／写 1 | 读 2／写 1，复现泄漏 | 两端 1 |
| 修复后 EIO | 读 2／写 1 | 两端均为零 | 两端 1 |
| 修复后 ENOSPC，交换实验 VM 角色 | 读 2／写 1 | 两端均为零 | 两端 1 |
| 修复后正常写入再销毁 | 零 | 零，写入内容匹配 | 两端 0 |
| 修复后正常写入再关闭 | 零 | 零，写入内容匹配 | 两端 0 |

另有暂停补丁单独的正常写入对照，两端退出零。六组完成采集均没有强制清理或残留任务；基线泄漏被明确保留为基线缺陷，并非功能通过。EIO／ENOSPC 最后一次 flush 都成功，但后端仍保留错误，候选继续退出一。取消请求没有恢复未写入的数据。

## 暂停缺陷和未通过的生命周期

最初两次真实客体正常写入后，QMP `stop` 都超时。GDB 栈显示主线程在 `pause_all_vcpus()` 等待，本地 CPU 已进入等待，两个远端占位线程却仍等待另一条件变量。额外的 CPU 链表符号读取失败，因此没有采集到相应 flags，不据此推断标志值。

暂停补丁仅在尚有未停止的远端占位线程时，唤醒现有远端条件变量；占位线程收到 `cpu->stop` 后确认停止。保留全部 vCPU 停止检查，也避免在占位线程已经退出后再等待一次不存在的确认。这解决本进程的暂停阻塞，**实际另一台机器仍必须由协调器另发 stop**。原始快照也显示，节点零因 I/O 错误停止时，节点一仍在运行，直到协调器显式停止它。

四组未完成记录全部保留并被检查器拒绝：

- 两次上述暂停阻塞，其中一次带真实线程栈。
- 暂停修复后的恢复尝试，第一次 `cont` 就触发既有的 `SSI clock candidate supports cold start only` 检查。计划的三轮恢复没有完成，不删除检查来假装支持恢复。
- 修复后的 EIO → reset → quit：两端复位成功、队列与原生引用归零，但副节点没有随主节点退出，40 秒后采集器强制清理。因此整个 reset 生命周期未通过。副节点未安装 GDB，未取得该次退出栈。源码仍有收到 RESET 后退出路由接收循环的路径，这是后续排查点，不能仅凭源码宣称已确认所有等待原因。

## 普通运行时与回归

诊断候选 SHA256 为 `30da605a7cfa058512ded7d134123f2f8f3b1f8bcee5cd1a8a5f9d5db383e467`；去掉诊断入口、保留两个修复的普通候选为 `f2fd12e514efdeb7493dd482f4ab343dce72289b8a90b131aebe84e4dddd4540`。补丁零 fuzz 重放与实际源码一致，编译日志无告警。普通候选各做一次单节点和双节点完整 SSH 客体回归，登录、同进程共享内存、用户态 PAUSE 和 1 MiB SFTP 均完成；三轮计时最大分别为 20.20 ms 和 125.22 ms，保留原 250 ms 门槛。QEMU 退出零，但双节点宿主仍有 DSM 关闭错误，完整 SSI 仍未通过。

实验结束，两台 VM 均恢复 `6.8.0-147-generic`；原引导文件哈希、防火墙、机器身份与 `/lib` 链接核对一致，没有残留 QEMU、DSM 或跟踪任务。业务主机、公司磁盘与隧道未改动；新增物理节点仍只做过 SSH/KVM 预检，没有加入 SSI。

后续必须分别完成全局暂停和时钟恢复、reset 后路由生命周期、所有设备生产者停止、KVM 封闭及带代际的 CLOSE/ACK。既有 DSM 关闭错误仍不能被 QEMU 退出零掩盖。文件读回也不证明掉电持久性；跨物理主机、超单机内存、分布式持久盘、Docker、PostgreSQL、Redis 和 sub2api 都仍未交付。

## 复现入口

在两台独占 PF24 实验 VM 上各启动一个采集器，核对相同二进制和客体镜像哈希，使用不同逻辑节点编号及两台实验节点地址：

```sh
python3 probe-virtio-dsm-pins.py \
  --qemu /lab/qemu-diagnostic --require-sha256 <诊断二进制SHA256> \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf24 --firmware /lab/pc-bios \
  --guest-kernel /lab/guest-vmlinuz --guest-kernel-sha256 <客体内核SHA256> \
  --initramfs /lab/guest-block-initramfs.cpio.gz --initramfs-sha256 <initramfsSHA256> \
  --node 0 --peers <实验节点A地址> <实验节点B地址> \
  --error 5 --directory /lab/new-case
```

节点一使用 `--node 1 --error 0`。标准输入按行接收 JSON，标准输出返回相应结果：两边 ready 后，由节点零依次执行 `{"op":"wait_ready"}`、`{"op":"write"}`；轮询 `{"op":"status"}` 等待 io-error，双方保存 `{"op":"snapshot","phase":"after_error"}`，分别 `{"op":"qmp","name":"stop"}` 并再次快照。双方 `{"op":"qmp","name":"qom-set"}` 销毁实验设备后保存 after_unrealize 和 before_quit；节点一发送 `{"op":"wait_exit"}`，节点零发送 `{"op":"quit"}`。正常对照在写入后使用 `wait_write` 等待 fsync 完成。完整 ready 快照与步骤顺序见公开证据中的 actions。

每个采集器写入自己的 `result.json`。协调端必须保留两边的原始 QMP、串口、stderr、宿主日志与实际退出码，并确认无残留任务；再将 `{ "run": {...}, "records": [节点零记录, 节点一记录] }` 交给 `check-virtio-dsm-pins.py`。检查器只接受已记录哈希的实验版本与该组协议，不将成功采集等同于完整 SSI 验收。
