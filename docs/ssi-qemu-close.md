# 限定 QEMU 配置的全节点关闭

PF28 与协议六 QEMU 候选完成了两台专用实验 VM 上的正常 DSM 关闭接线：真实 Ubuntu 客体执行 SSH、内存与 SFTP 后关机，两端 QEMU 退出零，原生跟踪确认每条连接完成握手，根线程在关闭返回之前回收。另一个真实 virtio-blk 客体正常写入后也通过；EIO 与反向 ENOSPC 保留错误并让两端退出一。

这是同一物理 ESXi 上、四 vCPU、每节点两个本地 CPU、单个 virtio-net 或 virtio-blk 的限定实验。双节点客体仍出现 `clocksource: Long readout interval, skipping watchdog check` 和 `workqueue: ... hogged CPU`。**完整 SSI 工作区、跨物理容量、时钟恢复和持久化仍未验收。** 实验候选不进入默认安装或 `ssi-launch` 的运行时准入。

建议依次看 [场景](../features/170-ssi-transport.feature)、[QEMU 补丁](../scripts/ssi-lab/experiments/qemu-global-close.patch)、[关闭检查器](../scripts/ssi-lab/check-qemu-close.py)、[块设备检查器](../scripts/ssi-lab/check-close-devices.py) 和 [完整证据](evidence/ssi-qemu-close-20261108.json)。内核协议与故障矩阵见 [PF28 原生关闭](ssi-kernel-close.md)。

## 接线与顺序

候选基于先前的 `qemu-system-x86_64-router-startup-2` 研究源码，保留块层错误优先级与设备解除修复。新增代码归属 GPL QEMU 实验，不能当作本仓库产品运行时。

1. 仅分布式实例进入关闭接线，要求 `SSHPOOL_LAB_GLOBAL_CLOSE=1`、精确 PF28 内核和本轮 CPU 拓扑。单节点沿用原清理流程。
2. 收集并持有已实现的 virtio 设备对象引用，拒绝 IOThread、vhost 和未经验证的 virtio 类型。先收集再销毁，避免遍历时改变对象树。这不是任意 PCI/后台生产者的完整白名单，证据仅覆盖保存的启动命令。
3. `vm_shutdown()` 停止本地 vCPU 和执行刷盘；失败或残留块设备 I/O 错误立即退出一。最终刷盘返回零不能覆盖此前未恢复的写入错误。
4. 两端交换 `QUIESCE` 并核对双向确认，确认所有 vCPU 停止和此前路由报文已经处理。节点零的序号成为双方内核关闭 generation。
5. 停止 virtio 状态并 unrealize；清理块层、网络和其他既有资源；退出通知仅执行一次；等待 `drain_call_rcu()`。此时路由仍开放，设备清理可以完成已有内存访问和中断处理。
6. 双向最终 `DRAIN` 完成后，查询真实 KVM 页引用，要求 active/read/write/error 全零，再调用 `KVM_DSM_CLOSE`。
7. 原生关闭成功之后才断开路由。设备清理、两个屏障和原生协议共用一个进程级三十秒最终期限；内核调用自身设置十五秒上限。未把尚未执行的全部挂起故障组合列为已验证。

路由版本由五升至六，避免不同关闭协议混用。序号绑定本次连接与屏障，不提供网络身份认证。实验仅使用两台专用 VM 之间临时放行的端口。

## 真实观测

| 场景 | 双端结果 | 证据边界 |
| --- | --- | --- |
| 单节点 Ubuntu 对照 | QEMU 退出 0 | SSH、三轮时钟、四线程内存、用户态 PAUSE、1 MiB SFTP 完成 |
| 双节点 Ubuntu 关机 | QEMU 退出 0 / 0；原生关闭约 13.82 / 13.94 ms | 每端两条入站连接，先回收根线程；仍有 watchdog 与 workqueue 告警 |
| 正常 virtio-blk 写入后 QMP quit | QEMU 退出 0 / 0；原生关闭约 13.93 / 13.87 ms | 真实 4096 字节写入、设备销毁、零引用和原生关闭全部通过 |
| virtio-blk EIO | QEMU 退出 1 / 1 | 失败请求仍占一条队列；主节点保留 failed，副节点保留屏障断连；没有正常关闭声明 |
| 交换两台 VM 角色后 ENOSPC | QEMU 退出 1 / 1 | 保留 nospace 与故障销毁记录；没有正常关闭声明 |

三轮时钟的最大定时器耗时：单节点 20.26 ms，双节点 53.81 ms，均低于既有 250 ms 门槛。这是本轮有限样本，不能覆盖启动 watchdog、长期漂移或此前失败，也不能据此推断性能相加。

块实验使用各节点独立的 sparse 64 MiB 文件，在偏移 1 MiB 写 4096 字节。主节点实际 virtio 请求、QMP 错误事件、队列、磁盘 SHA 和进程退出互相核验。副节点的独立空盘不是副本。正常文件读回不证明掉电持久性、fsync 崩溃语义、数据库恢复或 Ceph。

错误实验不执行 `KVM_DSM_CLOSE`：清理早段已发现 I/O 错误，进程退出后走故障销毁，内核保留 `-4` / `-104` 等记录。不得把线程最终回收当作正常握手通过。

## 复核与来源

QEMU 二进制 SHA256：`dee8df74fb42f472a8741d991f2cdcbd748ecc1107e68e510860ea726a39938f`。PF28 内核 SHA256：`d9d2d6f63d6fe6f92d4c64e78782254133861db562c2e6ad8bf4aecb2f4fe301`。

证据包含编译日志、原始与编译源码、补丁哈希、实际部署的采集脚本哈希、执行驱动、QMP、客体串口、完整宿主日志、原生跟踪及防火墙前后快照。测试会在临时目录重放补丁并逐字匹配编译源码：

```bash
python3 -m unittest discover -s scripts/ssi-lab -p 'test_kernel_close.py' -v
python3 -m unittest discover -s scripts/ssi-lab -p 'test_qemu_close.py' -v
```

独立检查器可直接读取证据中一个 `workspace_runs` 双节点条目或一个 `block_runs` 条目。前者运行 `check-qemu-close.py <条目.json>`，后者运行 `check-close-devices.py <条目.json>`。它们不会通过伪造 poweroff 记录把 QMP quit 混成客体关机。

关闭采集器 `trace-kernel-close.py` 只允许独占 PF28，要求明确命名的实验 QEMU、正确 DSM 节点和空跟踪环境；开启跟踪后输出 ready，收到 stop 才结束观测。块设备入口 `probe-close-devices.py` 复用既有客体采集器，仅允许本轮内核和 `--pin-query none`。这里空诊断采样不代表零引用；零引用来自关闭时的真实 KVM 查询与对应日志。

实验完成后，两台 VM 恢复原版 `6.8.0-147-generic`。机器身份、原启动文件哈希、GRUB 默认项与空 next_entry、`/lib -> usr/lib`、原防火墙均核对一致。恢复后重新检查 QEMU/DSM 进程、临时跟踪和实验 TCP 均为空；恢复结果保存在本次证据内。
