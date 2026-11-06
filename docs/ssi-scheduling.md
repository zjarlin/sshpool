# SSI 调度与 ESXi 资源预检

2026-11-06。PF11、QEMU、Ubuntu 客体和 initramfs 保持原哈希。本轮针对完整客体的长停顿增加调度观测，并发现、取消了两个专用实验 VM 的 CPU 总限额。研究对象仍是同一 ESXi 上的两个 VM，不代表不同物理机的资源聚合或故障接管。Ceph、持久盘、Docker 和业务数据库尚未接入。

## 资源限制必须先核对

原实验配置给每台 VM 分配 2 个 vCPU、1 GiB 内存，却把每台 VM **全部 vCPU 合计**限制为 2000 MHz。ESXi 在一个 20 秒样本中报告节点零 `cpu.ready=14501 ms`、`cpu.maxlimited=14486 ms`，可直接确认存在人为限速。不能因为宿主 Linux 的 steal 为零就排除虚拟化限速；也不能把 ready、maxlimited 和 costop 相加，它们存在重叠，而且 VM 指标汇总多个 vCPU。

本轮仅将两个实验 VM 的 `cpuAllocation.limit` 从 2000 改为 -1。配置修改前后保存记录并重新读取，核对 vCPU 数量、CPU 预约和份额、内存分配、设备列表、归属注解和资源池均未改变。内存仍为 1 GiB 全额预约，研究内核仍只通过一次性启动选择。

`scripts/ssi-lab/check-esxi-resources.py` 是只读前置检查：指定精确 MoID 和实验归属注解，采集 VM 与父资源池限额、物理宿主身份、ready/maxlimited/costop/CPU 使用量。密码通过终端隐藏输入，不接受命令行密码。运行环境需要 `pyvmomi`。

```sh
python3 scripts/ssi-lab/check-esxi-resources.py \
  --host esxi.example.test --user lab-reader \
  --vm vm-101 --vm vm-102 --annotation owned-ssi-experiment \
  --output new-resource-snapshot.json
```

私有实验 ESXi 的自签证书须明确选择 `--insecure`；默认验证 TLS。退出 2 表示有资源限额、历史样本限速或指标不完整；旧限额刚取消时，最近八个样本仍可能包含限速。检查器不会自动修改配置。根资源池由 ESXi 汇报主机容量，不把它当作人为子池限额；VM 内存上限等于配置容量也不视为额外缩减。通过只代表这些检查通过，不保证网络、磁盘、调度或长期负载稳定。

## 调度记录的解释

`trace-dsm-scheduling.py` 在独立 trace instance 中记录目标 QEMU/DSM 线程的唤醒、切换、迁移、TCP 接收及 MMU/TLB 操作，并保存线程起止身份和心跳。它不改变线程优先级或亲和性。只有明确指定内核、独占且有归属命名的 QEMU 才允许附加。

```sh
sudo python3 trace-dsm-scheduling.py --attach-pid QEMU_PID --node 0 \
  --require-kernel EXACT_KERNEL --output NEW_TRACE.json
```

需要同目录的 `trace-teardown.py`。控制器等待 `trace_ready`，完成测量后从标准输入发送 `stop`；最长窗口 360 秒。默认每个宿主 CPU 64 MiB 缓冲区，可用 `--buffer-kib` 在 8–64 MiB 内指定。多个节点必须先全部停止采样，再导出大文件，避免导出操作污染另一个节点。停止和清理必须成功，离线检查才接受记录。

```sh
python3 scripts/ssi-lab/check-dsm-scheduling.py NODE_SCHEDULING.json \
  --latency-trace NODE_LATENCY.json
```

分析器拒绝事件丢失、探针遗漏、时间倒退和 PID 复用。等待拆成 `runnable`、`sleep:*`、`scheduled` 和 `unknown`：`scheduled` 包含中断与虚拟化停顿，不能当作有效 CPU 计算；窗口边界保持未知，不外推。TCP 接收可能来自空闲监听器或 QEMU 控制连接，不能把最长一次接收直接叫作一次 DSM 请求延迟。可选的 latency 记录用于对齐具体响应接收。

原 32 MiB/CPU 缓冲区在全抢占和首次取消限额实验中发生溢出，保留为失败采样，不能从丢失窗口计算调度等待。扩大缓冲区是仪器调整，不是内核运行时性能修复。应用与完整工作区结果须另由无跟踪测试确认。

第一次使用 64 MiB/CPU 时，旧导出逻辑对数百 MiB 文本反复建立完整字符串，实验节点发生 OOM，节点零被终止的 Python 进程匿名 RSS 约 688 MiB。该次采样失败，实验客体由控制端正常关闭。导出已改为每次读取和 JSON 转义 64 KiB 文本；异常时仍清理自己创建的跟踪实例和探针，不扩大 VM 内存配额。测试同时核对引号、反斜线、控制字符和跨块 Unicode 内容保持一致。

## 验收边界

原有 20 ms 定时器的 250 ms 门槛、RTC/watchdog/DSM 错误检查均保留。取消 CPU 限额不能自动让这些门槛通过，也不能替代持久块设备、未修改容器、数据库事务安全、跨物理机容量和故障恢复的后续实验。

本轮实际对照如下。每次保持相同软件和三轮时钟探针，随后执行内存校验、1 MiB SFTP 回取及关机。计时列为本轮十二个 20 ms 定时器中的最大值；模式是宿主实验内核的动态抢占模式。

| CPU 总限额 / 模式 | 调度跟踪 | 定时器最大值 | 两侧最大可运行等待 | 完整工作区 |
| --- | --- | ---: | --- | --- |
| 2000 MHz / lazy | 32 MiB/CPU，完整 | 1067.785 ms | 1067.985 / 696.776 ms | 失败 |
| 2000 MHz / full | 溢出，排除调度分析 | 223.481 ms | 不使用丢失记录 | 失败 |
| 无限额 / lazy | 32 MiB/CPU 溢出 | 102.075 ms | 不使用丢失记录 | 失败 |
| 无限额 / lazy | 无跟踪 | 86.612 ms | 未测量 | 失败 |
| 无限额 / lazy | 64 MiB/CPU，分块导出，完整 | 108.328 ms | 590.542 / 453.978 ms | 失败 |
| 无限额 / full | 64 MiB/CPU，分块导出，完整 | 497.156 ms | 546.498 / 1398.638 ms | 失败 |

分块导出的两次实验分别保存两侧 1,861,564 / 2,013,824 和 1,626,857 / 1,474,760 条完整事件，没有缓冲区丢失、探针遗漏或再次 OOM。全抢占模式仍出现约 1.4 秒的响应接收等待，没有作为修复采用。无跟踪运行的定时器门槛通过，仍出现 watchdog 告警；两次完整跟踪分别还有 RTC 非法日期或定时器超限，正常关闭仍有 DSM 接收错误。内存与 SFTP 校验通过不抵消这些失败。

取消限额后的 ESXi 样本中 maxlimited 为零；这明确移除了人为限速，但不是所有剩余停顿的解释。单次运行、不同跟踪缓冲区和后台负载不能支持固定加速比，也不能据此定位为某个内核锁缺陷。下一步需要观察长等待期间实际执行线程的内核栈、抢占/中断关闭区间，以及同时间段的宿主虚拟化调度。

完整客体日志、资源变化、丢失计数、文件哈希和明确标记的端点摘录见 [本轮证据](evidence/ssi-scheduling-20261106.json)。数百 MiB 原始跟踪保存在私有实验目录，公开摘录不冒充全量回放。CI 可重算公开端点时间、工作区门槛和资源配置变化，并通过合成损坏记录测试分析器的拒绝路径。

实验结束后两台 VM 均恢复原版 Ubuntu `6.8.0-147-generic`。身份、`/lib -> usr/lib`、空 GRUB 一次性启动项、无残留 QEMU/DSM/跟踪事件及防火墙原样恢复均已核对。本机 Lima 保持停止。实验 VM 的 CPU 限额保留为 -1，且已更新私有新建脚本避免再次施加 2000 MHz 限额；没有调整业务 VM。
