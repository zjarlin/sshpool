# PF28 客体定时器与中断观测

2026-11-08，同一物理 ESXi 的两个专用 VM 再次运行四 CPU 无磁盘 Ubuntu 客体。新增应用区间记录与客体 tracepoint 检查器，确认一次 215.761 ms 的等待包含约 192.625 ms 的本地定时器中断。**这只是停顿位置的观测，没有确定宿主根因或修复运行时。** 带额外 kprobe 的后续实验又出现 390.605 ms 定时器，超过原 250 ms 门槛；此前 [445.409 ms 失败](ssi-clock-stalls.md) 同样保留。

## 真实对照

四次使用同一 PF28 内核、global-close QEMU、客体内核和 SSH initramfs。只有应用探针增加可选输出，实际 20 ms 睡眠请求及原计时检查保持不变。

| 实验 | 定时器数 | 最大应用耗时 | 客体跟踪 | 原 250 ms 门槛 |
| --- | ---: | ---: | --- | --- |
| 双节点 pair-a，原探针 | 12 | 54.660 ms | tracepoint | 通过本轮有限采样 |
| 双节点 pair-b，附应用区间 | 24 | 215.761 ms | 84,908 事件，无丢失 | 通过本轮有限采样 |
| 单节点 control-c，同样附区间 | 24 | 20.307 ms | 6,554 事件，无丢失 | 通过本轮有限采样 |
| 双节点 pair-d，额外函数探针 | 12 | 390.605 ms | kprobe 漏采，拒绝用于完整归因 | **失败** |

所有实验均完成 SSH、四线程内存校验、用户态暂停、1 MiB SFTP 与客体关机。三次双节点实验的两端原生关闭均通过原检查器，QEMU 自行退出零；关闭通过不能覆盖计时失败。双节点仍有 workqueue 告警，pair-b 启动时还有 watchdog 跳过检查；单节点本轮没有这两类告警。

单节点对照保留相同四 CPU 拓扑、内存、客体、QEMU 和 tracepoint 集合。它说明这次单节点记录没有同等级延迟，不能证明跟踪对 DSM 的开销可忽略，也不能替代多轮无跟踪性能验收。

## 215.761 ms 定时器中的区间

pair-b 的 PID 190、CPU 0 记录如下。表中全为同一 guest 的 ftrace `global` 时间。

| 事件 | 时间（秒） |
| --- | ---: |
| 应用定时器启动 | 80.193951 |
| 应用睡眠，CPU 切换到 idle | 80.196306 |
| 本地定时器中断入口 | 80.196322 |
| 第一个记录到的到期回调（tick） | 80.310800 |
| 应用 `hrtimer_wakeup` 入口 | 80.311895 |
| 应用进入可运行状态 | 80.314737 |
| 随后的一个 tick 回调入口 / 返回 | 80.315051 / 80.383340 |
| 本地定时器中断退出 | 80.388947 |
| 应用重新运行 | 80.401256 |

中断入口到第一个到期回调经过 114.478 ms；唤醒之后的一个 tick 回调又占用 68.289 ms 墙钟时间。唤醒至重新运行共 86.519 ms，其中 74.210 ms 仍在该中断内。因此不能把全部 86.519 ms 称作普通调度队列等待，也不能据此断言 QEMU 没有及时注入中断。

应用 `CLOCK_MONOTONIC` 与 ftrace `global` 是不同时间域，**禁止直接相减**。检查器另外在单调时钟域核对 `before`、`softexpires`、到期事件的 `now` 和 `after`。其中 `now` 是 hrtimer 循环传入的时间基准样本，不保证在每个回调入口重新读取；`soft - requested` 也只是相对定时器设定的参考点。这些差值用来检查关联和边界，不冒充精确的系统调用或回调入口耗时。

pair-d 尝试跟踪时间读取、tick 和自旋锁函数。计数器报告 5–6 次 kprobe missed，且该临时脚本在冻结后导出期间仍启用事件，命中数明显多于缓冲区事件。原始计数、脚本、工作负载和失败原因均保存；**不发布它的函数耗时统计作为已验证结论**。继续缩小中断路径之前，必须先解决仪器边界与漏采。

## 工具与可重放证据

入口是 `trace-guest-timers.sh`，只接受指定内核、实验 hostname、四 CPU 与 `rdinit=/init`，要求独占空闲 tracefs。它不修改调度策略或关闭 watchdog。`guest-clock --timer-intervals` 在完成计时后输出 PID、CPU 和单调时钟起止值，默认输出与 `--pause-rounds` 保持兼容。

客体内采集：

```sh
sh /tmp/trace-guest-timers.sh start
for trial in 1 2 3 4 5 6; do
  sh -c 'echo TRACE_CLOCK_PID=$$; exec /tmp/ssi-clock --timer-intervals' || exit $?
done
sh /tmp/trace-guest-timers.sh stop
tar -czf /tmp/guest-timers.tar.gz -C /tmp/ssi-timer-capture .
```

控制端保存应用输出为 `clock.log`，通过已认证 SFTP 取回归档。检查器只在内存中读取受大小限制的普通文件，拒绝路径、链接和重复成员：

```sh
python3 scripts/ssi-lab/check-guest-timers.py guest-timers.tar.gz clock.log
python3 -m unittest discover -s scripts/ssi-lab -p 'test_guest_timers.py'
```

检查器核对头部、四 CPU 计数、零丢失、事件过滤与窗口；按初始化代次识别指针复用，要求每个应用区间拥有唯一的启动、到期、返回、睡眠、唤醒及重新运行记录。取消、错误时钟、CPU/PID 混用、内部孤立返回和不完整目标区间都失败。中断和回调按 CPU 栈配对，边界未完成部分单列，不补造耗时。250 ms 门槛单独报告，超限时 CLI 在输出完整 JSON 后退出一；`CLOCK_PASS` 和解析成功均不能覆盖它。

[证据清单](evidence/ssi-guest-timers-20261108.json) 包含四次客体和工作负载日志、三次双端关闭记录、防火墙快照、应用构建哈希、失败仪器计数与恢复检查。[双节点完整 trace](evidence/ssi-guest-timers-20261108-pair.tar.gz) 和 [单节点完整 trace](evidence/ssi-guest-timers-20261108-control.tar.gz) 一并提交，普通 CI 核对哈希并重放全部 48 个应用定时器，不只重放选中的慢片段。

两台实验 VM 已恢复 `6.8.0-147-generic`，原启动文件和 GRUB 未变、防火墙恢复一致，实验进程、trace instance 与 TCP 无残留。正在运行的 Lima 未停止。跨物理容量、持久化、Ceph、Docker 和数据库恢复仍未完成。
