# DSM 接收等待实验

2026-11-06。继续使用同一 ESXi 上的两个专用 x86 VM、相同 QEMU 与无磁盘 SSH 客体。只研究 DSM 接收等待，没有挂载业务目录、安装 Ceph 或运行数据库。两个实验 VM 不能证明跨物理机容量相加或故障接管。

## 已定位的忙等

PF6 的 `__ktcp_receive()` 对每次接收都强制使用 `MSG_DONTWAIT`。等待任意请求的服务线程在空缓冲区收到 `EAGAIN` 后立即重试，已读到半帧的读者也采用同样循环。阻塞式上层调用并没有真正睡眠。

完整双节点启动期间，用 `profile-threads.py` 读取 `/proc` 中真实 QEMU 和 DSM 线程的 CPU 累计时间、状态和内核栈。约 90 秒采样窗口的结果：

| 节点 | 窗口 | 八个 DSM 接收线程 CPU 时间 | 等效核心占用 |
| --- | ---: | ---: | ---: |
| 0 | 89.45 s | 75.78 s | 0.847 |
| 1 | 89.53 s | 77.20 s | 0.862 |

vCPU 的快照多次落在 `ktcp_receive → kvm_dsm_fetch → ivy_kvm_dsm_page_fault`。同期 perf 样本中也反复出现接收路径的 socket 锁、接收和权限检查。不能据此责怪安全检查：问题是重复调用这些路径的忙等。没有关闭 SELinux、watchdog 或内核告警。

原始 `/proc` 记录按节点压缩保存为 [节点 0](evidence/ssi-pf6-node0-profile-20261106.jsonl.gz) 和 [节点 1](evidence/ssi-pf6-node1-profile-20261106.jsonl.gz)。可解压后运行 `summarize-profile.py`；CI 会解压并重新计算结果。快照不是精确函数耗时分析，而且采集会产生开销。开始时 `sched_schedstats=0`，因此不以附带的调度队列等待字段作性能结论。

## PF7 候选的边界

`experiments/kernel-dsm-receive-wait.patch` 仅修改接收等待：任意请求的接收者等待 socket；指定事务首次没有数据时返回外层，释放接收锁并采用已有退避；一旦读到部分帧，则由同一读者睡眠等待剩余字节。这样既避免忙等，也避免指定事务永久持有接收锁阻挡其他读者。

帧格式、页协议和所有权规则保持原样。没有应用 TCP_NODELAY 候选，也没有消除 EOF、信号中断或连接重置错误。它不提供正常关闭握手、请求排空、超时后的事务恢复或节点故障接管。

`probe-receive.py` 使用真实 `/dev/kvm`，复用 `probe-pvclock` 创建停止的 vCPU。它连接回环 DSM 监听器，依次观测空闲连接和仅发送八字节的半帧，随后关闭 socket 和 VM。八字节不足以构成请求，不触发页面操作。每个窗口用八个接收线程的真实 CPU 累计时间计算占用，以小于 0.1 个核心作为该受控等待测试的上限；这不是性能服务等级承诺。

同一 C 二进制与 Python 探针分别在两台节点的 PF6、PF7 内核运行：

| 内核 | 节点 0 空闲 / 半帧 | 节点 1 空闲 / 半帧 |
| --- | ---: | ---: |
| PF6 | 1.001 / 1.001 个核心 | 1.001 / 1.001 个核心 |
| PF7 | 0 / 0 | 0 / 0 |

每个窗口约三秒。零表示这段受控等待窗口内 CPU 累计计数没有增长，并非有负载时不消耗 CPU。PF7 栈中可直接看到 `sk_wait_data → tcp_recvmsg → kernel_recvmsg → __ktcp_receive`；关闭后四次实验均完成 VM 释放，没有接收线程残留。原始计数、线程身份、栈及宿主错误在 [接口证据](evidence/ssi-receive-probes-20261106.json)，CI 从计数重新计算，未采信探针输出的通过标记。

四次实验关闭不完整连接时都保留了 `ktcp_receive -104`，有一次 PF7 还报告 DSM 根线程退出 `-104`。这次验证的是等待和资源清理，**不是正常关闭协议已经完成**。最早两次探针因实验防火墙禁止回环而未进入测量，未纳入上表；之后只临时允许实验 VM 的 `lo/127.0.0.1:37710`，每轮测完删除该规则，未扩大外部来源。

之后给探针增加 `--close-order vm-first`，两台 PF7 节点各再运行一次：对端保持半帧连接开放时，直接销毁 VM，接收等待可被内核线程退出信号中断，VM 关闭成功且没有残留线程。新增脚本哈希分别随证据记录，前四次的原始哈希保留。`-4` 中断错误仍被记录。这只覆盖本地受控销毁，不代表远端物理机失联时能恢复未完成事务。

PF7 内核为构建 #10，SHA-256 `d6c588f65de38561acbe3bd8fdcfd2e6dac409c4544e0d17d5034a82257e03c3`。PF6 的 `ktcp.c` 与固定上游提交一致，从上游重新应用接收补丁得到的文件与实际编译文件逐字节一致。

PF7 完整客体运行中的另一次约 30 秒采样，两个节点接收线程分别消耗 0.592、0.653 CPU 秒，约 0.020、0.022 个核心；原始数据见 [节点 0](evidence/ssi-pf7-node0-profile-20261106.jsonl.gz) 与 [节点 1](evidence/ssi-pf7-node1-profile-20261106.jsonl.gz)。这两个窗口与 PF6 的采样阶段不完全相同，不能把比例直接当作吞吐提升倍数；前述同一空闲/半帧探针才是受控的忙等对照。

## 完整工作区与尚未通过的门槛

保持 QEMU、客体内核、initramfs 和流程不变。本次 PF6 双节点基线、PF7 单节点对照、PF7 双节点各运行一次；详细串口、时钟、内存和宿主日志见 [完整证据](evidence/ssi-receive-workspaces-20261106.json)。

| 项目 | PF6 双节点 | PF7 单节点 | PF7 双节点 |
| --- | ---: | ---: | ---: |
| 整个流程 | 919.92 s | 28.83 s | 243.71 s |
| 内存校验命令（含 SSH） | 162.66 s | 0.51 s | 40.96 s |
| 1 MiB SFTP 往返（含握手） | 69.82 s | 0.68 s | 15.60 s |
| 四个 20 ms 定时器最大耗时 | 511.85 ms | 20.59 ms | 91.58 ms |
| SFTP 内容校验及正常 S5 | 通过 | 通过 | 通过 |
| 完整启动门槛 | **未通过** | **未通过** | **未通过** |

两次双节点运行有不同时间窗口的性能采集，单次总耗时也包含启动、握手和宿主调度波动；这组观察不是可外推的性能倍数。PF7 仍明显慢于单节点，尚未达到用户希望的多机算力相加。

PF6 本轮出现丢失 43 个 RTC 中断、watchdog 跳过检查和 250 ms 定时器预算超限。PF7 单节点与双节点本轮的四个定时器均在预算内，但启动 watchdog 都曾跳过检查。PF7 双节点早期还记录了 `PM: RTC time: 00:00:00, date: 2000-00-00`，之后 rtc_cmos 才设置有效日期；不能据此声称 RTC 已修复。

PF7 双节点保留节点 0 的八条 `ktcp_receive -104` 与根线程退出 `-104`，节点 1 保留四条 `-4`。本轮三个完整流程的宿主日志没有新增 WARNING/BUG/Oops。两边 QEMU 退出 0 与客体关机不覆盖这些协议错误。pvclock 跨节点八次回归仍通过，新增记录已经进入 [pvclock 证据](evidence/ssi-pvclock-probes-20261106.json)。

因此完整 SSI 工作区仍未通过验收。下一步仍需定位 RTC/时钟和余下页面交接延迟，实现有确认和排空的关闭协议，再验收持久块设备、Docker、数据库、跨物理机容量与接管。Ceph 尚未接入。

## 复现入口

在 [PF6 补丁集](ssi-pvclock.md) 后应用接收补丁，另行构建 PF7；只在独占、可重置的实验 VM 一次性启动，保留原版内核为默认。研究内核无法保证超时一定能终止内核中的操作。

```sh
patch -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-receive-wait.patch
# 按实验构建流程生成独立的 -sshpool-gvm-pf7 内核。
sudo timeout --kill-after=5 45 python3 scripts/ssi-lab/probe-receive.py \
  --worker /path/to/probe-pvclock \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf7 --output new-receive.json

sudo python3 scripts/ssi-lab/profile-threads.py --pid QEMU_PID \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf7 --seconds 60 --output new-profile.jsonl
python3 scripts/ssi-lab/summarize-profile.py new-profile.jsonl
python3 scripts/ssi-lab/check-clock.py guest-clock.log --max-timer-ms 250
```

探针拒绝已有 QEMU/DSM/探针进程及占用的回环端口，不覆盖已有输出。运行中的 PF6 完整客体已经实际触发拒绝路径。仍要求操作者独占节点，检查端口不能代替实例隔离。

时钟检查器新增显式延迟预算，避免把“没有倒退”理解成“定时器延迟可用”；本轮使用 250 ms 作为四个 20 ms 睡眠的实验门槛。启动检查器也拒绝 RTC 无效月份/日期、丢失 RTC 中断与 watchdog 因长读数间隔跳过检查。四个样本不能代表长期尾延迟。

本轮结束，两台实验 VM 均恢复到原版 `6.8.0-147-generic`，管理 SSH 正常，`/lib -> usr/lib` 保留，无 QEMU、DSM 或探针残留，无待执行 GRUB 项。两次临时回环规则均已删除，原有实验网络过滤保持。业务主机、公司文件、数据库和生产隧道未参与实验。
