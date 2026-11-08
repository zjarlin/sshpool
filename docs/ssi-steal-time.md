# PF29 steal-time 页面一致性实验

2026-11-08，真实双节点探针确认 `record_steal_time()` 通过缓存地址写入客体页时绕过 DSM 所有权。PF28 的八次交接全部读到旧版本；PF29 在同一探针二进制、相同两台实验 VM 上八次全部通过。单节点 DSM 对照在两个内核上均通过。

**这是受控串行页面交接的修复，尚未证明它导致或消除了此前的客体中断停顿。** [390.605 ms](ssi-guest-timers.md) 和 [445.409 ms](ssi-clock-stalls.md) 的既有失败保留；250 ms 定时器门槛不变。两台 VM 位于同一物理 ESXi，不能算跨物理机容量验收。

## 缺陷与候选

KVM 为每个 vCPU 向客体报告 steal time，即该 vCPU 等待宿主调度的时间。`gfn_to_hva_cache` 只缓存地址，不授予 DSM 页写权限。实验把两个 64 字节记录放在同一页，让节点交替获取页面，再由失去页面所有权的原写入节点执行一次 KVM_RUN。

PF28 的一次实际交接：节点零写入 version 4；节点一取页并写入 marker 2；节点零内核把本地副本更新为 version 6，却仍看到 marker 1；节点一再次读取仍为 version 4、marker 2。另一个方向同样失败。这不是仅根据源码推测出的缺陷。

[内核补丁](../scripts/ssi-lab/experiments/kernel-dsm-steal-time.patch) 在 PF28 上增加以下行为：

- `record_steal_time()` 在整个缓存写入和版本更新期间持有 DSM 独占页权限，所有退出分支归还权限。
- 获取权限失败向 `KVM_RUN` 传播错误，不继续进入客体。
- `kvm_steal_time_set_preempted()` 位于不可等待网络的调度上下文；DSM 模式省略这个可选 preempted 提示，避免写失去所有权的副本。普通非 DSM 路径保留。

最小探针只运行 HLT，验证计账更新、远端可见性、同页另一条记录与标记保存。它没有单独验证调度抢占提示、并发撕裂、长时压力或断网错误路径。检查器始终返回 `preemption_hint_verified: false` 和 `full_ssi_accepted: false`。

## 原始实验

| 内核 | 模式 | 页面检查 | 失败 |
| --- | --- | ---: | ---: |
| PF28 | 单节点 DSM 对照 | 8 | 0 |
| PF28 | 双节点交接 | 8 | 8 |
| PF29 | 单节点 DSM 对照 | 8 | 0 |
| PF29 | 双节点交接 | 8 | 0 |

四次使用 SHA-256 为 `57787bfe3eb57eebdea49a5d7d49a0d05cde4ecf9e82a4da3cf17d1e66beda2c` 的同一静态探针。PF29 内核 SHA-256 为 `116f7f7e7f970a8cbfa850c340760146a94dc5dbb8e16cafde5e6c65b6e622a2`。配置只改变 LOCALVERSION；PF28 的其余已跟踪内核源码摘要不变。

每次最小探针都先在两端使用同一正代际执行原生 DSM_CLOSE，再逆序关闭 VM fd。宿主日志确认双节点各有 accepted=2、closed=1、eof=2、result=0；单节点三种连接计数为零。原防火墙精确恢复，实验进程、trace instance 和 TCP 状态清空。

## 完整客体回归与关闭边界

首轮 PF29 搭配旧 global-close QEMU，SSH、三轮时钟、四线程内存测试、用户态暂停与 1 MiB SFTP 均成功，但两端 QEMU 退出一。原因是旧 QEMU 在最终关闭入口只接受精确 PF28，随后宿主出现连接重置。**这轮关闭失败没有删除或改写为成功。**

[PF29 QEMU 补丁](../scripts/ssi-lab/experiments/qemu-pf29-lab-profile.patch) 只把独立实验构建的内核名称和说明改为 PF29，保留环境开关、KVM、无共享内存、四 CPU、每端两 CPU 和两节点限制。旧二进制保留。该补丁不修改默认运行时、通用内核白名单或 CLI 准入。

新 QEMU SHA-256 为 `d51d81986ecdcbfb5f1889d02480028cc4bf5f4466d3d09fcf34c653940ff251`。完整工作区使用相同客体、内存和四 CPU 拓扑，每次运行三轮时钟、四线程内存校验、用户态暂停与 1 MiB SFTP：

| 实验 | QEMU 版本 | 12 个定时器的最大耗时 | QEMU 退出 | 250 ms 门槛 |
| --- | --- | ---: | --- | --- |
| control-a | 原 PF28 guard | 20.186 ms | 0 | 通过本轮采样 |
| pair-a | 原 PF28 guard | 80.558 ms | 1、1 | 通过采样，但关闭失败 |
| control-b | 独立 PF29 guard | 20.639 ms | 0 | 通过本轮采样 |
| pair-b | 独立 PF29 guard | **359.971 ms** | 0、0 | **失败** |

pair-b 的时钟探针报告 CLOCK_PASS 并退出零，只能说明采样单调且没有提前返回。独立检查器按原门槛判定 359.971 ms 超限；**关闭成功不能覆盖计时失败**。两次双节点均有 workqueue 告警，pair-a 还出现 watchdog 跳过检查。本轮没有证明停顿改善。

PF29 没有套用 PF28 的原生函数跟踪元数据；关闭检查只核对实际 QEMU 双向 QUIESCE/DRAIN、设备解除、零引用、同一代际返回以及宿主 DSM_CLOSE_RESULT，明确返回 `native_function_trace_verified: false`。所有完整日志、构建摘要和采集驱动保存在[证据清单](evidence/ssi-steal-time-20261108.json)。

## 运行与重放

在显式指定的独占实验节点上运行，保持原 pvclock 默认模式兼容：

```sh
python3 scripts/ssi-lab/probe-pvclock.py \
  --ssh-config /path/to/lab-ssh-config \
  --host ssi-lab-1 --host ssi-lab-2 \
  --peer NODE0_IP --peer NODE1_IP \
  --worker ssi/probe-records \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf29 \
  --kind steal --log /path/to/new-run.jsonl
python3 scripts/ssi-lab/check-steal-time.py /path/to/new-run.jsonl --nodes 2
python3 -m unittest discover -s scripts/ssi-lab -p 'test_steal_time.py'
```

检查器按原始 JSONL 重放八次交接与关闭顺序，重算所有成功/失败字段；拒绝错误节点、缺失交接、非法字段、损坏保留字节、报告与原始数据不一致及不完整关闭。页面验证失败时 CLI 退出一。宿主日志由 `inspect_host()` 独立核对；仅运行 JSONL CLI 不代表已完成宿主检查。

普通 CI 重放四份完整记录及篡改负例，并从提交的 [PF28 x86.c 快照](evidence/ssi-steal-time-20261108-pf28-x86.c.gz) 零 fuzz、零 offset 应用补丁，核对结果与实际 PF29 编译源码一致。QEMU 也执行独立补丁重放。快照保留原 GPL-2.0-only 许可证声明与作者信息；实验补丁不因控制器采用 MIT 而变为 MIT。

两台实验 VM 已恢复 `6.8.0-147-generic`。本轮新增 PF29 GRUB 入口已移除，原 GRUB 配置、stock 启动文件摘要和防火墙与实验前一致；实验进程、trace instance 与 TCP 无残留。PF29 内核和模块文件保留用于复验，stock 默认不引用它们。Lima `sshpool` 保持运行。跨物理容量、持久化、Ceph、Docker/数据库及故障恢复仍未完成。
