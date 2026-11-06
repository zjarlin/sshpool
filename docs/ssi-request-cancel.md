# 完整页面请求的缺失槽重试取消

2026-11-06。PF10 在 PF9 的销毁顺序修复上，让 `ivy_kvm_dsm_handle_req()` 的重试入口检查停止与致命信号，并使两个缺失槽分支等待一个可中断的 jiffy 再重试。没有改变页面协议、关闭错误或验收门槛。

这是同一物理 ESXi 上两个专用 x86 VM 的内核实验。它不证明物理算力相加、超单机内存、持久磁盘、Docker、数据库或故障接管；Ceph 尚未接入。

## 问题与范围

PF9 的 `retry_handle_req` 在找不到 KVM 内存槽或 DSM HVA 槽时，释放 SRCU 后调用 `schedule()` 并直接重试，跳过外层的停止检查。线程仍是 runnable，`schedule()` 也不等于真正睡眠。完整请求因此可能使根线程停在 `kthread_stop()`，阻止 VM 回收。

PF10 在重新获取 SRCU 前检查 `kthread_should_stop()` 和 `fatal_signal_pending(current)`，取消时沿现有 `out` 路径释放临时页面并保留 EINTR。两个缺失槽分支使用 `schedule_timeout_interruptible(1)`，告警继续记录。其他页面状态重试也经过同一检查，但本轮动态证据只覆盖缺失 KVM 内存槽。

## 真实请求对照

探针创建真实 KVM VM 和 DSM 监听器，不创建 vCPU。正常请求使用固定 x86 ABI：14 字节传输头、24 字节 READ 请求、填充到 4110 字节传输帧，目标 GFN 为 2，事务号 42。返回页面是预先初始化的 4096 字节确定性内容。

三种模式分别验证：

- `late-register`：完整请求已进入处理器后才注册目标页；核对返回事务号、长度、版本、copyset 和完整页面 SHA-256。
- `cancel-root`：保留 VM fd，向根线程定向投递 SIGKILL，由根线程通过原有 `send_sig` 通知八个接收线程。先观察 500 ms 内能否退出，再补注册页面，为旧内核提供恢复通道。
- `close-vm`：在目标页仍不存在且对端连接仍开放时直接关闭 VM，要求两秒内完成；只在候选内核已通过可恢复取消测试后运行。

独立 trace instance 记录真实 `ktcp_receive` 返回 24、内存槽注册、处理器返回、九个线程退出及 VM 停止。取消模式还记录九次 `signal_generate`，要求 `grp=0` 且发送者/接收者 PID 匹配，故障取消的处理器返回值必须为 -4。检查器同时核对每 CPU 丢失计数、kprobe 命中/遗漏、线程快照身份与阶段顺序。

PF9 的有效基线在 500 ms 观察窗口内没有完成取消，补注册页面后才退出。PF10 在不注册页面时完成退出。未取消的读页响应 SHA-256 为 `f1a9116e64d5ce92231de69558afad42a650a9ee7ad481813ef824d649784ded`。

| 模式 | 节点 0 | 节点 1 |
| --- | --- | --- |
| 根线程故障取消，目标页仍不存在 | 11.612 ms 内九线程退出 | 1.739 ms 内九线程退出 |
| 直接关闭 VM，目标页仍不存在 | 3.750 ms | 3.245 ms |
| 延迟注册，未取消的请求 | 完整页面与事务元数据一致 | 完整页面与事务元数据一致 |

六组跟踪均无丢失或 kprobe missed。故障取消各 43 条事件、直接关闭各 30 条、延迟读页各 33 条。每组实验防火墙规则恢复前后 JSON 完全一致，临时跟踪事件与实例均清理完成。以上时延是各一次实验测量，不是长期尾延迟或整体性能保证。

最初一轮误用进程级 `kill`：该信号进入共享 pending 队列，未复现内核使用的线程定向信号，两版内核都等到最终 VM 关闭才退出。这两组保留为无效实验，检查器必须拒绝；有效重跑使用 `tgkill`，并用内核信号事件验证投递。前置检查遇到 TIME-WAIT 或暂时 SSH 不可达时未启动 KVM，不覆盖已有证据。

## 构建与复现

在 [PF9 源码](ssi-teardown.md) 上应用 `experiments/kernel-dsm-request-cancel.patch`。实际编译源、候选与零 fuzz 重放结果逐字节一致；配置仅 LOCALVERSION 从 PF9 改为 PF10。

```sh
patch --fuzz=0 -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-request-cancel.patch
GVM-kernel/scripts/config --file kernel-out/.config --set-str LOCALVERSION -sshpool-gvm-pf10
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- olddefconfig
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j4 bzImage modules
x86_64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static \
  scripts/ssi-lab/probe-dsm-request.c -o probe-dsm-request
# 仅在已核对归属、独占的研究 VM 上运行，所需回环端口由实验防火墙放行。
sudo python3 scripts/ssi-lab/probe-request-cancel.py \
  --worker ./probe-dsm-request --require-kernel 7.1.0-rc3-sshpool-gvm-pf10 \
  --mode cancel-root --output new-request.json
python3 scripts/ssi-lab/check-request-cancel.py new-request.json
```

工具依赖同目录的 `probe-receive.py` 和 `trace-teardown.py`。每次使用新的证据文件；等待 TIME-WAIT 自行回收，不跳过端口检查。`close-vm` 不能直接用于已知不能取消的旧内核。安装时保留原版 Ubuntu 为默认，仅用一次性 GRUB 项选择研究内核。

PF10 构建 #13，内核 SHA-256 `18561d7cd5455c06b50ad04a030f2d0812307f0f9e64c2ed407fbdf23a0b71ae`；运行包 SHA-256 `856f092b820aa6b26cdf7af232b0b2b2874c74e9c5af6fb622d46a069146a5e1`。内核补丁遵循 GPL-2.0-only，原创探针与检查器遵循仓库 MIT。

## 双节点回归

跨节点 pvclock 的八次页面交接全部通过，检查器重新核对版本与远端读取内容，退出顺序为节点 1 再节点 0。

完整无磁盘 SSH 客体沿用同一 QEMU、Ubuntu 客体内核与 initramfs，流程约 238.32 秒。两次 4 MiB 分配的八轮内存校验、1 MiB SFTP 往返通过；客体输出 S5 和 `Power down`，两边 QEMU 退出 0，关机 SSH 因远端关闭返回 255。SFTP SHA-256 为 `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`。

32 次跨 CPU 时钟采样没有倒退，但四个 20 ms 定时器约为 20.45、35.02、205.81、537.04 ms；最后一个超过原定 250 ms 上限。串口仍有三次 watchdog 检查跳过和 workqueue `hogged CPU`。因此完整工作区验收依然失败，未放宽门槛。单次样本不能说明 PF10 导致或解决了时钟尾延迟。

节点 0 的八条接收 `-104` 与根线程 `-104`、节点 1 的一条 `-4` 完整保留。限定宿主日志窗口没有新增 WARNING/BUG/Oops/段错误。请求取消、正常关闭协议和工作区稳定性是不同的验收项。

## 未完成边界

`dsm_lock()` 的不可中断 mutex 等待、异常请求长度/类型、一个持有 SRCU 后直接 `continue` 的异常分支仍需修复与独立验证。当前接收接口也未携带目标缓冲区容量，不能把本轮正常帧实验当作恶意报文安全性验证。没有实现对端确认、请求排空、数据库恢复或物理主机故障容错。

原始 trace 与机器可复核证据在 [实验数据](evidence/ssi-request-cancel-20261106.json)。重复的缺失槽告警在公开文件中以条数与消息模板表示，其余宿主日志逐条保留，并记录完整私有原日志的 SHA-256；没有过滤关闭错误。CI 只重新验证保存的实机记录和检查器负例，不在 GitHub runner 上运行研究内核。

本轮结束，两台实验 VM 均恢复为原版 `6.8.0-147-generic`，SSH 与身份核对通过，`/lib -> usr/lib` 保留，没有实验进程或待执行 GRUB 项。跟踪事件和实例已清理，防火墙与实验前完全一致。业务主机、公司文件、数据库和生产隧道没有参与实验。
