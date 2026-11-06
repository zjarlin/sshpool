# DSM 线程停止与 KVM 销毁顺序

2026-11-06。PF9 修正研究内核的本地销毁顺序，并以实际 kprobe 与调度事件验证。实验仍在同一物理 ESXi 上的两个独占 x86 VM 中进行，不证明物理资源相加或故障接管。Ceph、持久磁盘、Docker 与数据库尚未接入。

## 已确认的问题

PF8 在 `kvm_arch_destroy_vm()` 的末尾调用 `kvm_dsm_free()`，后者才停止 DSM 根线程与接收线程。此时 vCPU、MMU 等资源已经开始销毁，通用 KVM 路径也已注销 MMU notifier。DSM 页面请求处理器却仍能访问这些资源，违反 KVM 在 `kvm_arch_pre_destroy_vm()` 中明确要求的“先停后台线程、再释放 vCPU”顺序。

这不是仅凭源码推断：PF8 的真实跟踪记录显示，两个 `kvm_arch_vcpu_destroy` 与 `kvm_mmu_uninit_vm` 都先发生，八个 `dsm-conn` 线程和一个 `kvm-dsm` 根线程随后才退出。本次受控探针没有触发内存损坏，不能把此前的所有关机故障都归因于这个顺序问题。

## PF9 改动

`kernel-dsm-teardown.patch` 将线程停止抽成幂等的 `kvm_dsm_stop()`，在 `kvm_arch_pre_destroy_vm()` 一开始调用，早于通用 KVM 的路由、MMU notifier、vCPU 与 MMU 清理。函数等待所有 DSM 线程结束后才返回。

配置、socket 和 DSM 内存槽的释放仍留在原有 `kvm_dsm_free()` 中；它保留一次幂等停止调用，兼容 VM 创建失败、没有经过预销毁钩子的清理路径。未启用 DSM 的构建有空实现。没有改变报文协议、引入新的丢包容忍或屏蔽关闭错误。

## 顺序验收

`trace-teardown.py` 复用真实 KVM 接收探针，创建两个停止的 vCPU、内存槽和一个回环半帧连接。它不在这个局部测试中执行客体代码；完整客体另做回归。

使用独立 trace instance、全局时钟和按本次实验注册的 kprobe，记录预销毁、vCPU 销毁、MMU 销毁、DSM 清理的函数入口/返回，以及九个 DSM 线程的真实 `sched_process_exit`。同一探针进程、接收阶段记录的线程 PID 与退出事件必须匹配。

下表对应 VM 先关闭、半帧连接仍保持开放的实验；对端先断开时，接收线程可以在预销毁之前退出。

| 内核 | 实际记录的关键顺序 | 结果 |
| --- | --- | --- |
| PF8 | 预销毁返回 → 两个 vCPU 销毁 → MMU 销毁 → 九个 DSM 线程退出 | 关闭顺序不通过 |
| PF9 | 预销毁 → 九个 DSM 线程退出 → 停止函数返回 → 预销毁返回 → 两个 vCPU/MMU 销毁 | 关闭顺序通过 |

最终 DSM 释放会再次调用停止函数，记录中有第二对入口/返回，但没有重复的线程退出。这证明本轮的重复调用没有重复停止线程；不等于覆盖所有并发销毁情形。

两台 PF9 节点分别覆盖“对端先断开”和“VM 先销毁”两种顺序，四组均通过。每组包含 20 条完整事件，kprobe missed 和每 CPU overrun/dropped 均为 0；PF8 基线为 16 条完整事件，明确不通过同一顺序门槛。四组临时防火墙规则的前后 JSON 完全一致，注册的跟踪事件和实例均已移除。

[证据文件](evidence/ssi-teardown-20261106.json) 保存原始 trace、每 CPU 的 overrun/dropped 统计、kprobe 命中与 missed 计数、接收探针线程身份、运行时哈希和宿主日志。`check-teardown.py` 要求事件完整、无丢失、无重复，且停止函数返回前所有 DSM 线程均已退出；只有探针退出 0 或 trace 中出现成功文字都不能通过。

最初两次跟踪配置返回 EINVAL，尚未启动 KVM 探针：Python 文本追加模式对 tracefs 做 `SEEK_END`，该操作不受支持。工具改为 `os.open(O_WRONLY | O_APPEND)` 加 `os.write`，避免定位，也不使用会清空其他事件的 `O_TRUNC`。第三次取得了顺序记录，但过滤 kprobe profile 时错误地按组名过滤；内核只输出事件名，导致 profile 缺失。最终基线使用第四个独立标签，前面三次保留为失败/不完整证据，不计作完整验收。

## 构建与复现

在 [PF8 源码](ssi-startup.md) 后应用该候选，保留原版 Ubuntu 为默认启动项，仅在核对归属且可独立恢复的实验 VM 用一次性 GRUB 项启动。

```sh
patch --fuzz=0 -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-teardown.patch
GVM-kernel/scripts/config --file kernel-out/.config --set-str LOCALVERSION -sshpool-gvm-pf9
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- olddefconfig
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j4 bzImage modules
# 在独占实验 VM 中使用已核验哈希的探针，实验防火墙仅允许所需回环连接。
sudo python3 scripts/ssi-lab/trace-teardown.py \
  --worker ./probe-pvclock --receive-probe scripts/ssi-lab/probe-receive.py \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf9 \
  --close-order vm-first --output new-teardown.json
python3 scripts/ssi-lab/check-teardown.py new-teardown.json
```

对端先关闭的测试使用 `--close-order peer-first` 和新的输出路径；端口仍处于 TIME-WAIT 时等待回收，不绕过前置检查。跟踪需要已挂载的 tracefs 与 `CONFIG_KPROBE_EVENTS`。工具删除自己注册的事件和实例，外部实验驱动删除临时防火墙规则，并核对修改前后的规则 JSON 一致。

PF9 为构建 #12，内核 SHA-256 `647f0f124a0e807593166b80b12e956553dacbaab9b448d84fc0b03bde7700c0`。内核配置与 PF8 仅 LOCALVERSION 不同；三个实际编译源文件与候选、干净 PF8 上零 fuzz 重放的结果逐字节一致。公开内核补丁遵循 GPL-2.0-only，原创工具与测试遵循仓库 MIT。

CI 重算保存的真实记录，并用缺失/重复事件、错误线程身份、提前返回和丢失计数等负例验证检查器。GitHub runner 不运行这套研究内核，不能把 CI 通过当作额外的双节点实机实验。

## 回归结果

两台 PF9 节点分别通过端口冲突后的同 VM 重试、各 64 次启停与端口重新绑定、无效参数后的重试，共六组。跨节点 pvclock 的八次交接也通过，原始版本号与远端内容核对一致。

完整无磁盘 SSH 客体沿用相同 QEMU、Ubuntu 内核和 initramfs，流程约 190.8 秒。两次 4 MiB 分配的八轮共享内存校验、1 MiB SFTP 往返均通过；客体输出 S5 与 `Power down`，两边 QEMU 退出 0。关机 SSH 因远端断开返回 255。

32 次时钟采样未倒退，四个 20 ms 定时器约为 140.37、21.55、20.95、72.84 ms，通过既有 250 ms 门槛。但完整串口仍记录三次 watchdog 检查跳过与 workqueue `hogged CPU`，所以工作区启动/运行验收仍失败。节点 0 的八条接收 `-104` 和根线程 `-104`、节点 1 的一条 `-4` 原样保留；限定窗口内宿主日志没有新增 WARNING/BUG/Oops/段错误。一次运行不能证明时钟稳定或性能提升。

## 剩余边界

这是本地资源生命周期修正，不是正常关闭协议。对端断开和本地取消的 `-104/-4` 仍需记录，尚未实现双方确认、在途请求排空和故障恢复。本轮半帧测试没有执行完整页面请求，因此不证明任意正在处理的事务都能取消。

源码中 `ivy_kvm_dsm_handle_req()` 的缺失内存槽重试路径尚未逐次检查停止信号，页面锁等待等路径也需要专项验证。PF9 没有修改这些路径，不能声称所有退出死锁或 use-after-free 都已消除。RTC/时钟尾延迟、持久 I/O、数据库以及多物理机容量和故障接管仍是独立验收项。

本轮结束，两台实验 VM 均恢复为原版 `6.8.0-147-generic`，SSH 正常、`/lib -> usr/lib` 保留，无实验进程或待执行 GRUB 项。kprobe 事件与 trace instances 已清空，防火墙规则 JSON 与实验前完全一致。业务主机、公司文件、数据库和生产隧道未参与实验。
