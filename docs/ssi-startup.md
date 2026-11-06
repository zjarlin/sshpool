# DSM 启用失败与资源回收实验

2026-11-06。PF8 是独占 x86 实验 VM 的研究内核，仍使用同一物理 ESXi 上的两个 VM。它修复本地启用 DSM 时的错误传播和部分资源生命周期，不代表跨节点协调启动、正常关闭协议或故障接管完成。Ceph、持久块设备、Docker 与数据库尚未接入。

## 问题与改动

PF7 在启动内核线程后就让 `KVM_DSM_ENABLE` 返回成功，实际 `bind/listen` 在线程中稍后执行。监听端口已占用时，调用者仍可能看到成功并继续启动客体；之前的 [设备顺序实验](ssi-device-order.md) 曾因此出现远端页请求失败和无法完整回收，最终重置一个实验 VM。

`experiments/kernel-dsm-startup.patch` 在 ioctl 返回前完成监听，将绑定失败直接返回 QEMU。参数校验拒绝空列表、超出列表的节点编号和超过 `DSM_MAX_INSTANCES=16` 的列表，并正确返回用户地址复制错误。失败后释放已分配的配置，同一个 VM 可以重试。

根线程与连接线程使用 `kthread_create`，在唤醒前持有 task 引用，停止后再释放，覆盖线程提前退出的情况。部分创建的连接也进入统一回收列表；停止时先通知所有工作线程，再逐个等待。监听 socket 由 VM 持有，即使根线程尚未执行就被停止也会释放。TCP 控制块在创建、连接、监听和 accept 失败时释放，最终关闭也释放缓冲区；保留第一个关闭错误，不用后续成功覆盖它。

没有添加 `SO_REUSEADDR`，TIME-WAIT 仍可能导致绑定失败；现有的全部 TCP 状态前置检查继续保留。没有屏蔽 EOF、信号中断、watchdog 或其他告警。

## 真实接口证据

[原始证据](evidence/ssi-startup-20261106.json) 保存探针 stdout/stderr、退出状态、运行时哈希和限定实验窗口的宿主日志。

| 实验 | PF7 基线 | PF8 节点 0 / 节点 1 |
| --- | --- | --- |
| 占用回环监听端口后启用 | 错误返回成功 `0`，探针失败 | 返回 `-1 / EADDRINUSE(98)` |
| 释放端口后同一空 VM 重试 | 不执行后续重试 | 两边成功，关闭完成 |
| 创建、启用、关闭、重新绑定原端口 | 未执行 | 各 64 次全部通过 |
| 空列表、越界节点、65 个节点、无效指针 | 未执行 | `22/22/22/14`，随后有效参数重试成功 |
| 真实 QEMU 遇到监听冲突 | 源码中已有错误分支，但此前内核没有返回错误 | 两边打印 `Address already in use`，退出 1，没有进入客体 |

启动探针不创建 vCPU 或内存槽，不执行客体。PF7 的这次最小基线关闭得很快，没有捕获到线程内的 bind 日志；不能声称本次基线日志证明了异步 bind 失败。它直接证明的是端口仍被占用时 ioctl 却返回成功。

QEMU 的处理位于 `hw/i386/pc.c` 的 `pc_memory_init()`，原有 `ret < 0` 分支即可接收新的内核错误，无需改动 QEMU。两次实测从启动到退出约 61 ms、84 ms，仅是本次故障注入耗时，不是延迟保证。释放阻塞 socket 后端口重新绑定成功，均无残留 QEMU/DSM 线程。

## 连接与页面交接回归

两台 PF8 节点分别运行“对端先关闭”和“VM 先关闭”两种半帧测试，共四次。空闲、半帧两个约三秒窗口中，八个接收线程的累计 CPU 时间均没有增长；两种退出顺序均完成回收。`-104` 或 `-4` 仍在宿主日志中，不能当作已实现正常关闭握手。

这四次测试只临时允许回环 `127.0.0.1:37710`，每次结束后的 nft 规则 JSON 都与该次开始前相同。没有扩大外部网络来源。跨节点 pvclock 探针的八次交接也通过：从原始版本号、同页相邻记录和远端读取值重新核对，而非只检查 PASS 字样。

QEMU 冲突实验首次尝试与完整工作区首次尝试被全部 TCP 状态检查拒绝，均未启动 QEMU。失败的复合检查没有保存具体 TCP 状态；另外一次只读观察看到了 TIME-WAIT，不能据此把每次拒绝都说成已精确确认 TIME-WAIT。后续先确认两边端口为空，再使用新实验标签运行，没有覆盖先前尝试。

完整 SSH 客体沿用上轮的 MMIO 完成确认 QEMU、Ubuntu 客体内核和 initramfs，仅换成 PF8 宿主内核。本次四个 20 ms 定时器分别约 20.58、21.53、74.41、20.14 ms，32 次跨 CPU 采样未倒退，有限样本通过原有 250 ms 门槛。但启动时仍有两次 `Long readout interval, skipping watchdog check`，所以启动验收仍失败，不能把本次定时器通过称为时钟问题已经修复。

完整流程约 276.24 秒。SSH 身份检查、两次 4 MiB 分配的八轮共享内存校验、1 MiB SFTP 往返均通过；客体进入 S5 并输出 `Power down`，两边 QEMU 退出 0。关机命令的 SSH 因远端断开返回 255，不是所有命令都退出 0。串口仍有 workqueue `hogged CPU` 提示，节点 0 的八条接收 `-104` 与根线程 `-104`、节点 1 的一条 `-4` 也原样保留。限定窗口内的宿主日志没有新增 WARNING/BUG/Oops/段错误。单次流程时长不能作为 PF8 的性能提升或退化结论。

## 复现与证据检查

在 [PF7 源码与配置](ssi-transport.md) 后应用本候选，独立生成 PF8；默认构建脚本不自动启用这个研究补丁。

```sh
patch --fuzz=0 -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-startup.patch
GVM-kernel/scripts/config --file kernel-out/.config --set-str LOCALVERSION -sshpool-gvm-pf8
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- olddefconfig
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j4 bzImage modules
cc -O2 -Wall -Wextra -Werror -static scripts/ssi-lab/probe-dsm-startup.c -o probe-dsm-startup
# 仅在核对归属、端口空闲、内核与二进制哈希后的独占实验 VM 执行。
timeout --kill-after=5 30 ./probe-dsm-startup 7.1.0-rc3-sshpool-gvm-pf8 occupied > startup.log
python3 scripts/ssi-lab/check-startup.py startup.log
```

另两种探针模式为 `cycles`、`invalid`；每次使用新的日志名。实验网络必须保持隔离，不能把未认证的 DSM 监听暴露到不可信网络。内核不可中断等待可能使外层 timeout 无法回收，因此实验 VM 必须有独立恢复通道。

PF8 为构建 #11，内核 SHA-256 `8967674a2b770b350927d387002046cc1c2899995c9f1dd68f19c61a985cf4ee`。三个实际编译源文件、候选源文件、从干净 PF7 应用补丁所得文件逐字节一致，哈希保存在证据中。公开补丁遵循 Linux 的 GPL-2.0-only；原创探针与检查器遵循仓库 MIT。

CI 编译 C 探针，验证错误内核参数会拒绝执行，并重算保存的真实证据。检查器拒绝错误 errno、缺失重试、乱序关闭、重复轮次与缺失端口释放证明。CI 不在普通 runner 上伪装执行实验内核。

## 仍待完成

本次不覆盖分配失败/线程创建失败注入、远端连接故障后的协调退出、在途请求排空、节点失联恢复或长期内存泄漏检测。重复 64 次回收监听器和线程不能证明内核完全无泄漏。

源码核查还发现 `kvm_arch_destroy_vm()` 在销毁 vCPU/MMU 后才调用 `kvm_dsm_free()`；PF8 没有更改该顺序。存在在途页面请求时的销毁安全性仍需单独验证，不能把局部生命周期修正称为已解决所有 teardown 竞态。完整 SSI 仍须通过时钟/RTC、持久 I/O、数据库和多物理机容量与故障验收。

本轮结束，两台实验 VM 均已恢复原版 `6.8.0-147-generic`，管理 SSH 正常，`/lib -> usr/lib` 保留，无 QEMU/DSM/探针残留，GRUB 环境中没有待执行项，原有实验防火墙规则保持。业务主机、公司文件、数据库与生产隧道未参与实验。
