# PF20：VM/vCPU ioctl 准入屏障

PF20 在两台专用 x86 实验 VM 上验证了 VM/vCPU 原生 ioctl 的入口封闭和在途计数。封闭后新调用返回 `ESHUTDOWN`；此前准入的调用继续运行，直到完成内部操作、释放锁和 SRCU，再减少计数。页面服务线程仍能响应远端请求。**这不是全 VM 排空，也不是 SSI 或持久化验收通过。** 两台实验 VM 仍在同一台物理 ESXi 上。

[原始证据](evidence/ssi-ioctl-admission-20261106.json) 保存十组真实 KVM 探针、原始报文、完整跟踪、运行时及源码哈希和客体回归。首先阅读本文，再看 [需求](../features/170-ssi-transport.feature) 和 [检查器](../scripts/ssi-lab/check-ioctl-admission.py)。

## 修改与接口

[GPL-2.0-only 内核补丁](../scripts/ssi-lab/experiments/kernel-dsm-ioctl-admission.patch) 直接接在 PF19 后，构建后缀为 `-sshpool-gvm-pf20`。编译无警告，配置只改变版本后缀，零 fuzz 重放与实际编译源一致。默认安装流程不应用此实验补丁。

准入锁原子地排序“登记普通 ioctl”与“封闭入口”。计数覆盖整个 VM/vCPU ioctl，包括等待 vCPU 锁、架构专用的 unlocked ioctl、KVM_RUN、MEMCPY、MEMPIN、用户数据复制和错误返回；成功和失败出口统一释放令牌。它从 VM 创建后就计数，避免与 DSM_ENABLE 并发时漏记。compat 路径也经过同一准入函数，但本轮动态探针只验证原生 x86-64 ABI；不能把编译通过当作 32 位调用已验证。

研究 ABI 仅供后续关闭协议组合：

| ioctl | 参数与结果 |
| --- | --- |
| `KVM_DSM_IOCTL_DRAIN` (`0x4018aef6`) | 24 字节：`u32 version=1, u32 flags=0, u64 generation, u32 timeout_ms, u32 reserved=0`。generation 非零，期限 1–30000 ms；成功只表示普通 VM/vCPU ioctl 计数归零。 |
| `KVM_DSM_IOCTL_STATUS` (`0x8020aef7`) | 32 字节：`u32 version, u32 state, u64 generation, u32 active, s32 error, u32 reserved[2]`。state 为 0/1，表示开放/已封闭；控制调用自身不计入 active。 |

有效 DRAIN 永久封闭该 VM 的入口，不调用 `kvm_vm_dead()`，也不关闭 socket。相同 generation 可重复等待或复核；不同 generation 返回 `ESTALE`。超时返回 `ETIMEDOUT`，保留封闭状态及旧操作；信号也不重新开放入口。输入错误、未启用 DSM 或无法取得管理锁时，在封闭前分别返回 `EINVAL`、`EFAULT` 或 `EBUSY`。

期限从参数验证和封闭完成后的等待开始，不承诺整个系统调用的硬实时上限。管理锁使用 trylock，避免在封闭前无期限等待它。调用者须先请求 vCPU 停止；屏障本身不会强制结束正在执行的 KVM_RUN。计数归零表示内核操作已完成并进入返回尾部，不保证其用户线程已被调度或观察到返回。

真实协议故障沿用 PF17 的失败路径，唤醒屏障等待者并保留错误优先级；后续标准 VM/vCPU 管理调用返回 `EIO`。正常封闭不杀死 VM，只有真实故障才进入此失败路径。

## 已验证的范围

每台实验 VM 都执行了以下五组探针，页面对端为受控回环协议端点。它们证明真实 KVM 行为，不是内存计数的纯模型测试。

| 场景 | 核查内容 |
| --- | --- |
| 参数与空闲屏障 | 版本、flags、零 generation、非法期限、reserved 和坏指针被拒绝且入口仍开放；空闲封闭后 VM、vCPU、RUN、MEMCPY 新入口均拒绝。 |
| 在途写入 | 真实 MEMCPY 等待远端页面，两个控制线程同时等待；封闭期间另一页面仍收到正确响应；释放远端响应后写入内容正确，SRCU 释放和操作返回早于准入令牌释放。 |
| 超时复核 | 100 ms 等待超时，旧写入仍存活、入口仍封闭；随后响应被消费、写入完成，相同 generation 可成功复核。 |
| 故障优先 | 等待期间注入非法请求，原写入和两个控制等待者保留 `EPROTO`，不能以计数减少报告成功；后续管理入口为 `EIO`。 |
| 正在运行的 vCPU | 真实客体执行 HLT，内核栈显示 `kvm_vcpu_block`；计数保持为一，设置 immediate_exit 并发信号后 KVM_RUN 返回 `EINTR`，屏障才完成。 |

首个参数探针因漏导入 `json` 而在结果导出阶段失败，记录保留为拒绝项；当时已清理线程、跟踪及临时防火墙规则。修复探针后使用新编号采集。检查器使用 Linux 的 errno 数值，避免在 macOS 离线核查时误用本机不同的编号；它核查真正来自 DSM ioctl 的 SRCU 释放，不以同一线程后来执行的 MMU notifier 释放代替。

## 客体回归未通过完整验收

普通单节点在 11.64 秒内完成 SSH、三轮时钟、内存、PAUSE、1 MiB SFTP 往返和关机，最大定时器读数约 20.20 ms。双节点在 107.71 秒内完成这些操作且两端退出码为零，但第一轮时钟的 CPU 1 读数为 **431.58 ms**，超过原来的 **250 ms** 上限；启动日志还出现 `Lost ... RTC interrupts`。因此双节点 `operations_passed=false`。

双节点 QEMU 路由屏障完成，内核仍报 DSM 连接错误，全 VM 正常关闭不通过。没有关闭 watchdog、改变门槛或重跑挑选成功记录。本次变化与时钟失常的因果关系尚未确定，后续应进行固定负载的基线/候选对照；十组入口探针通过不能抹掉这次失败。

## 仍未解决

入口计数仅覆盖 VM/vCPU ioctl；KVM device fd、mmap、irqfd、定时器、设备后台任务和跨调用存活的 DMA pin 不在此验收内。MEMPIN 已返回也可能留下固定页面；现在封闭入口后连 unpin ioctl 都会拒绝，因此后续管理器必须在封闭前完成设备排空与解除固定，并验证它们，不能只看到 active=0 就关网。

服务线程的反向请求可能使用普通出站连接：`kvm_dsm_invalidate()` 也以 `from_server=false` 调用 fetch。按 socket bank 区分外部与内部请求会错误关闭仍被依赖的通道。仍需完整出站事务与缓存响应消费计数、跨节点请求链终止确认、最终 CLOSE/ACK 和故障优先级。

现有 QEMU 尚不调用这两个新 ioctl。它的路由屏障早于 `bdrv_close_all` 和网络清理，不能据此断言设备已停止产生 DSM 内存访问。当前内核的 pre-destroy 也先停止 DSM、后处理部分后台任务；正确协调这些生命周期仍是后续工作。不能用一次全局 SRCU 同步替代上述协议，否则可能等待仍需远端服务的线程而死锁。

PF19 双节点启动中的 watchdog 告警与关闭 `-104` 失败仍保留在旧证据中。新内核回归不构成原因分析，也不能用新结果覆盖旧失败。持久 I/O、Ceph、Docker、PostgreSQL/Redis/sub2api、超过单机内存的工作集、多物理机资源汇聚及故障接管均未验收。

## 实验维护与复核

本轮将新内核、initrd 和 System.map 放在专用 VM 根分区的独立目录，GRUB 通过该分区 UUID 找到文件；原 `/boot` 内核文件逐个核对哈希未变，默认仍是 Ubuntu。实验仅用一次性启动，结束后恢复 Ubuntu、原防火墙、空 GRUB 单次启动设置和无跟踪/DSM 线程的状态。未使用业务盘、生产服务或公司文件。

```sh
python3 scripts/ssi-lab/check-ioctl-admission.py probe.json
python3 -m unittest discover -s scripts/ssi-lab -p 'test_ioctl_admission.py'
```

真实探针必须显式指定 PF20 独占研究内核，前置检查拒绝已有实验进程、跟踪和相关端口双向的任何 TCP 状态。TIME_WAIT 自然结束前不创建新实例。公开证据去除地址与本机路径，保留原始工件哈希；项目脚本和文档为 MIT，内核补丁为 GPL-2.0-only。
