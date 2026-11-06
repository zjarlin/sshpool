# 异常请求接收与同页锁取消

2026-11-06。PF11 在 PF10 上修复接收缓冲区容量检查、异常分支回收和接收线程的页锁取消。两台专用 x86 VM 的限定探针通过，原始事件与运行时哈希见 [实验数据](evidence/ssi-request-safety-20261106.json)。

两台 VM 仍在同一物理 ESXi 上。本轮不证明跨物理机算力相加、超单机内存或故障接管；Ceph、持久磁盘、Docker、数据库资源聚合均未交付。原版 Ubuntu 继续作为默认引导，研究内核仅一次性启动。

## 修复边界

原 `ktcp_receive` 允许最多 4096 字节的传输载荷，调用者却可能只提供 24 字节请求或 1 字节失效确认缓冲区。原代码先复制，再在处理器中检查长度，检查发生得太晚。

PF11 为接收接口增加容量参数，三个调用点分别提供 `sizeof(req)`、`sizeof(u8)`、`PAGE_SIZE`。直接接收和事务缓存取出共用同一个复制前检查，超容量返回 `-EMSGSIZE` 并释放接收缓冲区；调用路径保留该返回值。外层帧长度仍先检查在 14–4110 字节范围内。发送端拒绝超过 PAGE_SIZE 的载荷，并清零固定帧未使用的尾部；没有声称清除了所有 C 结构体内部 padding。

处理器在取得 SRCU、访问请求描述数组和页状态之前检查完整请求长度、类型、SMM 字节以及 requester/sender 范围。SMM 在线结构从 `bool` 改为等宽的字节，避免编译器认为 `bool` 不可能大于 1 而优化掉检查。非法请求返回 `-EPROTO`，不是触发 WARN 后直接泄漏临时页面。内部不变量的 WARN 保留，但改走 SRCU/页锁的统一清理出口。

只有接收处理器改用 `dsm_lock_killable`；其他使用 `dsm_lock` 的路径维持原契约。失败时不解锁未持有的 mutex；取锁成功后再次检查停止信号，处理取消和取锁同时发生的竞态。退出仅将本地主动停止的 EINTR/EPIPE 归为正常，不抹掉协议错误。删除了末尾等根线程停止的停车循环，错误处理器可以先退出，由根线程稍后 join。PF8 已在唤醒线程之前持有 task 引用，此次真实提前退出与 VM 关闭验证了这一生命周期。

## 异常帧与资源证据

探针创建真实 KVM VM 和 DSM 监听器，不运行 vCPU。每个异常用例新建一条连接及八个处理线程，发送完整的固定帧，观察一个处理器返回指定错误；随后关闭对端，让其余七个处理器以 ECONNRESET 退出。最后在同一 VM 注册一页确定性内容，再验证正常 READ 与 INVALIDATE。

十五个用例为：

- 载荷长度 0、1、23、25、4096 字节。
- 请求类型 3、255；SMM 字节 2。
- requester 为 2、255、本机 0；sender 为 2、255。
- 外层声明长度 13、4111 字节。

每台节点的最终记录各包含 128 次真实临时页分配和 128 次匹配释放，129 个 DSM 线程全部退出。检查器按 PID、分配指针、调用位置和时间顺序核对，不以无崩溃或退出码代替释放证据。两次超容量请求返回 EMSGSIZE，其余非法请求返回 EPROTO；非法请求没有获取 KVM SRCU 或页锁。正常响应页 SHA-256 为 `f1a9116e64d5ce92231de69558afad42a650a9ee7ad481813ef824d649784ded`，失效确认值及固定帧尾部均为零。

最终异常用例分别保存 2915 / 2912 条事件，无 buffer overrun、dropped event 或 kprobe missed。VM 关闭约 11.33 / 17.32 ms。时间是单次实验观测，不是长期延迟保证。

## 页面锁竞争

先将同一页正常交给模拟节点 1。第二个 READ 使真实处理器取得页锁，再向该节点转发；受控对端暂不回复。第三个 READ 进入相同 `(slot, vfn)` 的页锁，并保持没有返回。

只向第三个请求的线程 `tgkill(..., SIGKILL)`，不取消根线程、不关闭 VM，也不释放持锁者的网络响应。两节点的等待者分别在约 2.034 / 2.486 ms 内返回 EINTR、释放 KVM SRCU 和临时页并退出。事件证明它没有调用 `dsm_unlock`，持锁者此时仍未解锁。

然后才发送确定性页面响应，原持锁者正常完成，返回相同页面、版本、copyset 和事务号。每台的八个临时页面全部配对释放；关闭约 38.49 / 48.70 ms。事件数为 471 / 462，无跟踪遗漏。故障取消的 `-4` 及根线程收到的 `-4` 继续保留在日志中。

第一次页锁实验使用 `/proc/stack` 查找包装函数，但编译器尾调用优化隐藏了函数名，因此两台都超时，不能算通过。最终探针使用真实取锁入口与返回事件识别等待者。另一次异常帧实验遇到线程恰在读取 `/proc/stack` 时退出的 ESRCH 采样竞态；探针修正为有限重试。失败尝试的原因、原始记录哈希、日志和清理结果均保留。没有修改候选内核来配合探针。

## 构建与复现

在 PF10 源码上应用 `scripts/ssi-lab/experiments/kernel-dsm-request-safety.patch`，共修改五个文件。候选、实际编译源和零 fuzz 重放结果逐字节一致；配置仅修改 LOCALVERSION。PF11 为 `7.1.0-rc3-sshpool-gvm-pf11`，构建 #14。

```sh
patch --fuzz=0 -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-request-safety.patch
GVM-kernel/scripts/config --file kernel-out/.config --set-str LOCALVERSION -sshpool-gvm-pf11
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- olddefconfig
make -C GVM-kernel O="$(pwd)/kernel-out" ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -j4 bzImage modules

# 仅在核对身份后的独占 PF11 实验 VM 运行，回环端口由临时实验规则放行。
sudo python3 scripts/ssi-lab/probe-request-safety.py \
  --worker ./probe-dsm-request --require-kernel 7.1.0-rc3-sshpool-gvm-pf11 \
  --mode malformed --output new-malformed.json
python3 scripts/ssi-lab/check-request-safety.py new-malformed.json
# 单独使用 --mode lock-cancel 与新证据文件验证页面锁竞争。
```

依赖同目录 `probe-request-cancel.py`、`probe-receive.py`、`trace-teardown.py`；检查器依赖 `check-teardown.py`。保留现有端口占用与内核版本检查，不向未修复的旧内核发送故意超长的完整帧。临时防火墙必须在实验后逐项恢复。

内核 SHA-256 为 `a082c9d3bc8a649abe636824b0b48d4066a8ea31caa82ac23576aca0e0a87e3d`，运行包为 `50acb1e156736e753ba8c4babe26db7640402f666c62f8d00f1e65fc64e32157`。内核补丁遵循 GPL-2.0-only，原创探针和检查器遵循仓库 MIT。

## 仍待验证

动态证据覆盖直接接收请求、合法失效确认发送和一个真实同页锁竞争。事务缓存取出超长响应、接收超长失效确认、内部 INITIAL/owner 不一致分支尚未单独注入；不能把共用函数的静态审查当作这些路径全部通过。当前未启用 KASAN，也没有完成协议认证、重放防护、全局失败协调或正常关闭握手。

PF10 的缺失槽取消回归约 6.15 ms、直接关闭约 28.72 ms，均通过原检查器。跨节点 pvclock 八次交接通过。

完整无磁盘客体回归约 261.35 秒，SSH、两次 4 MiB 分配的八轮内存校验和 1 MiB SFTP 往返通过，SFTP 哈希仍为 `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`。客体输出 S5 与 `Power down`，两边 QEMU 退出 0，关机 SSH 返回 255；采样工具无错误。

32 次时钟采样没有倒退，但四个 20 ms 定时器实际约 27.59、2353.99、21.56、38.78 ms；第二个违反原定 250 ms 上限。客体还有三次 watchdog 跳过检查和多次 workqueue `hogged CPU`。**完整工作区仍然验收失败。** 与 PF10 单次记录不同，不能据此确认 PF11 导致性能退化，也没有放宽验收门槛。

节点 0 的八条接收 `-104`、八条处理器 `-104` 与根线程 `-104`，节点 1 的一条 `-4` 均保留，限定宿主日志没有新增 WARNING/BUG/Oops/段错误。新增处理器日志来自本轮将静默 debug 输出改为明确错误报告，不能当作错误首次发生的证据。整体 SSI 仍须满足时钟、watchdog、持久 I/O、Docker、数据库与物理故障门槛。

本轮结束，两台专用 VM 均恢复到原版 `6.8.0-147-generic`，身份与 SSH 核对通过，`/lib -> usr/lib` 保留，没有待执行 GRUB 项、实验进程或跟踪残留；防火墙与实验前完全一致。构建用 Lima 恢复停止状态。业务主机、公司文件、数据库和生产隧道没有参与实验。
