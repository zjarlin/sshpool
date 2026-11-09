# KVM 请求频率与实际计时

在两台原版 `6.8.0-147-generic` 实验 VM 上，`KVM_SET_TSC_KHZ` 接受升频到 **2,873,248 kHz**，运行后 `KVM_GET_TSC_KHZ` 仍报告同一值，但客体 RDTSC 的实测速率保持在原生 **2,394,374 kHz** 附近。降频到 **1,915,499 kHz** 返回 `EINVAL`，GET 却已经报告该请求值。设置和读回成功不能作为真实频率缩放的证据；设置失败后也不能假定临时 vCPU 状态完全未变。

现有 Rust 预检与 QEMU 的不同频率拒绝保持生效。实验不改变宿主频率，不安装研究内核，也不把此次结果接入默认运行时。

## 测量方法

[探针](../scripts/ssi-lab/probe-tsc-frequency.c)先核对精确内核和架构，再创建一个标准 KVM VM、一个 vCPU、64 KiB 匿名内存；没有磁盘、网络设备或 DSM。观测线程与 vCPU 线程固定到不同的许可 CPU。完成寄存器、内存、TSC 和 pvclock MSR 初始化后才设置频率，避免设置后的初始化覆盖待测状态。

客体的 82 字节程序使用共享内存请求/响应握手。每次请求前记录宿主 `CLOCK_MONOTONIC_RAW`，客体复制一份版本号为偶数且前后相等的 pvclock 记录，在两个 LFENCE 之间执行 RDTSC，再发布响应；宿主观察响应后记录上界。十二个样本相隔约 100 ms，共调用一次 `KVM_RUN`，最终必须得到 HLT 和 RIP `0x1052`。一次用户态调用不等于没有内部 VM exit；pvclock 版本确实发生了多次更新。

对样本 a、b，真实间隔落在：

```text
elapsed_ns ∈ [b.before − a.after, b.after − a.before]
TSC_kHz ∈ [ΔTSC × 10⁶ / elapsed_max, ΔTSC × 10⁶ / elapsed_min]
pvclock_ns = system_time + (((guest_tsc − pvclock_tsc) 按有符号 shift 移位) × multiplier >> 32)
```

检查器用整数和有理数运算重算边界，输出时才转为浮点数。固定排除首次进入，以样本 1→11 报告总体包络，同时检查其间每个相邻区间，防止中途跳变被平均值掩盖。每段的整个 RDTSC 包络必须位于原生频率 ±0.1%，pvclock 速率包络必须位于 1±0.1%；升频请求的容差区间必须与实际包络不相交。首样本握手上限 100 ms，其余 10 ms，间隔限制 90–500 ms；这些是验收门槛，不是实时性能保证。

宿主 RAW 的 clocksource 也是 TSC，因此这里只衡量嵌套客体相对于其 Linux 宿主的速率，没有独立外部 UTC 参考，也不证明物理振荡器绝对精度。两台 Linux VM 属于同一个物理 ESXi，不能计为两个物理故障域。

## 实际结果

| 节点 | 请求 | 实测 TSC 包络（kHz，显示时向外取整至 0.001） | pvclock 速率包络 |
| --- | --- | --- | --- |
| node0 | 原生 | [2,394,339.065, 2,394,382.938] | [0.999985409, 1.000003733] |
| node0 | 升频 20% | [2,394,371.560, 2,394,377.085] | [0.999998980, 1.000001288] |
| node1 | 原生 | [2,394,371.015, 2,394,381.016] | [0.999998752, 1.000002930] |
| node1 | 升频 20% | [2,394,371.732, 2,394,376.565] | [0.999999052, 1.000001071] |

两个降频请求都以 `SET=-1, errno=22` 结束，没有样本或 `KVM_RUN`，直接关闭三个 fd。四次执行均正常 HLT，结束后没有遗留实验进程或 KVM fd；精确内核、启动配置、模块、machine-id/DMI/boot 摘要、防火墙与端口范围前后一致。内核仅新增预期的 `user requested TSC rate below hardware speed` 日志。

完整[清单及压缩原始记录](evidence/ssi-tsc-frequency-20261109.json)包含六组正式运行、两份启动前失败、四份早期诊断、实际探针与采集器源码、对应内核源码及按 ELF 符号截取的反汇编。早期 v2 诊断没有 RDTSC 后的 LFENCE，也没有运行后 GET；v3 补上这两项，结果未改变。诊断记录缺少正式前后状态，不计入正式验收。

首次正式采集在启动可执行文件时因权限位缺失失败，尚未创建 KVM。修正实验文件权限后用新文件保存运行，原始失败保留。检查器和测试要求失败记录没有运行、节点状态一致，不能将其删除或算成测量通过。

## 新 ESXi 候选与不同频率拒绝

2026-11-09，重装为 ESXi 的独立物理机上，一台专用副本在断网启动后重建了 machine-id、D-Bus 身份和 SSH 主机密钥，并按新 MAC 修正 Netplan 与 DHCP 身份。重启后身份持久化、boot-id 改变，随后才连接实验网。身份审计与以下采集通过摘要对应；另一台预存副本保持关机。

同一 v3 探针、二进制和原版内核在候选上得到：

| 请求 | 实测 TSC 包络（kHz，向外取整至 0.001） | pvclock 速率包络 |
| --- | --- | --- |
| 原生 2,095,148 kHz | [2,095,146.994, 2,095,148.800] | [0.999999519, 1.000000381] |
| 升频 2,514,177 kHz | [2,095,147.051, 2,095,148.846] | [0.999999546, 1.000000403] |

升频 SET 和运行后 GET 均成功，实际 RDTSC 仍为原生速率。降频至 1,676,118 kHz 返回 `EINVAL`，GET 已报告该请求值；临时客体未执行，三个 fd 全部关闭。前后身份、启动配置、模块、防火墙一致；归档后删除本轮临时目录，再次核对无实验进程或 KVM fd。候选 VM 保留原版内核并继续开机，供后续隔离实验使用。

真实 Rust CLI 预检把原节点 **2,394,374 kHz** 与候选 **2,095,148 kHz** 组合，退出码为 **2**，唯一 blocker 为原生频率不一致；双方均无 `KVM_CAP_TSC_CONTROL`。检查器把每端两个 vCPU 的预检频率与该节点实际采集的原生频率、machine-id 摘要关联，Rust 测试重新执行 `ssi::assess` 并逐字段比较报告。三种请求模式也必须具有相同原生频率，不能为不同模式拼接不同机器的样本。

新[候选清单](evidence/ssi-tsc-frequency-candidate-20261109.json)通过 SHA256 引用已冻结的双节点基线，重放时仍校验历史失败与源码。公开记录只保留身份摘要与归一化节点名；重启前后的网络配置确实经过修正，不声称整个准备阶段配置未变。空 VM 预检仍报告 `physical_topology_verified=false`、`running_clock_verified=false`、`full_ssi_accepted=false`。分别在两个物理宿主测量不等于同一客体已跨物理运行。

接入阻塞在频率比例，而非一个固定起点偏移。当前运行时只加减 TSC offset；即使某一时刻对齐，两个原生速率仍不同。后续需要证明 L0/L1 实际暴露且执行了硬件缩放，或在独立候选中实现完整时间虚拟化，并一并验证 RDTSC/RDTSCP、pvclock、定时器及暂停恢复。仅重写 CPUID 频率、周期性补 offset、放宽容差或成功调用 SET 都不能满足准入。

## 原版内核解释及边界

归档源码来自 Ubuntu `Ubuntu-6.8.0-147.147` 的 `arch/x86/kvm/x86.c`，与所运行内核版本对应，而非 PF30 的 7.1 研究内核：

- `kvm_set_tsc_khz` 在调用 `set_tsc_khz` 之前写入 `virtual_tsc_khz` 和转换参数，因此后续失败也能留下新的 GET 值。
- 没有硬件缩放时，`set_tsc_khz` 对高于原生的请求开启 `tsc_catchup`/`tsc_always_catchup` 并返回成功，对低于原生的请求返回失败。
- GET 直接返回 `virtual_tsc_khz`，不测量客体实际执行的 RDTSC。
- pvclock 更新使用的实际频率及 masterclock 缓存与 catch-up 路径有关。源码可以解释为何 ioctl 成功不足以证明缩放；本轮没有动态跟踪这些分支，不能声称已经定位此单 vCPU 观测结果的全部原因。

有限的一秒左右窗口不能证明多 vCPU、任意负载、暂停恢复、跨物理长期漂移或定时器行为。独立候选已完成身份隔离和单 vCPU 实测；下一步仍需评估硬件缩放暴露或经过验收的时间虚拟化方案，不能删除频率相等检查来绕过它。

## 重放与复现

普通 CI 只重放证据、运行反例测试，并在 Linux 编译探针及验证错误内核拒绝，不启动实验 VM：

```sh
python3 scripts/ssi-lab/check-tsc-frequency.py docs/evidence/ssi-tsc-frequency-20261109.json
python3 scripts/ssi-lab/check-tsc-frequency.py docs/evidence/ssi-tsc-frequency-candidate-20261109.json
python3 -m unittest discover -s scripts/ssi-lab -p 'test_tsc_frequency.py'
cargo test --locked --test ssi_preflight
```

在已隔离且至少有两个许可 CPU 的原版 x86 Linux VM 上，先编译、核对产物哈希与文件执行权限，再运行采集器；输出必须是新文件：

```sh
cc -O2 -Wall -Wextra -Werror -static -pthread probe-tsc-frequency.c -o probe-tsc-frequency
sudo python3 capture-tsc-frequency.py --require-kernel 6.8.0-147-generic \
  --binary ./probe-tsc-frequency --binary-sha256 <实际SHA256> \
  --source ./probe-tsc-frequency.c --output <新记录.json>
```

反例测试覆盖伪造频率元数据、宿主时间、单个 TSC 跳变、pvclock 版本与换算、错序/缺样、过宽/倒退包络、错误 HLT、缺少关闭、设置失败后执行、遗留 fd、源码和归档哈希破坏。预检与默认运行时准入不因这些限定实验变更，严格 SSI 仍未完成。
