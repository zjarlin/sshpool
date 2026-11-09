# 同一 KVM 实例的双 vCPU 计时实验

2026-11-09，专用 Linux VM 复用 [PF32 软件 TSC 缩放内核](ssi-tsc-scaling.md)，完成三组交替执行的双 vCPU 矩阵。**最后一组的全部速率包络通过 ±0.1% 检查，但四个共同偏移配置均未建立 ±100 微秒的跨 vCPU 对齐界限。** 有意注入的 50 毫秒偏移在三条 TSC 路径上全部检出。

未建立界限的样本仍与允许区间相交，因此只能判为测量不确定，不能据此断言内核存在超过 100 微秒的真实偏差。检查器保留全部三组结果，不挑选第二组中通过的原生与降频运行来宣称整体完成。

## 范围和采样方法

每次探针创建一个 KVM VM 和两个 vCPU，分别使用 64 KiB 客体地址区间和独立 pvclock 页面。先为两个 vCPU 显式选择软件缩放、配置相同比例，再设置并读回共同 TSC offset。目标频率沿用已有实际预检：本节点原生 2,095,148 kHz，另一物理节点目标 2,394,374 kHz；升频和降频分别为原生的 6/5 与 4/5，整数截断。负对照仅给 vCPU 1 增加 `requested_khz * 50` 个 TSC tick，即 50 毫秒。

两个 vCPU **顺序执行**，每轮改变先后顺序，每三轮交换宿主 CPU 绑定；观测线程绑定另一宿主 CPU。每次运行采集 12 轮，每轮每个 vCPU 各读取 RDTSC、RDTSCP、TSC MSR 和稳定偶数版本的 pvclock。AUX 分别为 `0x53534900` 与 `0x53534901`。采样后以 IO 退出，最后各执行 HLT，共 26 次 KVM_RUN，正常关闭四个 fd。运行后再次改频均返回 EINVAL，频率与 offset 读回未变。

三组的计时方式不同，实际编译源码与 ELF 分别保存：

| 矩阵 | 宿主计时边界 | 轮间等待 | 速率通过的运行 | 同时通过速率与对齐的运行 |
| --- | --- | --- | --- | --- |
| io-envelope-a | 整个 KVM_RUN | 100 ms | 无 | 无 |
| handshake-b | 客体就绪后请求，到收到采样确认 | 100 ms | 原生、降频、偏移对照 | 原生、降频 |
| handshake-c | 与 B 相同的共享内存握手 | 500 ms | 原生、升频、降频、目标、偏移对照 | 无 |

每组均为四个共同偏移配置加一个目标频率的偏移对照，共 15 次探针运行，全部正常退出。所有矩阵的宿主前后快照相同、内核日志没有增量。另一次采集器缺少 `--software` 参数的启动失败也保留：退出码 2，未执行客体。

第一轮仅用于初始化；验收覆盖每个 vCPU 的所有相邻区间 1→2 至 10→11，以及总区间 1→11。两次读数各由宿主 `CLOCK_MONOTONIC_RAW` 前后读数包住，速率的整个可能区间必须落在请求速率的 ±0.1% 内；pvclock 对应速率为 1。非原生配置还必须排除原生速率。延长 C 的轮间等待提高了速率观测分辨率，没有放宽门槛。

跨 vCPU 验收逐轮计算“客体时间差减宿主时间差”的区间。设先后读数的宿主边界为 `[a_before, a_after]`、`[b_before, b_after]`，客体读数差换算为纳秒后为 `delta`，则偏移差范围为：

```text
[delta - (b_after - a_before), delta - (b_before - a_after)]
```

三条 TSC 路径和 pvclock 均使用同一 ±100,000 ns 门槛：整个区间位于门槛内为 `within`，完全分离为 `outside`，部分重叠为 `inconclusive`。只有全部为 `within` 才算对齐通过。不能把区间中点或最小误差作为验收值。

C 组各共同偏移配置的最大区间端点绝对值如下，覆盖全部时钟路径及轮次，向外取整至 0.001 微秒。这些数字是测量区间边界，**不是真实偏移的测定值**。

| 配置 | 最大端点绝对值（微秒） | 逐轮结果集合 |
| --- | ---: | --- |
| 原生 | 149.851 | within、inconclusive |
| 升频 | 159.425 | within、inconclusive |
| 降频 | 117.956 | within、inconclusive |
| 目标 | 109.336 | within、inconclusive |

三组负对照的每个验收轮次、每条 TSC 路径均完全离开允许区间，且包住随读取顺序变化的有符号 ±50 ms 注入值。仅仅出现宽区间或未通过对齐不足以算检出。pvclock 的换算补偿了 TSC offset，不表现为相同的 50 ms 错位；因此检查器要求三条 TSC 路径确实检出，单独保留 pvclock 结果。

## 证据与复现

[证据清单](evidence/ssi-tsc-multivcpu-20261109.json)引用三份完整原始矩阵、三份实际运行的 ELF 和一份源码归档，并通过摘要关联原 PF32 证据。检查器核对压缩文件与解压内容摘要、ELF 符号范围中的客体指令、运行源码、内核镜像、模块参数、节点和启动身份、时间顺序、全部分析及恢复记录。

```sh
python3 scripts/ssi-lab/check-tsc-multivcpu.py docs/evidence/ssi-tsc-multivcpu-20261109.json
python3 -m unittest discover -s scripts/ssi-lab -p 'test_tsc_multivcpu.py'
python3 scripts/feature-status.py --check
```

**检查器退出 0 表示归档完整、重算与保留的结论一致，不表示多 vCPU 对齐通过。** 输出分别列出 `rate_passed`、`offset_passed`、`accepted`。CI 通过也不能替代实测验收。反例测试覆盖身份/顺序/AUX 错误、同速但错位、被总平均掩盖的中间跳变、非法 pvclock、错误注入方向、配置冻结和清理缺失。Linux x86_64 CI 还编译探针并验证错误内核在打开 KVM 前退出 2。

如需新实验，先保留本次记录，再在独占 VM 使用原 PF32 镜像及显式宿主参数；不修改默认构建。当前 [探针](../scripts/ssi-lab/probe-tsc-multivcpu.c)对应 C 组，使用 `cc -O2 -Wall -Wextra -Werror -static -pthread` 编译。采集器从原软件缩放源码归档提取 `capture-tsc-scaling.py`，在独立目录应用 [采集补丁](../scripts/ssi-lab/experiments/capture-tsc-multivcpu.patch)；测试验证所得源码与本次归档一致。为每次新实验使用新输出路径和新清单，不能覆盖或套用本次固定结果。原 A/B 源码仍在归档中。

本轮结束后已启动原版 `6.8.0-147-generic`，归档并移除本轮 PF32 内核、模块、一次性启动项和远端探针。GRUB、历史启动文件、防火墙、Netplan、apt 缓存摘要与实验前一致，无实验进程或 KVM fd；VM 保持开机。

## 尚未完成的边界

宿主 MONOTONIC_RAW 仍以其 TSC 为基准，实验没有独立 UTC 参考，也没有让两个 vCPU 同时执行。没有运行跨物理同一 Linux 客体，没有验收定时器、暂停恢复、长期漂移或数据库接管。默认运行时仍拒绝不同原生频率。

下一步先减少跨 vCPU 测量区间的不确定性，在原 ±100 微秒门槛下重新采集完整矩阵；在得到明确对齐证据后再推进并发、生命周期与双端运行时集成。现有冷启动同步和完整 SSI 场景保持原状态。
