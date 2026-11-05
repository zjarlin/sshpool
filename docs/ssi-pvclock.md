# pvclock 页面所有权修复实验

2026-11-06 本地时间。两个专用 x86 VM 仍位于同一物理 ESXi，固定上游和 PF5 补丁集见 [设备内存实验](ssi-device-memory.md)。本次只修改研究宿主的 KVM pvclock 写入路径，未接入业务数据、磁盘、Ceph 或数据库。

## 已经复现的缺陷

`kvm_setup_guest_pvclock()` 使用 `gfn_to_pfn_cache` 缓存的宿主指针更新时钟。PF5 中，这条路径没有取得 DSM 写权限：即使页面已归另一节点，内核仍会写本地旧副本。普通 KVM 的页表与缓存有效性检查不等同于 DSM 所有权。

新的 `probe-pvclock.c` 直接使用 `/dev/kvm`。每个实例只有两个停止的 vCPU 和两页 RAM；执行代码只有一条 `HLT`，不启动发行版、网络设备或磁盘。两个 vCPU 的 32 字节时钟记录位于同一页，相隔 64 字节，另有一个标记。

每个检查按同一顺序进行：当前节点先取得页面并更新时钟；另一节点写入标记，强制转移页面所有权；当前节点再通过 KVM 更新时钟；另一节点通过 DSM 读取并逐字段比较新版本、时间、转换参数、同页另一记录与标记。探针直接观察写入方的本地记录，避免一次额外 DSM 读取意外补救错误。

PF5 单节点对照 8/8 通过，双节点 8/8 失败。例如：

| 状态 | 写入方版本 | 远端读到的版本 |
| --- | ---: | ---: |
| PF5，页面转移前 | 4 | 4 |
| PF5，页面转移后再更新 | 6 | **4** |
| PF6，同样操作 | 6 | **6** |

PF5 的内核确实完成了新版本写入，远端却仍取得旧记录；这不是只有日志告警的推断。完整原始字段、四组运行结果和 VM 关闭记录见 [机器可读证据](evidence/ssi-pvclock-probes-20261106.json)。`test_probe_pvclock.py` 从原始字段重新计算结果，不采信记录中的通过标记，并覆盖旧快照、奇数版本、零时间与同页数据损坏。

## PF6 修复及范围

`experiments/kernel-dsm-pvclock.patch` 在 DSM 模式的 KVM pvclock 写入之前获取整页写权限，完成奇偶版本更新和原有脏页记账后释放。DSM 网络等待发生在获取 `gpc` 自旋锁之前。缓存刷新失败也会释放已经取得的权限；获取失败会保留错误日志并请求下一次时钟更新。

未启用 DSM 时保持原路径。没有绕过 watchdog、修改 guest 内核或重写时钟版本协议。本补丁只覆盖 `vcpu->arch.pv_time`，尚未覆盖 Xen 的用户地址缓存、Hyper-V 时钟页、steal-time、异步缺页完成记录及其他直接指针访问。

| 项目 | 结果 |
| --- | --- |
| PF5，同一 KVM 实例中的两条时钟记录 | 8/8 通过 |
| PF5，两个 KVM 实例跨节点交接 | 0/8 通过，两个方向都丢失更新 |
| PF6，同一 KVM 实例中的两条时钟记录 | 8/8 通过 |
| PF6，同一二进制的跨节点交接 | 8/8 通过 |

之后用新的 KVM 实例再次运行双节点探针，仍为 8/8 通过。更新后的协调器也在完整客体运行时拒绝了已经占用的 DSM 端口，没有启动新探针；客体退出后再执行成功。

探针在每个 VM fd 关闭后才报告 `closed`，协调器等待两边进程退出后才输出最终结果。双节点关闭阶段仍有 `ktcp_receive -104/-4` 等已知连接退出错误；这些没有被定义为无害。探针通过只证明这组串行控制下的页面交接，没有证明并发读写无撕裂、故障恢复、所有缓存路径或长期时钟正确。

PF6 内核为 `7.1.0-rc3-sshpool-gvm-pf6`，构建 #9，SHA-256 为 `207f9bc82b4b5a07ab69d9505efc3a630559c1439977378ef566db6dbf630146`。四组接口测试使用完全相同的探针二进制，SHA-256 为 `86f12c44e32069272174d1768e30d494fb126bdfb97d51aa60edd85ba3987756`。从固定上游重新应用补丁得到的 `x86.c` 与实际编译文件逐字节一致。

## 完整客体结果与剩余问题

使用相同的 TSC offset QEMU 候选和 Ubuntu/Alpine 客体，只将宿主换为 PF6。单节点对照通过；一次完整双节点运行也通过了 SSH、32 次跨 CPU 时钟采样、四线程内存测试、1 MiB SFTP 收发删除与 S5 正常关机，两边 QEMU 返回 0，总耗时约 1166 秒。输出见 [完整客体证据](evidence/ssi-pvclock-workspace-20261106.txt)。

本轮没有再观察到之前的 TSC warp、TSC unstable 或 kvm-clock 零读数。但是仍有以下明确失败项，完整工作区继续未通过：

- RTC 报告 `hctosys: unable to read the hardware clock`，启动检查器已增加这条拒绝规则。
- watchdog 因读取间隔过长跳过了一些检查。不能用这些未执行的检查证明稳定。
- CPU 2 的 20 ms 睡眠实际约 6.97 秒；时钟采样通过不代表调度延迟可用，也未达到接近多机算力之和的目标。
- DSM 关闭阶段仍有连接错误。实际关机与 QEMU 退出 0 不覆盖这些错误。

下一步需要定位调度/页面交接延迟和 RTC 读取失败，并实现可区分正常退出与节点失联的关闭协议。持久块设备、Docker 和数据库仍需在这些基础问题解决后独立验收。

## 重现

在 PF5 的补丁集之后应用此补丁，更改 `LOCALVERSION` 为 `-sshpool-gvm-pf6` 后另行构建，保留原版内核为默认，通过 `grub-reboot` 一次性启动。安装时仍使用独立暂存目录，不覆盖宿主 `/lib` 链接。

```sh
patch -d GVM-kernel -p1 < scripts/ssi-lab/experiments/kernel-dsm-pvclock.patch
x86_64-linux-gnu-gcc -O2 -Wall -Wextra -Werror -static \
  scripts/ssi-lab/probe-pvclock.c -o probe-pvclock
# 将同一二进制放到两个独占实验节点的 ~/ssi/probe-pvclock。
python3 scripts/ssi-lab/probe-pvclock.py \
  --ssh-config /path/to/verified-lab-ssh-config \
  --host lab0 --host lab1 --peer 192.0.2.10 --peer 192.0.2.11 \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf6 --log pair.log
```

单节点对照只提供一个 `--host`，省略 `--peer`。协调器要求严格 SSH 主机密钥校验，不覆盖已有日志，并在启动前通过 `ss` 拒绝已占用的 DSM 监听端口。二进制再检查实际内核、架构和 DSM capability。端口检查不能代替独占实验节点，底层 DSM 协议也尚无本项目实现的认证。

每个远端进程有 180 秒外层时限，单次响应等待 45 秒。超时不能保证终止卡在内核中的操作，异常退出必须再核对实验 VM；不能仅凭本地 SSH 结束认定远端释放完成。不要直接对业务宿主运行。

本轮结束后，两台专用实验 VM 均正常重启回原版 `6.8.0-147-generic`。已核对管理 SSH、`/lib -> usr/lib`、无 QEMU/DSM/探针残留及无待执行的 GRUB 启动项。业务 VM、公司文件与隧道配置未改动。
