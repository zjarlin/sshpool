# 跨节点设备操作的完成边界

后续协议 5 的 [路由启动版本实验](ssi-router-startup.md) 发现旧主节点仍可执行客体；再后的 [双端封存启动器](ssi-launch.md) 已验证四种混配都在双方执行前拒绝。该场景通过启动器入口标为 verified，直接调用旧 QEMU 的缺陷仍在。下面保留 2026-11-06 的原始实验结论。

2026-11-06。实验仍只使用同一 ESXi 上的两台独占 x86 VM、PF7 研究内核和无磁盘 Ubuntu 客体。测试对象是 QEMU 自带 EDU 设备，没有接入 Ceph、公司目录、Docker 或数据库。这不是跨物理机容量或故障冗余的证明。

## 要验证的契约

本地 KVM 的普通 MMIO 退出路径在 `address_space_rw()` 返回后才恢复 vCPU；原远端路径只发送写请求就恢复 vCPU，接收端何时实际执行设备操作并没有确认。因而客体可能先发布共享内存状态，另一个 CPU 随后读到设备旧值。

这里选择与本地同步设备模型一致的更强完成边界。不能据此断言所有真实 PCI 设备都承诺“互斥锁加 mfence 等于设备写入已完成”：PCI posted write、驱动的读回刷新与设备异步处理仍需遵循各自规范。完成确认也不等于 `fsync`、设备 flush、DMA 完成、数据库提交或数据已经复制到 Ceph。

## 可复核的实验

`guest-io-order.c` 只允许作为专用客体 PID 1 执行，并要求启动标记、四个在线 CPU、未绑定驱动且 ID 为 `1234:11e8` 的 EDU 设备。它不操作 RTC、磁盘、DMA 或中断。四个线程固定在四个 CPU，在同一互斥锁下读写 EDU 的存活寄存器；每轮有屏障，共 64 轮、256 次检查。寄存器返回上一写入值的按位取反，程序同时维护共享内存中的期望值。

普通单节点和双节点基线均为 256 次检查、零差异。为扩大真实网络交付与设备执行之间的时间窗口，独立诊断补丁仅在接收端对地址 `0xfeb00004` 的四字节写入、且显式设置 `SSHPOOL_LAB_EDU_DELAY_US=50000` 时睡眠 50 ms。延迟发生在设备全局锁外，随后仍调用真实设备操作；没有伪造读取值。其他设置或已持有 BQL 时立即报错。

第一次延迟基线报告 23 次差异，但 stderr 插入了一条串口记录，检查器拒绝不完整明细。该次关机后 QEMU 还发生段错误，地址定位到 `vm_state_notify`；尚未证明具体竞态。保留原始失败，不将其当作完整验收。

分开 stdout/stderr 后的第二次延迟基线，256 次检查中 23 次读到旧值，全部明细与累计数量一致，两端退出 0。两次实验都注入了 128 次远端寄存器延迟。这个对照定位的是操作完成边界，不证明之前的 RTC 或 watchdog 告警由它引起。

完成确认候选在恢复干净的实验宿主后，通过相同 initramfs、相同 128 次延迟下的全部 256 次检查，两端退出 0。原始串口、诊断输出、运行时哈希、宿主日志、vCPU 采样及失败干预记录见 [实验数据](evidence/ssi-device-order-20261106.json)。不使用三次不同启动过程的耗时推算性能倍数。

## 候选补丁

`qemu-mmio-completion.patch` 在接收端实际执行 `address_space_rw()` 后返回写完成标记。发送端持有连接锁直到收到该标记，避免响应被下一请求消费。读取仍返回原来的数据格式；新增对短读、连接错误、非法 MMIO 长度和错误确认的检查。设备自身的 `MemTxResult` 语义与原本地路径一致，完成标记不承诺设备接受了所有地址或完成内部异步工作。

启动时钟握手的协议版本升为 2，两端须使用同一候选。该版本检查用于防止旧、新二进制混用后把响应解析错位；不能代替完整协商、断连超时或请求排空机制。PIO、PCI 配置广播与双向设备回调没有在本补丁中改成同步确认。

实际将旧版本作为节点 0、新版本作为节点 1：新节点在启动握手明确报告 `Protocol error` 并退出 1，未进入客体探针；旧主节点仍需外层 30 秒 timeout 终止（SSH 返回 255），之后两边没有 QEMU/DSM 线程残留。这个方向的拒绝已验证，但反向混配与双方协调退出仍未完成，因此当时协议场景保留 partial。

首次候选运行未进入客体测试：节点 1 的 DSM 监听返回 `-98`，节点 0 随后页请求返回 `-111`。现有端口检查只检查监听状态，未涵盖连接关闭期间的端口占用；已将实验前置检查扩展到全部 TCP 状态。SIGTERM 未完成回收，追加 SIGKILL 后仍有一个线程组未回收。节点 0 正常重启恢复，节点 1 正常重启未恢复 SSH/guest tools，最终只对已核对归属的实验 VM 52 执行 ESXi reset。没有修改研究内核去掩盖这些错误。这是启动/清理路径的待修问题，不能记为设备测试通过。

新的 `run-node.sh` 已在有实验监听器时实际拒绝启动。另一次尝试捕获 TIME-WAIT 拒绝时，检查前端口已经释放，脚本因而启动了默认无磁盘实验进程；未启动配对节点，随后按确切进程路径与实例名终止。该次操作保留为测试干预记录，不作为 TIME-WAIT 拒绝证据。全部状态前置检查仍有检查与实际绑定之间的竞态，不能替代内核层的启动握手和错误回收。

后续在节点 1 实际观察到端口 `37711/40001` 的 TIME-WAIT，使用 `QEMU=/usr/bin/false RUN_SECONDS=1` 再验证，脚本明确输出端口占用并退出 1。这个安全后备确保即使连接刚好消失也不会启动客体。证据中保留两次不同操作，不能用后一次成功覆盖前一次测试干预。

## 普通候选与完整工作区回归

不包含诊断延迟代码的候选 SHA-256 为 `45eeeabe124051c2d40d763313d6c1941fd23b4ce1c57aaf6e6f2466e6fd4156`。单节点及普通双节点 EDU 测试均为 256 次检查、零差异，两端正常退出。

随后在同一候选上运行原有无磁盘 SSH 工作区，流程约 212.99 秒。SSH 身份检查、时钟程序执行、两次 4 MiB 分配的八轮共享内存校验、1 MiB SFTP 往返均完成，文件 SHA-256 一致。客体输出 S5 与 `Power down`，两端 QEMU 退出 0；执行关机命令的 SSH 连接被远端关闭，命令返回 **255**，不是所有命令都退出 0。

**完整验收仍失败。** 四个 CPU 的有限时钟样本没有倒退，但一个 20 ms 定时器耗时约 1.04 秒，超过既有 250 ms 门槛；启动还丢失一个 RTC 中断、两次跳过 watchdog 检查。关闭时节点 0 保留八条接收 `-104` 和根线程 `-104`，节点 1 保留两条 `-4`；本轮宿主日志没有新增 WARNING/BUG/Oops/段错误。未关闭 watchdog、修改定时器预算或把 EOF 错误改成成功。

这次完整流程既不能证明长期可用，也不能把单次延迟变化归因到完成确认补丁。证据中的 `workspace` 保存全部相关日志；CI 明确要求保留时钟预算和启动门槛失败这一事实。

## 复现与边界

在 [传输实验](ssi-transport.md) 所列 PF7 内核和时钟候选 QEMU 的独立源码目录上应用 `qemu-mmio-completion.patch`。需要受控延迟对照时再应用 `qemu-edu-delay.patch`；两种组合都已重新应用到源码，并与实际编译文件逐字节核对。诊断补丁不进入默认部署路径。原始路由文件及各个编译候选的 SHA-256 保存在证据的 `compiled_router_sha256`，运行二进制哈希随每次实验保存。

```sh
cc -O2 -Wall -Wextra -Werror -static -pthread \
  scripts/ssi-lab/guest-io-order.c -o guest-io-order
# 在独立 initramfs 根目录将程序安装为 /init，按上级实验说明打包。
# 客体额外参数：-device edu,addr=0x2
# 内核命令行：rdinit=/init sshpool_io_order_probe=1
# 诊断运行显式设置：SSHPOOL_LAB_EDU_DELAY_US=50000
# stdout 和 stderr 分别保存，避免诊断文字插进串口记录。
python3 scripts/ssi-lab/check-io-order.py guest-serial.log
```

完成两节点独占、运行时哈希、研究内核、防火墙和所有 TCP 状态检查后，在两边分别运行下面命令；第二节点改 `node=1`。示例使用保留地址，须替换为实验节点地址。两个节点只能启动这一组实例，不挂载宿主目录或磁盘。

```sh
node=0
runtime="$HOME/ssi"
# 防止重跑时覆盖已有证据。
set -C
# 延迟对照使用单独的诊断二进制并显式设置此环境变量。
export SSHPOOL_LAB_EDU_DELAY_US=50000
timeout --kill-after=5 600 "$runtime/qemu-system-x86_64-mmio-completion-delay-1" \
  -name "sshpool-io-order-$node,debug-threads=on" \
  -machine pc,accel=kvm,kernel-irqchip=split \
  -cpu qemu64,-x2apic,+tsc-adjust,enforce \
  -smp 4,sockets=2,cores=2,threads=1 -m 256 \
  -nodefaults -display none -serial stdio -monitor none -no-reboot \
  -L "$runtime/pc-bios" -kernel "$runtime/guest-vmlinuz" \
  -initrd "$runtime/guest-io-order-initramfs.cpio.gz" -device edu,addr=0x2 \
  -append 'console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic sshpool_io_order_probe=1' \
  -local-cpu "cpus=2,start=$((node * 2)),iplist=192.0.2.10 192.0.2.11" \
  > "guest-$node.log" 2> "qemu-$node.err"
```

单节点对照移除 `-local-cpu` 并只启动一个 QEMU；普通候选改用不含延迟补丁的二进制。两种双节点对照保持同一客体镜像。研究内核发生不可中断等待时，外层 timeout 无法保证清理，因此必须准备仅作用于实验 VM 的恢复通道。

检查器从失败明细重新计算每轮累计数，核对全部轮次、CPU 覆盖、结果与退出标记。QEMU 退出 0 不等于客体测试通过，记录缺失也不会被当作零失败。CI 重新解析已保存的真实证据并编译探针；不在 GitHub runner 上伪装执行双节点研究内核。

余下验收包括协议故障注入、RTC/时钟、启动和关闭协议、持久块设备、Docker、PostgreSQL/Redis、跨物理机容量和故障接管。完整 SSI 仍未交付。

本轮结束，两台实验 VM 已恢复到原版 `6.8.0-147-generic`，管理 SSH 正常，`/lib -> usr/lib` 保留，无 QEMU/DSM/探针残留、无待执行 GRUB 项。原实验防火墙保持，本轮没有增删规则。业务主机、公司文件、数据库和生产隧道未参与实验。
