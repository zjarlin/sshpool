# SSHPool

**一个稳定的 Linux / SSH 工作台，多台可替换的构建节点。**

**目标差距：当前产品不满足“一个 Linux/数据库实例使用多台机器合计资源”的完整 SSI 要求。** 资源池与有状态恢复仍未交付。最新 GiantVM 调研、实际 KVM/ISA 阻塞和容量边界见 [严格 SSI 可行性](docs/ssi-feasibility.md)；不要把任务调度器的验收数量当作 SSI 完成度。

**PF23 最新进展：** 修复设备固定页面仍被持有时错误封闭 ioctl 入口的问题；重复或错误类型的解除不再减计数，部分固定失败只回滚本次新增引用。两台实验 VM 的 8 组候选探针通过，保留 2 组 PF22 失败对照。完整双节点操作完成，但定时器最大 264.93 ms 超过原 250 ms 门槛，DSM 关闭仍报错，**完整 SSI 未通过**。Ceph、Docker、数据库和跨物理机接管仍未交付，见 [固定页面修复、实测与剩余范围](docs/ssi-pin-lifecycle.md)。

**PF22 事务进展：** DSM 出站事务和缓存响应持续计数到真正消费或故障回收；两台专用实验 VM 的六类探针通过。还复现并修复了 PF21 在 65,535 个活跃编号后无限重试的问题，保留失败记录。该轮双节点 SSH、内存、文件传输和三轮时钟通过，但 **DSM 关闭错误仍阻止完整 SSI 验收**，历史 RTC/时钟失败也没有被本次通过覆盖。Ceph、Docker、数据库与跨物理机接管仍未交付，见 [实现、证据和剩余范围](docs/ssi-exchange-accounting.md)。

**SSI 实验进展（2026-11-06）：** 已在同一 ESXi 的两个隔离 x86_64 节点上启动一个 Ubuntu 客体，完成同进程跨节点内存测试、SSH、1 MiB SFTP，并观察到客体关机后的 QEMU 退出；内核 DSM 正常关闭尚未通过。PF6 修复了 pvclock 绕过 DSM 写权限导致远端读到旧版本的问题，两次真实接口探针通过；见 [pvclock 修复与证据](docs/ssi-pvclock.md)。**PF11 历史内存和文件传输回归通过，但一个 20 ms 定时器耗时约 2.354 秒，超过 250 ms 门槛，仍有 watchdog 和 DSM 关闭错误，完整 SSI 工作区未通过验收。** PF10 的约 537 ms、较早实验的 RTC 读取失败和约 6.97 秒延迟均保留为历史证据，不能由单次差异推断本轮补丁的性能因果；跨物理机、超单机内存、持久磁盘、Docker、数据库和故障恢复均未验收。此前 [设备内存](docs/ssi-device-memory.md)、[时钟](docs/ssi-clock.md) 和 [SSH 工作区](docs/ssi-workspace.md) 记录保留用于对照。

**设备顺序实验：** 受控延迟下，原远端 MMIO 路径的 256 次检查出现 23 次旧值读取；增加设备执行后的完成确认，同一探针全部通过。仍是实验候选，启动/清理、时钟、持久磁盘及数据库尚未完成，见 [设备完成边界与失败记录](docs/ssi-device-order.md)。

**启动回收实验：** PF8 将本地 DSM 监听失败同步返回 QEMU；两节点的端口冲突、同 VM 重试、各 64 次启停和两种半帧关闭顺序通过。全局协调启动、在途请求排空与故障接管仍未完成，见 [启动回收证据与限制](docs/ssi-startup.md)。Ceph 尚未使用。

**关闭顺序与请求取消：** PF9 在销毁 vCPU/MMU 前停止 DSM 线程，见 [关闭顺序证据](docs/ssi-teardown.md)。PF10 修复缺失内存槽时无法取消的完整读页循环，见 [请求取消证据](docs/ssi-request-cancel.md)。PF11 为接收提供缓冲区容量并统一异常回收，两节点各十五类异常请求和同页锁取消通过实机事件核验，见 [请求安全证据](docs/ssi-request-safety.md)。事务缓存、超长失效响应、内部不变量异常和正常关闭协议仍未全部验收。

**延迟定位：** 单节点/双节点页面探针通过内容、并发写入与逐线程 ioctl 计时核验。此前捕获计时数据页上的具体缺页指令，以及一个 TCP 已确认后仍等待约两秒才响应的请求；详见 [定位与验收边界](docs/ssi-latency.md)。

**调度与资源预检：** 实测发现两台实验 VM 各有 2000 MHz CPU 总限额，并有明确 ESXi 限速计数；已仅在实验 VM 取消该限制。新增只读资源预检、调度等待分解和分块跟踪导出，见 [调度实验](docs/ssi-scheduling.md)。取消限额后的无跟踪测试有一次十二个定时器最大 86.6 ms，但仍有 watchdog 与关闭错误，不能据此宣布完整工作区或性能聚合通过。

**PF14 自旋实验：** 在没有 PLE 的实验宿主上，可显式强制 DSM 客体的 PAUSE 指令返回 KVM。已捕获真实退出并验证四个客体 vCPU 的用户态进度；开关默认关闭，完整 KVM／中断记录和同内核开关对照见 [实验结果](docs/ssi-vcpu-residency.md)。仍保留一次无跟踪 SFTP 建连超时和其余工作区失败，不能据此部署业务容器或数据库。

**PF15 宿主定时器：** KVM 返回时补上已有的延期重装处理。两侧完整跟踪的重装拖延从约 90–115 ms 降到最多 14 μs；两次三轮无跟踪时钟测试通过原 250 ms 门槛。RTC、watchdog 和关闭错误仍阻止完整 SSI 验收，Ceph、Docker 与数据库尚未接入；见 [结果、失败与原始记录边界](docs/ssi-host-timers.md)。

**RTC 路由候选：** 分布式 QEMU 禁用本地合并 PIO 注册后，两次双节点 RTC 探针各 32 次读取通过独立时间窗口核验，普通单节点保留原注册行为。首次工作区回归完成 SSH、内存和 SFTP，三轮定时器最大 66.6 ms；第二次启动却触发 DSM 页副本集合告警并失去响应，需要强制清理。**完整 SSI 仍失败，Ceph 和业务数据仍未接入。** 补丁、初步探针误判和失败现场见 [RTC 与剩余一致性问题](docs/ssi-rtc.md)。

**PF16 页副本集合：** 真实 KVM 单页实验复现了固定页面重试时提前清空副本集合的问题；候选保留尚未交出的副本集合，两节点对照通过。两次双节点工作区均完成 SSH、内存和 SFTP，三轮时钟上限保持 250 ms；正常关闭仍报 DSM 接收错误，完整 SSI 和业务存储仍未验收，见 [原因、对照与剩余范围](docs/ssi-copyset-retry.md)。

**PF17 故障传播：** 非法请求或断连现在会使实验 VM 失效，唤醒已建立连接中的等待者，并让 KVM 管理接口返回错误。真实双节点注入进一步暴露并修复 QEMU 错误转储的递归崩溃：新候选两端返回失败码 1，旧版段错误记录完整保留。这实现故障停止，正常关闭仍有连接重置，自动接管、Ceph 和业务数据恢复尚未实现，见 [故障传播实验](docs/ssi-failure-propagation.md)。

**QEMU 关闭屏障：** 协议三候选在停止 vCPU 和本地排空后核对双向确认，两个真实双节点关机对照通过该屏障。内核 DSM 仍报连接重置，完整关闭与持久化未验收，见 [路由排空与剩余关闭工作](docs/ssi-router-drain.md)。

**PF18/PF19 内核入站屏障：** 新增单条 DSM 入站流的排空确认，等待早先页面请求完成响应并释放页锁与 SRCU；七个并发请求和页锁竞争均有真实 KVM 证据，PF19 进一步在释放接收锁前锁存坏帧故障。PF19 双节点回归完成操作但仍出现启动 watchdog 告警，完整工作区未通过。全 VM 外部入口、反向请求与最终关闭尚未协调，Ceph、Docker、数据库和接管仍未交付，见 [内核入站排空实验](docs/ssi-kernel-drain.md)。

SSHPool 面向只能配置一个远程主机的 AI 编程工具、Remote SSH IDE 和终端。工作台放在可靠的宿主上，源码与编辑会话留在工作台；明确加入的项目可以把构建交给资源合适的 SSH 节点。

当前是 **0.1 实验版本**：统一 SSH、整项构建调度和隔离执行已经实现。它不提供跨机器共享内存，不会让任意程序自动获得集群所有 CPU，也不会透明迁移正在运行的进程。普通命令在工作台执行；项目 opt-in 后，支持的构建包装器自动调度。详细需求与尚未实现的目标见 [FEATURE.md](FEATURE.md)。

**登录后的 `uname`、`top`、`free` 只显示工作台资源。** `sshpool status` 查看各节点快照；实际计算节点以任务的 `attempts[].node` 和远端容器为准。已验证 ARM64 工作台提交到独立 x86_64 Linux Worker 的计算、日志、产物和清理闭环；macOS Worker 只有资源探测证据，WSL2 尚未实机验证。当前不会把 sub2api 进程的内存压力自动转移到其他设备。证据和复现步骤见 [硬件执行验证](docs/validation.md#hardware-proof)。

```mermaid
flowchart LR
  Client[AI / IDE / ssh / scp] --> SSH[稳定入口：SSH 字节流透传]
  SSH --> Linux[Linux 工作台：OpenSSH / 文件 / 编辑器]
  Linux -->|源码快照、构建请求| Controller[Rust 控制面]
  Controller -->|系统 OpenSSH| A[Linux + Docker]
  Controller -->|系统 OpenSSH| B[macOS + Docker Linux VM]
  Controller -->|系统 OpenSSH| C[Windows 内的 WSL2 + Docker]
  A -->|日志与显式产物| Controller
  B -->|日志与显式产物| Controller
  C -->|日志与显式产物| Controller
```

图中 macOS / WSL2 表示适配方向，不能视为均已完成执行验收。

## 能力与边界

- **真正的 SSH 兼容面**：复用后端 OpenSSH，透传交互终端、SFTP/scp、rsync 和端口转发。后端故障时已有连接会断开，不伪造无损迁移。
- **简单节点登记**：复用系统 SSH 别名、密钥和跳板；不在 Worker 安装常驻 Agent，不分发控制面的私钥。
- **保守调度**：检查平台、内存、磁盘、负载、并发配额；先留出业务资源。无适合节点时明确失败，不在忙碌主机上硬启动。
- **隔离构建**：容器非 root、只读根文件系统、无宿主 bind mount、无 Docker socket、默认禁网、限制 CPU/内存/PID/日志/时间。工作区为有容量上限的 tmpfs，计入内存限制。
- **数据闭环**：明确选择项目，遵循 `.gitignore`，拒绝符号链接并排除常见凭据；只取声明的产物，导出到新目录，绝不覆盖源工程。
- **谨慎重试**：编译返回非零不会自动重试。基础设施失败只有在 `idempotent=true`、禁网、旧容器确认清理且仍有重试额度时才切换节点。SSH 断线不被视为任务已经停止。
- **持久记录**：任务、节点选择、尝试与结果写入控制面私有目录。重启后核对未完成任务并记录中断，不盲目重放。容器自身还有最长存活时间。

## 快速开始

需要 Rust 1.89+、系统 OpenSSH。Worker 需要 Python 3、可用的 Docker Linux 引擎，以及允许 `docker create/start/exec/inspect/rm` 的可信运维账号。用户提供的构建脚本只在受限容器内执行。默认容器隔离不是对不可信租户的完整安全边界；生产隔离建议用专用计算虚拟机和 rootless Docker。

```sh
cargo install --git https://github.com/zjarlin/sshpool --locked
sshpool init
sshpool node add linux-builder --ssh my-linux --reserve-memory-mib 8192
sshpool node add arm-builder --ssh my-mac --reserve-memory-mib 4096
sshpool doctor
sshpool node prepare linux-builder alpine:3.22
sshpool serve
```

配置位于 `~/.sshpool/config.toml`。节点地址、token、SSH 凭据与任务数据都不应提交到 Git。配置修改后重启控制面。`prepare` 是显式拉取镜像操作；普通构建不会自动拉镜像。`prepare` 同时把镜像加入该节点的允许清单；已安装的业务镜像也不会自动开放给任务。

稳定 Linux 工作台可以是已有 Linux 主机，或 Mac 上无宿主目录挂载的 Lima VM。把 `ssh_backend` 指向它的 SSH 端口，客户端只连接 `ssh_listen`。默认两者为 `127.0.0.1:2223` 和 `127.0.0.1:2222`。

Mac 的完整引导见 [部署文档](docs/deployment.md)，可使用仓库内的 `scripts/create-workspace.sh` 创建隔离的 Linux 工作台。

### 提交一个项目

```sh
cd my-project
sshpool project-init --image rust:1.93 --platform linux/amd64
```

编辑生成的 `sshpool.toml`，例如：

```toml
image = "rust:1.93"
platform = "linux/amd64"
command = ["cargo", "build", "--release"]
outputs = ["target/release/my-app"]
memory_mib = 4096
scratch_mib = 2048
cpus = 2.0
timeout_secs = 1200
pids = 256
network = true
retries = 0
idempotent = false
```

```sh
sshpool run
sshpool jobs
sshpool logs <job-id>
sshpool fetch <job-id>
sshpool cancel <job-id>
```

日志返回当前终端；产物由 `fetch` 解包到 `.sshpool/results/<job-id>/`。已存在的输出目录会被拒绝。私有依赖建议预先制作镜像；不要在构建参数、项目文件或镜像里放生产凭据。

镜像中的编译器负责执行构建。平台必须明确匹配：`linux/amd64` 产物不能当作 `linux/arm64` 产物。Mac Worker 贡献的是 Docker Linux VM，当前不执行原生 Xcode/macOS 构建。Windows Worker 的 SSH 必须进入 WSL2，而不是 PowerShell。

### 保留常用构建命令

```sh
sshpool install-shims
export PATH="$HOME/.sshpool/bin:$PATH"
cargo build --release
```

包装器支持 `cargo build/test/check/clippy`、`gradle`、`make`，只在有 `sshpool.toml` 的项目根目录中分发；版本查询、Cargo 元数据等仍走本地工具。它不会劫持任意 shell 命令。`./gradlew` 不经过 PATH，使用 `sshpool run -- ./gradlew build`。Node.js、Python、其他构建工具也可以用 `run -- ...`，只需相应容器镜像。

### Linux 工作台连接 Mac 控制面

客户端二进制支持：

```sh
export SSHPOOL_ENDPOINT=http://host.lima.internal:8877
export SSHPOOL_TOKEN_FILE="$HOME/.sshpool/token"
```

仅把控制面 token 放到可信工作台，权限设为 `0600`。节点 SSH 私钥留在 Mac。默认 API 只监听宿主回环；跨不可信网络使用 SSH 转发或 HTTPS，不能把明文 HTTP 暴露到公网。

## 已知限制

- 使用整个任务分派；尚未集成 sccache/Icecream 的编译单元拆分或远程缓存。原型借鉴 Slurm 的资源预约、OpenSSH 的连接面和容器运行时的隔离机制，不依赖这些项目的源码。
- tmpfs 避免写满业务磁盘，但大型构建需要相应内存。不能把多个 Worker 的内存合并给一个任务。
- 资源探测是快照，业务负载仍可能突然增长。预留量需要按部署测量，容器和虚拟化引擎必须支持并实际执行 cgroup 限额。
- Docker Desktop 的内部磁盘与空闲内存不能仅由宿主指标完全判断。任务不会自动拉镜像，工作区不使用宿主磁盘；镜像维护仍由运维负责。
- 不自动同步已有工程或清理公司文件。任务记录与源码归档当前保留供诊断；应在控制面停机后按保留策略管理专用状态目录。
- 不保证入口 Mac 关机、休眠或重启时会话在线。稳定入口仍是一个故障域。
- 不提供 NAT 穿透；复用已有 SSH ProxyJump/ProxyCommand 或受控网络。没有新增路由、隧道或端口映射。

## 开发与验证

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

从 `src/main.rs` 看 CLI，再看 `src/api.rs` 的任务接收，最后看 `src/runner.rs` 的容器生命周期。`src/scheduler.rs` 负责资源选择，`src/archive.rs` 负责文件边界。架构、验证范围与未来方向见 [docs/architecture.md](docs/architecture.md)。

MIT License.
