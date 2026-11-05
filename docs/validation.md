# 0.1 验证记录

记录环境和证据边界；这里不包含真实 SSH 地址、密钥、token 或公司路径。

## ssh

在 Apple Silicon 宿主上的 Lima Linux 工作台验证：统一 SSH 别名返回 Linux aarch64；从控制客户端使用 scp/SFTP 上传文件；工作台没有宿主 home 的 virtiofs 挂载。完整 IDE 安装和自动重连尚未验收。

自动化验证 `gateway_preserves_full_duplex_bytes_and_half_close` 确认双向二进制字节和半关闭语义。

## nodes

实际只读探测了 Linux ARM64、Linux x86_64 和 macOS ARM64 三类节点，返回独立资源快照。资源不足的 macOS Worker 被候选过滤，未通过降低预留强行执行构建。WSL2 尚无实机测试。

## rust

从统一 SSH 工作台执行 `cargo build --offline --release`，通过项目配置和 Cargo shim 提交 ARM64 Rust Alpine 镜像。任务以 UID 65534 执行，在容器内完成编译。通过 `fetch` 在全新目录回取可执行文件并实际运行，输出目标架构 aarch64。

## jobs

ARM64 的 shell 任务已完成日志、退出码、产物导出与清理闭环。x86_64 shell 命令已实际执行并输出正确架构；曾发生远端 Docker 清理超时，控制面记录 interrupted、禁止重试并隔离节点。之后独立确认该任务容器已不存在。

2026-11-05 再次从 ARM64 工作台提交独立 x86_64 Worker 任务，已完成输入、计算、产物校验和清理闭环，详见下面的 hardware-proof。不能用一次成功消除磁盘或网络故障的历史风险。

恢复、取消、配额与故障切换的进一步验收结果会在本文件追加。单元和 API 测试不替代真实故障注入。

## isolation

实际任务输出 UID 65534，工作台与容器均未挂载宿主 home。文件边界测试覆盖外部符号链接、tar 穿越/软硬链接/特殊文件、未声明产物、已有输出不覆盖、畸形/超量上传与相邻文件保护。

资源过滤测试覆盖平台、内存、磁盘、CPU 负载、并发槽位和未知清理隔离。cgroup、tmpfs、网络与日志上限的完整压力矩阵尚需补充，不能据此承诺所有业务峰值下的 SLO。

## deployment

Mac 上已安装专用 LaunchAgent，读取私有状态目录并启动独立 Lima 工作台与控制面。API 回环访问，未授权请求返回 401。此机制在用户登录后运行，不保证宿主关机或休眠期间在线。

当前验证使用 macOS ARM64 Rust 1.94 与 Linux ARM64 Rust 1.93。GitHub Linux/macOS CI 的实际结论以仓库运行结果为准。Windows 原生客户端、跨公网网络和恶意多租户隔离未验证。

## hardware-proof

2026-11-05 的独立硬件验收：统一入口的 `uname -m` 为 `aarch64`，任务 `298b9c97-748f-4a28-a291-e31aba0efa0d` 声明 `linux/amd64`，调度到独立 Linux Worker。只上传新建演示目录的公开输入与脚本，没有使用公司文件。

| 证据 | 实测 |
| --- | --- |
| Worker Docker 端点 | 该 Worker 本机 `unix:///var/run/docker.sock` |
| 宿主 CPU | x86_64，32 个逻辑 CPU |
| 任务进程 | 该 Worker 的 `docker top` 中有 `awk`，宿主 PID 1761699 |
| 计算配额与占用 | 0.5 CPU，`docker stats` 为 50.65%，内存限制 128 MiB |
| 文件与网络 | `mounts=[]`，`network=none`，UID 65534 |
| 工作台侧检查 | 同一任务标签的容器数量为 0 |
| 计算结果 | 循环计算 1 至 10000000 的和模 1000003，返回 435 |
| 结果验证 | 工作台按等差数列公式独立验证；输入 SHA-256 与回传记录相同 |
| 终态 | `succeeded`，`exit_code=0`，`cleanup_confirmed=true` |
| 清理复查 | Worker 上该任务容器已不存在 |

事件链覆盖 `submitted → assigned → image_check → container_create → source_import → execution → artifact_export → cleanup(confirmed) → finished(Succeeded)`。`audit_events_survive_state_reload_without_credentials` 另行验证事件 API 鉴权、重载读取与 token 排除。

复现入口：在已有获批 `alpine:3.22` 镜像的 x86_64 Worker 上，通过工作台建立一个只含公开文件的演示目录：

```toml
image = "alpine:3.22"
platform = "linux/amd64"
command = ["sh", "-c", "mkdir out; uname -sm > out/runtime.txt; awk 'BEGIN {s=0; for(i=1;i<=1000000;i++) s=(s+i)%1000003; print s}' > out/result.txt; cat out/runtime.txt out/result.txt"]
outputs = ["out"]
memory_mib = 128
scratch_mib = 16
cpus = 0.5
timeout_secs = 90
network = false
retries = 0
```

保存为 `sshpool.toml` 后执行 `sshpool run`，记下任务 ID，再用 `sshpool events <id>` 和 `sshpool fetch <id>` 核对。复现示例使用更短的循环；上表记录对应实际验收的 1000 万次循环。Worker 管理员可以同时检查该任务标签的容器进程；仅打印 `uname` 不足以单独证明未使用仿真。

macOS ARM64 Worker 本次只完成资源探测：可用内存约 2.7 GiB，小于保留给原有业务的 4 GiB，系统负载约 36。未降低预留、停止原有业务或强行执行。其任务执行验收仍未完成；未完成不能记作已经贡献硬件。不同 Worker 的可用内存没有合并，普通 SSH 命令和现有 sub2api 服务仍在各自原主机运行。
