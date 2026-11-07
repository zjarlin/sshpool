# 0.1 验证记录

记录环境和证据边界；这里不包含真实 SSH 地址、密钥、token 或公司路径。

## ssh

统一入口是字节透传，认证、PTY、SFTP 和转发都由后端 OpenSSH 完成。2026-11-07 用可复跑脚本核对过「统一入口 vs 直连工作台」的等价性：

```sh
scripts/check-ssh-parity.sh 2222 2223      # 入口端口、直连端口；输出 JSON
```

同一份本地输入（文本 + 256 KiB 随机二进制）分别经两个入口执行 PTY、scp、sftp、rsync 和 `-L` 本地端口转发，比较的是远端 sha256 与真实响应内容，而不是退出码：四项文件操作两端摘要一致，转发取回非空响应，两个入口的 ed25519 主机公钥相同（代理没有替换后端身份）。原始输出在 [evidence/ssh-parity-20261107.json](evidence/ssh-parity-20261107.json)。

边界：只覆盖本机 loopback 的 `-L` 转发，不含 `-R` / `-D`；不覆盖 VS Code Remote SSH、JetBrains Gateway 等 IDE/AI 客户端的安装与重连（那是单独的待验收场景）。SSH 会话落在稳定工作台，与构建任务在隔离容器内执行是两件事。

## nodes

实际只读探测了 Linux ARM64、Linux x86_64 和 macOS ARM64 三类节点，返回独立资源快照。资源不足的 macOS Worker 被候选过滤，未通过降低预留强行执行构建。WSL2 尚无实机测试。

2026-11-07 增加了在线 `node enable` / `node disable`。控制面在不重启时更新调度状态并原子保存配置；仍有活动任务的节点拒绝禁用。API 测试覆盖鉴权、未知节点、活动任务保护、连续切换两个节点以及重载后保留全部选择。远程探测缺少控制面 `enabled` 字段时仍可解析，避免状态查询因协议扩展失败。

## limited-queue

有限队列默认关闭；`Build.queue_timeout_secs=0` 时无候选 Worker 仍立即失败。显式等待时，任务保存绝对截止时间和可选优先级，以 `queued` 状态持有本地源码。`limited_queue_waits_once_and_cancel_wakes_the_runner` 验证无节点时只写入一次 `queue_wait`、重复唤醒不刷审计，并验证取消后进入已确认没有远端尝试的 `cancelled` 状态。控制面重启测试验证未过期且归档合法的未领取任务保留原截止时间，而过期、缺失或损坏源码的请求进入 `interrupted`；已尝试任务仍不会重放。优先级边界、期限范围和排序由 `retry_and_path_policies_fail_closed` 与 `limited_queue_orders_priority_then_submission_time_with_stable_ids` 覆盖。

这些测试使用本机临时状态，不建立 Worker 连接。它们证明控制面生命周期和失败语义，不证明入口主机故障时队列仍在线，也不构成 SSI、Ceph 或数据库接管验收。

## source-integrity

源码快照按规范化路径排序，时间戳归零，仅把文件内容和可执行位带入归档。`source_snapshot_is_deterministic_and_records_sha256` 验证同一项目两次归档结果及摘要相同；单元回归另行验证扫描窗口中的可见修改会使快照失败。客户端随后把归档 SHA-256 放入 `x-sshpool-source-sha256`，控制面重算并写入任务记录。

`source_digest_mismatch_cleans_staging_without_publishing_a_job` 验证摘要不匹配返回 400、删除本次暂存目录且不发布任务。这里的“一致性”是拒绝扫描期间可观察到的修改，不是文件系统原子快照；对无协调写入者或完全不可观察的写入，代码不会给出超出证据的保证。

## rust

从统一 SSH 工作台执行 `cargo build --offline --release`，通过项目配置和 Cargo shim 提交 ARM64 Rust Alpine 镜像。任务以 UID 65534 执行，在容器内完成编译。通过 `fetch` 在全新目录回取可执行文件并实际运行，输出目标架构 aarch64。

## jobs

ARM64 的 shell 任务已完成日志、退出码、产物导出与清理闭环。x86_64 shell 命令已实际执行并输出正确架构；曾发生远端 Docker 清理超时，控制面记录 interrupted、禁止重试并隔离节点。之后独立确认该任务容器已不存在。

2026-11-05 再次从 ARM64 工作台提交独立 x86_64 Worker 任务，已完成输入、计算、产物校验和清理闭环，详见下面的 hardware-proof。不能用一次成功消除磁盘或网络故障的历史风险。

恢复、取消、配额与故障切换的进一步验收结果会在本文件追加。单元和 API 测试不替代真实故障注入。

### 从提交到产物交付（统一入口）

2026-11-07 新增 `tests/delivery_live.rs`：进程内启动真实 `axum::serve`（端口 `0` 由内核分配），用 `sshpool::client::Client` 走完整的 HTTP 入口——提交项目归档、跟随 `/v1/jobs/{id}/log`、按任务 ID 回取产物。测试不直接调用 `runner`，也不读写控制面目录绕过 API；断言目标是「工作台真的拿得到东西」，不是「接口返回 200」。

```sh
SSHPOOL_LIVE_NODE=okm182-lan \
  cargo test --test delivery_live -- --ignored --test-threads=1
```

| 场景 | 断言 |
| --- | --- |
| 正向交付 | `phase=succeeded`、`exit_code=0`、`artifacts=true`、`cleanup_confirmed=true`；日志同时含远端 stdout 与 stderr；事件链 `submitted → assigned → image_check → container_create → source_import → execution → artifact_export → cleanup(confirmed) → finished`；产物解包后架构与请求平台一致、计算值由工作台用等差数列公式独立复核 |
| 非零退出 | `client.run` 返回 7，任务 `failed` 且 `exit_code=7`，`artifacts=false`，产物接口明确报错而不是回空归档，容器仍然被清理 |
| 产物缺失 | 命令 `exit 0` 但声明的 `out` 不存在 → 任务 `failed`，消息含 `artifact export failed`，不发布任何产物 |
| 不覆盖 | 对同一目录二次 `fetch` 必须失败（复用 030 的 `fetching_never_overwrites_existing_directory`） |

实测：`okm182-lan`（linux/amd64）与 `sshpool-anchor`（linux/arm64）各一轮，三个场景全部通过；每轮结束后两台 Worker 上 `docker ps -aq --filter label=io.sshpool.job | wc -l` 均为 0。证据在 [evidence/delivery-20261107.json](evidence/delivery-20261107.json)。

虚构一条「交付成功」比失败危险：这里刻意把三类失败也写成自动化断言（非零退出、缺产物、重复回取），因为它们的共同失效模式都是「报告成功但工作台没有可用产物」。

顺带修掉一处重复：`Client::follow` 原先内联了一份取日志的代码，且 `Client` 没有对外暴露读取日志的方法。现在统一为 `Client::log(id, offset)`（返回原始字节，一次最多 256 KiB），`follow` 与新测试共用同一实现。

### 取消与执行期限

`POST /v1/jobs/{id}/cancel` 与期限到期走同一条停止路径：控制面先按任务标签确认容器身份，再发送 `docker stop --time 20`，然后重新读取状态。只有 `Absent` 与 `Stopped` 算「已停止」；`Running` 和任何 SSH 错误都不算，此时任务进入 `interrupted` 并隔离该 Worker，绝不报成 `cancelled`。

这里有个容易写错的前提，已在真实 Worker 上实测：**只杀掉控制面这一侧的 SSH 客户端不会停止远端进程**。断开整个 SSH 会话后，容器仍是 `running`，容器内 `docker exec` 启动的 `sleep` 也仍在。所以取消必须显式发停止请求，而不能靠丢弃连接。

| 阶段 | 行为 |
| --- | --- |
| 镜像检查后、`docker create` 前 | 已取消/到期则完全不创建容器（容器不存在即等于已确认不存在） |
| `create` 后、`start` 前 | 容器停在 `Created`，没有进程可停止，直接收尾 |
| 源码导入后、启动命令前 | 先请求停止再返回，避免白跑一次完整构建 |
| 执行中 | 每秒检查，触发后停止并等待 `docker exec` 客户端退出 |

实测（`sshpool-anchor`，linux/arm64，Docker 29.1.3，alpine:3.22）：

- 取消：任务进入 `running` 后 2 秒取消 → 远端收到停止请求、`events.jsonl` 记录 `client-cancel; remote container stopped`、终态 `cancelled`、`cleanup_confirmed=true`、按 `label=io.sshpool.job=<id>` 查询容器数为 0。
- 期限：`timeout_secs=5` 而命令是 `sleep 600` → 记录 `deadline` 原因、终态 `failed` 且消息含 `job deadline exceeded`、容器数为 0。
- 复验：`sshpool-anchor` 连续 8 轮、`okm182-lan`（linux/amd64）连续 4 轮，每轮两个场景全绿，每轮结束后按标签查询残留容器数都是 0。

### 连接层抖动不该被当成任务结论

这轮实测暴露了一个真实的误判：lima 的 sshd 在并发连接下会丢弃部分握手（实测并发 100 条约 1/3 失败，报错 `Connection timed out during banner exchange`），而 OpenSSH 用**退出码 255**表示连接层错误、命令根本没跑。此前只有 `Err` 分支重试，`Ok((255, …))` 直接当成任务失败，于是「已经确认停止」的任务被改写成 `interrupted` 并隔离 Worker。

现在按「命令是否可能已经执行」分两类：

| 路径 | 重试 | 理由 |
| --- | --- | --- |
| `docker image inspect`、`docker inspect`（标签核对）、`docker ps` | 是（最多 3 次） | 只读，命令没跑到可以安全重放 |
| `docker stop`、`docker rm -f`、`tar -xf` 覆盖导入 | 是（最多 3 次） | 幂等：再执行一次得到同一结论/同一棵树 |
| `docker exec` 跑构建命令 | 否 | 命令可能已经在远端执行，重试等于同时跑两份业务 |

`Err` 与 `Ok((255, …))` 两条入口都覆盖；执行超时（`timed out after`）与命令自身的非零退出码都不算连接层失败，绝不重试。

证据在 [evidence/cancel-timeout-20261107.json](evidence/cancel-timeout-20261107.json)。语义边界要说清：`docker stop` 的 SIGTERM 发给容器 PID1（本项目是 `sleep timeout+grace`），不是容器里的业务进程，所以取消是「确定停止」而不是「优雅排空」——不给业务进程自定义清理时间，被取消的任务一律不导出产物，中间结果也不保证可用。

## isolation

实际任务输出 UID 65534，工作台与容器均未挂载宿主 home。文件边界测试覆盖外部符号链接、tar 穿越/软硬链接/特殊文件、未声明产物、已有输出不覆盖、畸形/超量上传与相邻文件保护。

2026-11-07 起，隔离不再只是命令行声明：`docker create` 之后、`docker start` 之前，控制面用 `docker inspect` 的真实 HostConfig 复核，任何一项不符就停在 `Created` 状态（随后按任务标签删除），不会启动。校验项与实测值见 [evidence/isolation-runtime-20261107.json](evidence/isolation-runtime-20261107.json)，覆盖只读根文件系统、空 capability、`no-new-privileges`、非 root、无 bind mount / volumes-from / 设备 / 宿主命名空间、禁网、不发布端口、`--restart=no`、`--log-driver=none`、init 进程，以及内存/CPU/PID/ulimit/tmpfs 上限与请求一致。

这轮实测发现并修复了一个真实缺陷：**Docker 对 `--tmpfs` 默认追加 `noexec`**，即使显式给了其他选项也照样加。此前 `/work` 因此不可执行，编译出的二进制和测试程序会直接 `Permission denied`（实测 exit 126）。现在 `/work` 显式带 `exec`（编译产物必须在里面跑），`/tmp` 保持 `noexec`，两者都由校验强制。

资源过滤测试覆盖平台、内存、磁盘、CPU 负载、并发槽位和未知清理隔离。业务 SLO 压力矩阵仍未完成：并发构建对业务延迟、swap、磁盘水位的影响需要在业务主机上实测，不能据此承诺所有业务峰值下的 SLO。

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

## physical-host-and-build-proof

2026-11-07 新增一台独立 x86 物理 Worker，并从 ARM64 统一工作台成功提交真实构建。公开记录 [ssi-physical-host-20261107.json](evidence/ssi-physical-host-20261107.json) 已去除地址、账号、密码、私有路径和磁盘序列号；检查器 `scripts/ssi-lab/check-physical-host.py` 会拒绝把未确认磁盘标成可擦除，也会拒绝提升为完整 SSI、自动故障接管或分布式存储已验证。

| 证据 | 实测 |
| --- | --- |
| 物理 CPU | 双路 Xeon E5-2620 v4，16 物理核/32 逻辑 CPU |
| 内存与虚拟化 | 约 60.5 GiB；普通用户可访问 KVM API 12 |
| 容器运行时 | Docker 29.1.3，cgroup v2，内存/CPU/PID 限额有效 |
| 隔离 VM | 8 vCPU，12 GiB，100 GiB 稀疏 overlay，SSH 仅映射回环 |
| 物理执行 | 3 秒负载内八条 KVM vCPU 线程各产生 300 ticks |
| 文件边界 | 未传业务块设备、未用 virtfs/9p、未挂载宿主业务目录 |
| 构建任务 | `26757349-13e7-4a74-9fd4-17520a2c76bf`，`linux/amd64`，离线 Cargo release |
| 结果与清理 | `succeeded`，`exit_code=0`，`cleanup_confirmed=true`，无残留容器 |
| 产物 | SHA-256 `b51f6aeb99d2ef3558f3b4415c0099de75c803511b3828589821e84ec9f0c423` |
| 架构边界 | 产物在物理 Worker 上运行成功；在 ARM64 入口被 `exec format error` 拒绝 |
| 存储边界 | 独立附加盘的文件系统和归属未确认，未挂载、未格式化、未创建 RAID/LVM/OSD |

实测已经证明真实物理计算卸载、日志、产物和清理闭环；它仍是任务调度，而不是严格 SSI。跨物理同一进程没有运行，CPU/RAM 没有合并，Ceph 没有部署，`.182` 故障后的自动服务接管和 sub2api/PostgreSQL/Redis 迁移也没有验收。

## publication

公开源码已发布到 [zjarlin/sshpool](https://github.com/zjarlin/sshpool)，MIT 许可，包含 Cargo.lock、Linux/macOS CI 和 Gherkin 验收清单。首个源码提交为 `b27c835`。提交前检查真实地址、节点 SSH 别名、用户目录、私钥标记和常见 token 格式，没有将私有配置或任务归档加入仓库。

本地 Rust 测试、格式检查、Clippy 和 release build 通过；具体数量随版本增长，以对应提交的 CI 为准。工作台客户端与 Mac 控制面均已更新，但公开源码不代表生产可用或全部验收场景通过。CI 运行结果见 [GitHub Actions](https://github.com/zjarlin/sshpool/actions)。

## control-state-recovery

2026-11-07 在两个独立物理故障域完成非业务演示任务的 quorum-2 双向恢复：先隔离一个远端并从另一个恢复完整任务归档，再交换隔离方向重复验证。恢复结果保留任务 ID、源码 SHA-256、队列状态、revision、事件和提交回执。脱敏记录见 [control-state-recovery-20261107.json](evidence/control-state-recovery-20261107.json)。

同日补上「控制面主机整体丢失」的故障注入（`tests/control_state_live.rs`，一次性 namespace，`okm182-lan` + `macmini-lan` 两个独立物理故障域，连续 3 轮通过）：

| 注入 | 实测 |
| --- | --- |
| 新主机只有 `config.toml` 与 `token`，`jobs/` 与回执目录为空 | 从远端副本恢复出任务，日志、已声明产物、终态事件、源码摘要与 revision 全部一致 |
| 只剩一台远端副本 | quorum 2 由「新主机 + 一台远端」满足，仍能恢复 |
| 两台副本都被删除 | 拒绝启动（`quorum not met at startup`），且不生成任何任务目录 |
| 恢复目录缺少 `token` | `State::load` 拒绝加载，证明密钥不在恢复范围内 |

这轮还修了一个真实缺陷：`State::finish` 原先先做最后一次跨机提交、再写 `finished` 事件，导致终态事件永远进不了恢复包——从远端恢复出来的任务看不到「何时结束」。现在事件先落盘再提交；`job.json` 仍是阶段权威来源，所以提交失败只多一条事件，不会让任务被误判为已结束。

自动化还覆盖同一 revision 的不同内容或回执冲突、达不到 quorum、较新发布版本损坏、重复主机/故障域、namespace 路径逃逸和未确认远端清理。真实测试没有证明运行进程迁移、自动控制面接管与入口 DNS 切换、PostgreSQL 事务容灾或跨主机存储；这些仍按失败关闭处理。

## stateful-backup-recovery

2026-11-07 对 `sub2api` 的 PostgreSQL 与 Redis 做了隔离恢复演练。备份前暂停 9 个受管容器，应用停写后导出 PostgreSQL 自定义归档、Redis RDB、应用配置与卷归档、容器清单和镜像，随后重启并确认核心应用健康。恢复包内 13 个真实载荷逐项校验摘要，PostgreSQL 归档包含 116 个 `TABLE DATA` 条目，容器镜像归档也通过格式检查。

加密副本在另一台独立物理机的临时目录中解密成功。密文摘要为 `23c27d…4ac2`，解密后的压缩包摘要与源包及本机副本一致，均为 `9806968f…ff60c`；明文和临时解密工具随后删除。该步骤证明异地介质和口令可恢复出原始包，不证明已完成业务切换。

PostgreSQL 15.19 在现有实例中创建临时数据库，以 `pg_restore --no-owner --no-acl --exit-on-error` 恢复成功；116 张表、78 个序列、482 个索引和 95 个外键的 schema 对象清单与当前生产清单逐字节一致，116 张表的行数全部成功导出。生产数据库没有被停止或替换，临时库随后删除。

Redis 8.10.2 使用独立容器和独立命名卷恢复，网络为 `none`。RDB 校验通过：原始 12,136 个键、7,788 个过期信息，检查时有 4 个键已过期；加载后 761 个键按 TTL 过期、11,375 个键存活，DB0/6/7 分别为 11,321/27/27。备份时默认 DB0 的 `DBSIZE=12080`，隔离加载后不能与这一历史计数做等值比较。临时容器和卷已删除，生产 Redis 未被停止或替换。

证据见 [stateful-backup-recovery-20261107.json](evidence/stateful-backup-recovery-20261107.json)。本轮验收边界：

- 成功的是历史时点逻辑备份、RDB 加载和隔离恢复；备份时间之后的写入存在非零 RPO。
- 没有实现 PostgreSQL 持续 WAL 归档或流复制、Redis 持续复制、写入 fencing、自动故障转移或入口 DNS 切换。
- 应用配置与数据库虽在同一次停写窗口导出，尚未在独立演示环境完成整套 `sub2api + PostgreSQL + Redis` 恢复并接管流量，因此不能宣称生产数据库高可用。
- `sub2api-chatgptweb` 在备份前已存在 `Restarting (137)`，本轮未把它归因于备份流程或宣称该子服务健康。


## watchdog-cleanup-proof

2026-11-07 把「清理未确认时禁止换机重跑」从一句注释变成可执行的证据链。之前的实现只会把 Worker 隔离，并要求重启控制面才能恢复接单；现在隔离状态可以在线解除，且解除依据可复现。

证据来源只有三种，全部落在 `docs/evidence/watchdog-cleanup-20261107.json`：

| 证据 | 含义 | 前提 |
| --- | --- | --- |
| `remote-absent` | 容器已不存在 | `docker inspect` 明确返回 no such object/container |
| `remote-stopped` | 容器存在但未运行 | 标签必须与本任务 UUID 一致；`--restart=no` 不会复活 |
| `watchdog-lease-expired` | SSH 不可达，但容器 PID1 的 `sleep` 已到期 | 启动时记录过租约；判定加 60 秒时钟偏差上界 |

容器入口始终是 `sleep timeout_secs + 180`，所以任何一次执行都有确定寿命。控制面在 `docker start` 之后读取 `State.StartedAt`，把「启动时刻 + 超时 + 180 秒」写进 attempt 的 `watchdog_deadline`；读不到就留空，等价于「没有证据」，而不是「可以放行」。

实测：

- 真实 Worker（`okm182`，Docker 29.1.3，linux/amd64）上按 runner 完全相同的参数创建容器：`sleep 2` 前 `State.Running=true`，到期后 `false` 且 `ExitCode=0`，`--restart=no` 不复活。改动完成后同一组 `tests/watchdog_live.rs` 在另一台真实 Worker（本机 lima `sshpool`，Docker 29.1.3，linux/arm64）上重跑通过：`2 passed`。
- 真实停止容器：`node reconcile` 返回 `remote-stopped`，删除容器并解除隔离。
- 真实运行中的容器：即使租约已过期，`proven=false`，删除被拒绝 —— 实际状态优先于时间推断。
- SSH 完全不可达：租约未到期时报告剩余秒数并继续拒绝；到期后 `watchdog-lease-expired` 生效。
- 解除隔离后只有「幂等 + 禁网 + 仍有重试额度 + 未被取消」的任务重新排队；重跑继承历史 attempt，已执行过的 Worker 不会被再次选中，也不会因为重跑而多给一次额度。判据是「该 Worker 出现过 attempt」，**不按 `outcome` 过滤**：控制面在容器仍运行时崩溃会留下 `outcome: None`，那台机器同样执行过本次任务。
- 重跑没有可用 Worker 时任务以 `failed` 结束，原因写明 `already attempted this job; retries only switch workers`，不会显示成空理由，也不会把排队当成成功。
- 仍在 `running` 的任务不参与外部核对：执行者自己负责清理，此时容器可能尚未创建；若把这种 attempt 当待核对，`docker inspect` 的 absent 会被误写成「已证明清理」。

边界：这只证明「没有进程还能继续提交结果」，不证明中断前的输出有效，也不迁移内存或进程。跨机器 CPU/内存聚合、数据库事务容灾、自动控制面接管仍未实现。

排障记录：本轮改动后先在 `okm182` 上重跑这两条 live 测试，SSH 卡在 banner 交换、`docker create` 耗时 18.7 秒、`docker rm -f` 数分钟未返回 —— 是该主机磁盘/负载饱和，不是测试回归；改在另一台真实 Docker 上重跑通过，自动化规则不依赖任何远端。`okm182` 上本轮遗留的 `sshpool-live-*` / `sshpool-manual-*` 容器待主机恢复后再删除，不计入清理完成。
