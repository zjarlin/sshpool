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

2026-11-07 这条链路写成了可复跑的 `#[ignore]` 测试 `tests/nodes_live.rs`，走真实 CLI（`node add` → `doctor` → `node list`），不直接调用 `probe::all`：

| 断言 | 实测 |
| --- | --- |
| 每台已登记主机独立报告 | `linux/aarch64`（4 CPU、5285 MiB）、`linux/x86_64`（32 CPU、27112 MiB）、`darwin/arm64`（10 CPU、2703 MiB） |
| 单节点失败不吞掉其他结果 | 额外登记 `192.0.2.1` 后，`doctor` 仍返回 4 条记录，可路由节点无 error，黑洞节点带 error |
| 名字与能力一一对应 | 输出里没有重复名字，OS/arch/runtime_arch 非空 |
| 重复名字被拒绝 | `node add node-0` 失败，`node list` 里的节点条目数不变 |
| 别名不允许 shell 语法 | `host; rm -rf /`、`-oProxyCommand=evil`、`host\`id\``、空串都被 CLI 拒绝且不落盘 |

`macmini-lan` 的可用内存（2703 MiB）仍低于业务预留，所以它只在这条「报告」场景里出现，没有参与构建调度——报告能力与允许执行是两件事。

2026-11-07 增加了在线 `node enable` / `node disable`。控制面在不重启时更新调度状态并原子保存配置；仍有活动任务的节点拒绝禁用。API 测试覆盖鉴权、未知节点、活动任务保护、连续切换两个节点以及重载后保留全部选择。远程探测缺少控制面 `enabled` 字段时仍可解析，避免状态查询因协议扩展失败。

### 探测在调度锁外，快照有 TTL

`runner::run` 原先在持有全局 `state.scheduling` 锁时执行 `probe::all`。`transport` 固定 `ConnectTimeout=5`，所以只要有一台节点不可达，**所有任务派发都会被这 5 秒串行阻塞**。实测黑洞节点（`192.0.2.1`，RFC 5737）`ssh` 恰好耗时 5.01s；正常节点一次完整探测为 `okm182-lan` 0.35s、`sshpool-anchor` 0.18s、`macmini-lan` 1.15s。

现在探测在锁外完成，锁内只读内存快照：

| 环节 | 行为 |
| --- | --- |
| 调度路径 | `ensure_health()` 仅在快照超过 `HEALTH_TTL`（15s）时探测 |
| 状态查询 | `/v1/status` 无条件 `refresh_health()`，顺手把缓存刷成新鲜 |
| 并发探测 | `probing` 锁合并：等待者复用前一个调用者的新鲜快照，一次抖动不会放大成多轮 SSH |
| 无快照节点 | 返回 `health not probed yet` 占位，`scheduler::score` 据此拒绝（fail-closed） |
| 拿到锁后 | 重新读一次节点列表，避免「读节点 → 管理员禁用 → 拿到锁」把任务派给刚停用的 Worker |

回归测试 `tests/scheduling_lock.rs` 用「TCP accept 后不发 SSH banner」的本地监听器确定性复现，不需要 Docker：

- `an_unreachable_worker_does_not_hold_the_scheduling_lock`：探测已连上监听器时，另一路在 1s 内拿到调度锁；任务随后走完 ConnectTimeout 并以 `no eligible worker: hangtest: ...` 失败。**在旧实现上该测试失败**（`scheduling lock is held while a worker probe is still running`），因此不是恒真断言。
- `a_worker_without_a_health_snapshot_is_refused`：没有快照的节点被拒绝分配，且快照与节点一一对应。
- `concurrent_probes_share_one_round_trip`：两个并发调用只产生一次 SSH，得到同一份快照。
- `a_node_disabled_during_the_probe_is_not_assigned`：探测进行中执行 `set_node_enabled(false)`，任务必须失败且 `attempts` 为空（**去掉锁内重读后该测试失败**，证明它抓到了真实的竞态）。

真实节点侧用 `tests/scheduling_live.rs`（`#[ignore]`）验证：配置一台 `priority=100` 的黑洞节点 `192.0.2.1` 与 `okm182-lan`，`/v1/status` 里黑洞节点带 `Operation timed out`、可达节点无 error，任务仍派给 `okm182-lan` 并确认清理——优先级更高的坏节点没有被误用。证据在 [evidence/scheduling-probe-lock-20261107.json](evidence/scheduling-probe-lock-20261107.json)。

语义边界：**快照最多陈旧 15s**，刚被占满的节点可能在这段时间内仍被选中，兜底是容器创建后的 `isolation::verify_created` 与调度重试；探测本身仍会等满 ConnectTimeout，锁外执行只是不让阻塞扩散到其他任务。

## limited-queue

有限队列默认关闭；`Build.queue_timeout_secs=0` 时无候选 Worker 仍立即失败。显式等待时，任务保存绝对截止时间和可选优先级，以 `queued` 状态持有本地源码。`limited_queue_waits_once_and_cancel_wakes_the_runner` 验证无节点时只写入一次 `queue_wait`、重复唤醒不刷审计，并验证取消后进入已确认没有远端尝试的 `cancelled` 状态。控制面重启测试验证未过期且归档合法的未领取任务保留原截止时间，而过期、缺失或损坏源码的请求进入 `interrupted`；已尝试任务仍不会重放。优先级边界、期限范围和排序由 `retry_and_path_policies_fail_closed` 与 `limited_queue_orders_priority_then_submission_time_with_stable_ids` 覆盖。

这些测试使用本机临时状态，不建立 Worker 连接。它们证明控制面生命周期和失败语义，不证明入口主机故障时队列仍在线，也不构成 SSI、Ceph 或数据库接管验收。

## source-integrity

源码快照按规范化路径排序，时间戳归零，仅把文件内容和可执行位带入归档。`source_snapshot_is_deterministic_and_records_sha256` 验证同一项目两次归档结果及摘要相同；单元回归另行验证扫描窗口中的可见修改会使快照失败。客户端随后把归档 SHA-256 放入 `x-sshpool-source-sha256`，控制面重算并写入任务记录。

`source_digest_mismatch_cleans_staging_without_publishing_a_job` 验证摘要不匹配返回 400、删除本次暂存目录且不发布任务。这里的“一致性”是拒绝扫描期间可观察到的修改，不是文件系统原子快照；对无协调写入者或完全不可观察的写入，代码不会给出超出证据的保证。

## rust

从统一 SSH 工作台执行 `cargo build --offline --release`，通过项目配置和 Cargo shim 提交 ARM64 Rust Alpine 镜像。任务以 UID 65534 执行，在容器内完成编译。通过 `fetch` 在全新目录回取可执行文件并实际运行，输出目标架构 aarch64。

2026-11-07 把这条链路写成可复跑的 `#[ignore]` 测试（`tests/shim_live.rs`）。它走真实二进制 `CARGO_BIN_EXE_sshpool shim cargo -- build --release --offline`，不直接调用 `runner`：

| 断言 | 实测（`sshpool-anchor`，linux/arm64，rust:1.93-alpine） |
| --- | --- |
| shim 退出码与任务终态 | 0 / `succeeded`，`exit_code=0` |
| 原命令逐字下发 | `build.command == [cargo, build, --release, --offline]`，没有重写 |
| 非 root 执行 | 构建脚本在容器内读到 `id -u` = 65534 |
| 架构 | 容器内 `uname -m` 映射后等于请求平台 |
| 真实产物 | `target/release/demo` 的 ELF `e_machine` = 0xb7（aarch64）/ 0x3e（amd64） |
| 回取后可执行 | 把回取的二进制重新上传到 Worker 执行，输出 `sshpool-demo`、退出码 0 |
| 清理 | `cleanup_confirmed=true`，按任务标签查询容器数为 0 |
| 不劫持普通命令 | 在无项目目录执行 `cargo --version` 成功且不产生新任务 |

这轮还修掉一个真实缺陷：`shim` 回退到本机工具时先 `canonicalize` 了 `~/.sshpool/bin`，**从未执行过 `install-shims` 的用户没有这个目录**，于是 `cargo --version` 之类的普通调用直接报 `No such file or directory`，而不是落到本机工具。现在目录缺失时只按原样路径比较，不再报错。

证据文件：[evidence/shim-20261107.json](evidence/shim-20261107.json)。

边界：`okm182-lan` 上没有 Rust 工具链镜像，测试在该节点显式 `skipped` 而不是失败——缺镜像不等于 shim 有缺陷。x86_64 架构的 ELF 断言目前只在物理 Worker 的手工验收里（见 `physical-host-and-build-proof`）出现过，`shim_live` 尚未在 x86 节点实跑。

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
| 审计 | 用真实 `sshpool` 二进制执行 `sshpool events <id>`，事件数量与 API 一致且不打印 token |

实测：`okm182-lan`（linux/amd64）与 `sshpool-anchor`（linux/arm64）各一轮，三个场景全部通过；每轮结束后两台 Worker 上 `docker ps -aq --filter label=io.sshpool.job | wc -l` 均为 0。证据在 [evidence/delivery-20261107.json](evidence/delivery-20261107.json)。

虚构一条「交付成功」比失败危险：这里刻意把三类失败也写成自动化断言（非零退出、缺产物、重复回取），因为它们的共同失效模式都是「报告成功但工作台没有可用产物」。

审计事件这条也补上了 CLI 那一半：先前只有 API 返回事件链，`sshpool events <id>` 从未被真实执行过。现在用 `CARGO_BIN_EXE_sshpool` 走同一份真实入口，比对事件数量并断言输出不含 token。这里踩到一个测试写法问题：本文件是 current-thread 运行时，同步等待子进程会**把进程内 axum 服务一起阻塞**（实测 150s 超时），必须放进 `spawn_blocking`。

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

### 升级与到期任务清理 {#upgrade-and-retention}

_（本节标题锚点为 `upgrade-and-retention`。）_

`sshpool jobs inspect` / `sshpool jobs prune` 只改本机任务目录，不走 HTTP 接口，因此不扩大鉴权面。核对会拒绝而不是跳过无法解释的目录：非规范 UUID 目录名、缺 `job.json`、记录与目录名不一致、终态缺 `finished_at`、`.revision` 超前于已发布版本、`source.tar` 非法或摘要不符、声明了产物却缺 `artifacts.tar`、目录里出现未知文件/符号链接。控制面启动时的 `State::load` 对这些目录是静默跳过，清理若沿用同一语义就会把一个命名错误的历史任务永久留在磁盘上。

| 不变量 | 实现 | 自动化 |
| --- | --- | --- |
| 活跃任务永不清理 | 只有 `succeeded`/`failed`/`cancelled` 进入候选 | `terminal_states_with_unconfirmed_cleanup_are_never_pruned` |
| `interrupted` 永不清理 | 它可能被 `node reconcile` 自动重跑 | 同上 |
| 清理必须逐个确认 | 逐 attempt 取 `Some(confirmed)`，`None` 回退到顶层标志 | `legacy_records_without_per_attempt_cleanup_follow_the_top_level_flag` |
| 年龄与最近保留同时满足 | `finished_at + older_than_secs <= now` 且不在 `keep_last` 内 | `keep_last_and_age_are_both_required_before_a_job_qualifies` |
| 归档必须可恢复 | 写出后核对摘要，再 `install_bundle` 重新安装并逐字段比对 | `apply_writes_a_restorable_bundle_and_moves_instead_of_deleting` |
| 移动而非删除 | 任务目录移入 `backups/jobs/pruned-<ts>-<uuid>/`，只有 `--purge` 才回收 | `purge_reclaims_the_moved_directory_keeps_the_bundle` |
| 失败整批回滚 | 任一候选失败即把本批已移动目录移回，并删掉半成品归档 | `retention::tests::a_late_failure_restores_every_moved_directory_and_drops_partial_bundles` |
| 计划与执行之间不得变更 | 用同一时钟重新生成候选集合并逐项比对 | `apply_is_idempotent_after_a_clean_run_and_rejects_a_stale_plan` |
| 不碰运行中的控制面 | 独占 `controller.lock` 失败即拒绝 | 见下方 CLI 实录 |
| 旧记录先补齐再清理 | 缺摘要时阻塞，`replica adopt` 补摘要后可继续 | `adopting_a_legacy_record_unblocks_pruning` |
| 半成品归档必须撤销 | 取包后校验失败则删归档、把目录移回 `jobs/` | `retention::tests::a_stage_failure_removes_the_untrusted_bundle_and_keeps_the_task_in_place` |
| purge 失败不丢报告 | 第一条失败即停止，归档保留，实际进度走 stderr | `retention::tests::a_purge_failure_stops_at_the_first_error_and_keeps_archives` |

真实二进制在临时 home 上的实测（`--older-than-days 30 --keep-last 0`）：`inspect` 报 1 个任务、0 个 blocker；dry-run 列出 1 个候选且目录仍在 `jobs/`；`--apply` 生成 14336 字节归档（SHA-256 `be09806b…`），任务目录移入 `backups/jobs/pruned-…/`，`remaining_jobs=0`。再执行一次是干净的空计划（退出码 0、`pruned=0`），`backups/jobs/` 仍只有 1 个批次目录 —— 命令行每次都重新生成计划，所以"过期计划"只会出现在库层调用；该断言由 `apply_is_idempotent_after_a_clean_run_and_rejects_a_stale_plan` 覆盖，不是 CLI 行为。对一个被 `flock` 持有的 `controller.lock` 执行 `--apply`，退出码 1，错误为 `controller is running on this home; stop it before pruning`。往 `jobs/` 放一个指向 `/tmp` 的符号链接后，`inspect` 退出码 2 并报 `task entry is a symbolic link`，`prune` 退出码 1 拒绝执行；空 `jobs/` 上 `inspect`/`apply` 都干净返回且不生成批次目录。

再把**本机生产状态目录只读复制**到 `/tmp`（未改动生产）并用 release 二进制清理：`inspect` 报 7 个任务、1,037,065 字节、0 个 blocker；`--older-than-days 1 --keep-last 0` 选出 5 条（2 个 `failed`、3 个 `succeeded`），`interrupted` 的 `1fe5b0f1` 与最年轻的 `26757349` 被跳过；`--apply` 移动 571,783 字节、生成 593,920 字节归档，`jobs/` 只剩 2 条、465,282 字节。逐个重算归档摘要一致，`job.json` 逐字段一致（差异仅为 serde 在重写时补出的 `attempts[].watchdog_deadline` / `cleanup_proof: null` 默认值）。证据见 [evidence/retention-20261107.json](evidence/retention-20261107.json)。

生产状态目录本身只做了 `inspect` 与 dry-run（`--older-than-days 7 --keep-last 3` 计划为空：`1fe5b0f1` 因 `interrupted` 被排除，其余因 `keep_last` 或年龄未到而保留），没有真正清理。

尚未覆盖：跨主机副本的保留（远端副本仍需 `replica sync` 自行管理）、`backups/jobs/` 自身的容量上限与再压缩、`--purge` 后的归档恢复演练（`install_bundle` 只在临时目录验证，没有替换过真实控制面状态）。

### 跨不可信网络的控制面 {#access-network}

_（本节标题锚点为 `access-network`。）_

控制面默认仍是回环上的明文 HTTP：默认配置没有 `tls_cert` / `tls_key`，行为与之前一致。需要跨不可信网络时，`config.toml` 同时给出证书链与私钥（绝对路径、私钥 `0600`）即可让同一个 `serve` 改用 rustls 终止 TLS，ALPN 为 `h2` + `http/1.1`；客户端用 `--ca-file` 或 `SSHPOOL_CA_FILE` 指定信任的 CA，没有"跳过校验"的开关。客户端拒绝把 CA 文件用于 `http://` 端点，因为这个组合只可能来自误配置。

| 不变量 | 实现 | 自动化 |
| --- | --- | --- |
| 不校验证书就失败 | 未提供 CA 时用系统信任链；自建 CA 的证书必须显式 `--ca-file` | `https_verifies_the_certificate_and_short_lived_credentials_can_be_revoked` |
| 明文不能顶替 TLS | 向 TLS 端口发 HTTP/1.1 明文请求在握手层失败，不落到路由 | 同上（`Received HTTP/0.9 when not allowed`） |
| CA 只对 HTTPS 有意义 | `http://` + `--ca-file` 在建立客户端前就报错 | `a_ca_file_with_a_plaintext_endpoint_is_refused` |
| TLS 配置必须成对 | 只配证书或只配私钥都拒绝启动；相对路径也拒绝 | `half_configured_tls_is_refused` |
| 私钥不能组/其他可读 | 启动时检查 `mode & 0o077`，失败即拒绝绑定端口 | `a_world_readable_key_blocks_startup`、`a_world_readable_key_is_refused` |
| 空/非 PEM/不匹配的密钥 | `server_config` 在绑定前失败 | `an_empty_or_missing_certificate_fails_at_startup`、`a_mismatched_key_is_refused` |
| 慢连接不阻塞控制面 | 每次握手在独立任务里完成，`accept()` 只取已完成握手的连接（信号量 64，超时 10s） | `garbage_and_silent_connections_do_not_block_the_listener` |
| 只存凭据摘要 | 磁盘只有 SHA-256；token 明文只在签发时打印一次 | `issued_tokens_verify_and_never_store_the_secret`、`summaries_never_carry_the_digest` |
| 到期是半开区间 | `created_at <= at < expires_at`，边界秒即失效 | `issued_tokens_verify_and_never_store_the_secret`（4599/4600 秒） |
| 撤销立即生效且幂等 | 撤销后下一次请求即 401（已通过鉴权的进行中请求不被中断）；重复撤销保留最早的 `revoked_at` | `revoke_takes_effect_immediately_and_is_idempotent` |
| 伪造 token 不碰磁盘 | 前缀不符或摘要不符都直接拒绝，不做任何写入 | `foreign_and_forged_tokens_do_not_touch_the_store` |
| 坏库失败即拒绝 | 非 JSON、错 schema、未知字段、空 subject、坏摘要都 `Err`（fail-closed） | `a_corrupt_store_fails_closed`、`duplicate_identifiers_and_bad_lifetimes_are_rejected` |
| 并发签发不丢记录 | `issue`/`revoke`/`prune` 先取 `credentials.lock` 排他锁再读改写 | `concurrent_issuance_does_not_lose_records`（去掉锁后 8 次并发只剩 1 条） |
| 只清理已撤销且已过期 | 仍有效或"过期但没撤销"的记录都保留 | `prune_only_drops_credentials_that_expired_after_revocation` |
| 坏库不锁死控制面 | 动态凭据校验 `Err` 时记 stderr 并返回 401，主 token 照常通过 | `dynamic_credentials_authenticate_and_a_corrupt_store_still_denies` |

真实二进制（macOS ARM64 release，rustls 0.23/ring，TLS1.2+1.3，openssl 4.1.0 自建 CA → `CA:FALSE` 叶证书）在 `127.0.0.1:18877` 的实测矩阵：`curl --cacert` 三种协商全部 `200`（auto/h2、强制 `--http1.1`、强制 `--http2`）；不带 CA 时 curl 退出码 60、`unable to get local issuer certificate`、状态 `000`；向 TLS 端口发明文 HTTP 退出码 1、`Received HTTP/0.9 when not allowed`。CLI 带 `--ca-file` 访问 `https://` 成功返回 `[]`，不带 CA 报 `invalid peer certificate: UnknownIssuer`。

凭据侧：`credential issue --subject workbench --ttl-hours 1` 输出 `spt_` 前缀、101 字符、后 64 位十六进制的 token；`credentials.json` 与 `credentials.lock` 均为 `0600`，且磁盘上既没有明文也没有 secret 片段。该 token 能正常调用 `jobs` / `status`；`revoke` 后立刻复用得到 `controller: unauthorized`；重复 `revoke` 时 `revoked_at` 保持不变；根 token 全程不受影响；`--ttl-hours 2161` 被拒（`credential lifetime must not exceed 90 days`）；`prune` 默认 dry-run 只打印计划。向 `credentials.json` 写入坏内容后，CLI 用动态凭据退出码 1（`unauthorized`），服务端 stderr 出现 `credential store unusable`，根 token 仍是 200。松散私钥（`0644`）启动报 `TLS key … must not be readable by group or others (chmod 600)`；只配 `tls_key` 报 `tls_cert and tls_key must be configured together`；先发垃圾字节再建一条只连不说的连接，随后的正常请求仍在 1.6ms 内返回 200。证据见 [evidence/access-network-20261107.json](evidence/access-network-20261107.json)。

抓到的两个真实缺陷：`axum` 未启用 `http2` feature 时，ALPN 协商成 `h2` 但服务端只会说 HTTP/1.1，curl 报 `Error in the HTTP2 framing layer` —— 打开 `features = ["http2"]` 后三种协商全部正常。握手最初串行执行，被"只连不说"的客户端卡住整个控制面；改成每连接独立任务 + 64 并发上限 + 10 秒超时后，该测试与真实链路都恢复正常。

尚未覆盖：证书轮换/热重载（换证书需重启控制面）、客户端证书（mTLS，当前只做服务端证书校验）、凭据分级授权（短期凭据与根 token 权限相同，都能提交和取消任务，`Principal` 只用于识别主体与写审计）、跨公网真实 RTT、CA 文件轮换与吊销列表。

### 可查询的用户访问审计 {#access-audit}

_（本节标题锚点为 `access-audit`。）_

控制面用同一个中间件给**每个**请求留痕：先鉴权，再执行，最后按真实状态码落一行 JSON 到 `home/access.jsonl`。审计与鉴权分离（处理器用 `Principal` 提取器，不再各自比对 token），所以不会有"某个接口忘了记"，也不会出现两条鉴权路径判断不一致。

| 字段 | 含义 |
| --- | --- |
| `schema` | 行格式版本（当前 `1`），只增不改 |
| `time` | 落盘时刻（Unix 秒） |
| `request` | 客户端 `x-request-id`，或服务端生成的 UUID |
| `subject` | 主体名；根 token 固定 `root`，匿名请求为空串 |
| `kind` | `root` / `credential` / `anonymous` |
| `credential` | 短期凭据的 grant id；根 token 与匿名请求为 `null` |
| `decision` | `allowed` 或 `denied` |
| `reason` | `root-token` / `credential` / `missing-token` / `unknown-token` / `store-unusable` |
| `method`、`route` | 方法与**路由模板**（如 `/v1/jobs/{id}`）；未命中任何路由为 `unmatched` |
| `job` | 路径中的规范 UUID（不是就不记） |
| `status` | 实际返回的状态码 |

日志里**只有**上面这些字段：写入口只接受已经脱敏的值，没有把原始请求塞进去的通道。实测日志中不含根 token、凭据 secret，也没有 `authorization` 字样；请求正文、查询串与环境变量一律不落盘。未命中路由刻意只记 `unmatched` 而不记原始路径 —— 路径可能被塞进被误当成 URL 的凭据，记下来等于把秘密写进日志。

主体三态：根 token（`kind=root`，无凭据 id）、短期凭据（`kind=credential`，带 grant id，`subject` 是签发时给的名字）、匿名（`subject` 为空串）。拒绝同样记录，否则"有人一直在试 token"在日志里完全看不见；三种拒绝原因只进日志，**响应体永远是同一个 `unauthorized`**，不向探测者泄露"token 存在但过期"还是"凭据库坏了"。

请求标识：客户端给 `x-request-id` 且只含 `alnum` 与 `- _ . : /`、长度不超过 128 时原样沿用（可用于把 CLI 一次操作与服务端记录对上），否则服务端生成 UUID；这是为了避免调用方把换行或超长内容塞进日志行。

查询：`GET /v1/access?subject=&decision=&since=&limit=`，`limit` 默认 200、硬上限 5000，返回按时间倒序；`sshpool access` 是它的 CLI 包装。**查询本身也被审计** —— 匿名的 `/v1/access` 得到 401，而且这条拒绝会作为 `route == "/v1/access"`、`decision == "denied"` 的记录出现在下一次查询里。

有界：单文件 4 MiB，保留当前文件与 `.1`/`.2` 两代，磁盘上限 12 MiB。写满就滚动，**从不清空** —— 清空会让"审计突然变空"看起来像没有访问。滚动时先丢最老一代，再从旧往新搬，最后由 `current → .1`。

fail-closed 的两处边界：

| 情形 | 行为 | 自动化 |
| --- | --- | --- |
| 当前文件末行是崩溃留下的半行 | 读时容忍并告警；**下一条 append 先把它切掉**，不会变成中间行 | `newest_generation_is_readable_and_a_torn_tail_does_not_hide_history`、`a_torn_tail_is_dropped_before_the_next_append` |
| 中间行损坏（含 schema 不符、未知字段） | 整次查询 `Err`，不跳过、不猜 | `a_corrupt_middle_record_fails_closed` |
| 滚动代存在但读不了（权限、I/O） | 报错，不静默少读一段历史；只有「不存在」才跳过 | —（真实二进制：`access.jsonl.1` 置 000 后退出码 1） |
| 审计文件不可写 | 副作用请求（非 GET/HEAD/OPTIONS）在**执行前**返回 503，动作不发生；只读请求仍可用 | `a_non_writable_access_log_blocks_side_effect_requests` |
| 行太大 / 磁盘满 / sync 失败 | 不吞错误：响应结束后的写失败只记 stderr（不能把已完成的响应改成失败） | — |

`decision` 当前只区分 401 与"非 401"，这是一个**已知口径**：400（例如 `unknown job`、非法 `limit`）也会记成 `allowed`，`status` 才是准确的结论；要看真正的授权边界请用 `reason` + `status`。

真实二进制（macOS ARM64 release，临时 home、回环端口）实测：7 个矩阵请求加上 1 次就绪探测共留下 8 行，根 token 带 `x-request-id: cli-run-1` 时该字符串原样出现在 `request` 字段；凭据请求记成 `subject=workbench-ü`、`kind=credential`、带 grant id；匿名与伪造 token 都是 `401 / denied`（`missing-token` 与 `unknown-token`）；凭据打不存在的路由得到 `404`，日志里 `route=unmatched` 且不含 `/v1/does-not-exist`；`/v1/jobs/<uuid>` 的 UUID 进 `job` 字段。把 `access.jsonl` 换成一个同名目录后，`GET /v1/status` 仍 200，`POST /v1/nodes/test-node/disable` 返回 503。往末尾写半行后查询仍能读到 13 条；随后下一次请求返回 200，半行被清掉（`torn_line_still_present=false`、`new_record_found=true`），16 行全部可读。把第 2 行改成 `{not json}` 后 `sshpool access` 退出码 1，报 `malformed access record at …/access.jsonl:2: key must be a string`；把 `access.jsonl.1` 的权限设成 `000` 后同样退出码 1，报 `cannot read …/access.jsonl.1: Permission denied`。证据见 [evidence/access-audit-20261107.json](evidence/access-audit-20261107.json)。

尚未覆盖：跨主机汇集与远程日志后端（只写本机 `home/`）、防篡改（能写 home 的人可以改写或删除记录，没有签名链或只追加存储）、按主体分权（所有凭据权限相同，审计只记录不约束）、超过 12 MiB 的历史归档、按 IP/地理位置归因。

### 外部观测系统 {#external-observation}

_（本节标题锚点为 `external-observation`。）_

Prometheus 抓取走**独立的** `metrics_listen`（`config.toml`），默认不监听 —— 启动行写 `metrics=off`。它不挂在 `/v1/...` 上，因为 Prometheus 默认 15 秒抓一次，走控制面路由的话光是抓取就会在几分钟内把 12 MiB 的有界访问审计冲掉。抓取不经过 `audit_access` 中间件，也不触发远端探测：指标是控制面**已有事实**的渲染，不是新的探活通道。

| 指标 | 类型 | 口径 |
| --- | --- | --- |
| `sshpool_jobs{result}` | gauge | 终态任务数，6 类：`succeeded` / `failed-before-exit` / `failed-exit-nonzero` / `failed-after-exit` / `cancelled` / `interrupted`；进行中的任务不计入 |
| `sshpool_job_attempts_total`、`sshpool_job_retries_total` | counter | 已记录任务的尝试次数之和、除首次外的重试次数 |
| `sshpool_active_jobs`、`sshpool_queued_jobs`、`sshpool_queued_oldest_seconds` | gauge | 已领取未结束、等待领取、最老排队任务已等待秒数 |
| `sshpool_jobs_cleanup_unconfirmed` | gauge | 尚未确认远端清理的任务数 |
| `sshpool_job_queue_seconds{result}` | histogram | 提交到**第一次**被领取；从未领取不出样本 |
| `sshpool_job_duration_seconds{result}` | histogram | 最后一次领取到终态（含远端清理） |
| `sshpool_node_ready{node}` / `node_cpus` / `node_memory_available_mib` / `node_disk_available_mib` / `node_load` / `node_reserve_memory_mib` | gauge | 当前健康快照 |
| `sshpool_access_log_bytes{generation}` | gauge | 访问审计各代字节数；不存在的代次不出现 |

失败分类**只看结构化字段**（`phase` + `exit_code`），不解析 `job.message` 的文案：`failed-before-exit` 是容器没给出退出码（调度、SSH、启动或超时未确认），`failed-exit-nonzero` 是跑完但退出码非零，`failed-after-exit` 是以 0 退出后失败（产物、清理、复制）。改提示文案不会改变任何分类。

直方图是**累计桶** `5/30/120/600/1800/7200` 秒再加 `+Inf`，每个 `result` 分类都有完整的 `_bucket`/`_sum`/`_count` 三条，`+Inf` 恒等于 `_count`。没有样本的分类照报 0 桶，抓取端不用判断"这个分类存不存在"。

节点探测失败（SSH 不可达、未探测过）时 `node_ready=0`，且 `node_cpus` / `memory_available_mib` / `disk_available_mib` / `node_load` 一律报 **0**，不沿用上一次快照 —— 旧数字会被误读成当前水位。`node_reserve_memory_mib` 是配置事实，探测失败照报。节点名按 Prometheus 规则转义 `\`、`"` 与换行：一个带引号的节点名不该能让整份 exposition 解析失败。

端点行为：

| 情形 | 行为 | 自动化 |
| --- | --- | --- |
| `GET /metrics` 与 `GET /` | 200，`text/plain; version=0.0.4; charset=utf-8` | `scraping_is_parseable_and_never_writes_the_access_audit` |
| 未知路径 | 404，不把任何请求都当成指标 | 同上 |
| 沉默/半开连接 | 只丢那一条（每条连接独立任务、5 秒读超时、32 连接上限） | `a_silent_scraper_does_not_block_the_next_scrape` |
| 不配 `metrics_listen` | 启动行写 `metrics=off`，没有第二个监听端口 | `metrics_are_off_by_default_and_opt_in_on_a_separate_port` |
| 节点不可达 | `node_ready=0`、资源报 0、控制面仍服务 | `an_unprobeable_node_reports_zero_resources_not_a_stale_number` |
| 空控制面 | 仍输出稳定骨架（各项 0），抓取端不用判空 | 同上（`nodes = []`） |
| 端口被占用 | 服务启动前直接失败，而不是运行到第一次抓取才发现 | —（`serve` 里先 bind） |
| `metrics_listen` 与 `api_listen` / `ssh_listen` 同端口 | 配置校验直接拒绝，不等到 bind | `metrics_endpoint_cannot_reuse_a_control_plane_port` |

值的类型是硬约束：样本值只能是数字，`sshpool_node_ready` 曾输出过 `true`，那会让整份 exposition 被解析器拒绝；测试里的严格解析器就是这条的守卫（`the_parser_rejects_a_boolean_sample_and_counts_inf`）。

真实二进制（macOS ARM64 release，临时 home、回环端口）实测：4 个终态任务夹具（成功、退出码 3、0 退出后失败、清理未确认的 interrupted）加 1 个不可达节点，抓取 200、`content-type` 正确、9916 字节 / 160 行；`succeeded=1`、`failed-exit-nonzero=1`、`failed-after-exit=1`、`failed-before-exit=0`、`interrupted=1`、`cancelled=0`，`attempts_total=4`、`retries_total=0`、`cleanup_unconfirmed=1`；排队 4 秒在 `le="5"` 起每个边界都为 1、`sum=4`，执行 207 秒与 296 秒分别落在对应分类的 `sum` 里，`+Inf == count`。节点全部报 0 而预留仍是 4096（配置事实）。同一份状态下连续两次抓取字节完全一致。8 条只连不说的连接没有拖住下一次抓取（0.0s 返回 200）。抓取 3 次前后 `access.jsonl` 都是 752 字节，证明它不写审计。不配 `metrics_listen` 的实例启动行是 `metrics=off`。空控制面（无任务、无节点）照常 200 并输出全 0 骨架。把 `metrics_listen` 配成与 `api_listen` 同一个端口时，`serve` 在绑定前就以退出码 1 报 `metrics_listen must not reuse api_listen or ssh_listen`，没有先占端口。证据见 [evidence/metrics-20261107.json](evidence/metrics-20261107.json)。

尚未覆盖：日志后端本身（本仓库只产出 `events.jsonl` 与 `access.jsonl`，由部署者用 Loki/ELK 消费）、指标持久化与 Prometheus 抓取配置（本仓库只提供 exposition 端点）、**端点鉴权**（该端口无鉴权，因此只暴露节点名与数值，不含 SSH 目标、token、任务消息或任何自由文本，也不含按 IP 的归因）、多控制面实例的聚合。

### 存储放置核算 {#storage-placement}

RAID 可以不做，但「几副本、能少几个域、还剩多少可写容量」必须先算清楚再承诺。`src/placement.rs` + `sshpool storage-plan --topology <file>` 对一份**只描述事实**的拓扑做纯算术：不探测主机、不读块设备、不格式化、不创建 OSD，输出一份 JSON 与退出码。

```json
{
  "schema": 1,
  "replica_count": 3,
  "min_size": 2,
  "recovery_reserve_permille": 200,
  "monitor_count": 3,
  "hosts": [
    { "name": "store-a", "failure_domain": "rack-a", "devices": [{ "name": "sda", "size_bytes": 4000000000000 }] },
    { "name": "store-b", "failure_domain": "rack-b", "devices": [{ "name": "sdb", "size_bytes": 6000000000000 }] },
    { "name": "store-c", "failure_domain": "rack-c", "devices": [{ "name": "sdc", "size_bytes": 8000000000000 }] }
  ]
}
```

```sh
sshpool storage-plan --topology topology.json   # 可承诺：退出码 0
                                               # 拒绝承诺：退出码 2，报告仍完整
```

核算口径：

| 项 | 规则 |
| --- | --- |
| 故障域 | 同一 `failure_domain` 的多个 VM 合并为**一个**；`vm_of` 指向的物理宿主与其 VM 也合并 |
| VM 自报独立域 | `vm_of` 指向 A 却写了自己的 `failure_domain` → 拒绝（不能靠改名字买到第二个域） |
| 物理盘与 VM 盘同域 | 两代都申报磁盘 → 拒绝（容量属于哪一层不明确，会被重复计算） |
| 副本容量 | 副本必须落在不同域；可写数据 `D` 满足 `副本数 × D ≤ Σ min(域可用容量, D)`，用整数二分求上限，不做浮点近似 |
| 恢复预留 | 每域先扣 `recovery_reserve_permille`（千分比），**必填**；缺省成 0 等于虚报容量 |
| 仲裁 | `monitor_count` 必须是奇数且不超过域数；`quorum = n/2 + 1`，容错 `n - quorum` |
| 拒绝时 | `usable_after_recovery_reserve_bytes = 0`、`tolerated_domain_failures = null`，即使有人只看数字也拿不到可用容量 |
| 输入边界 | `deny_unknown_fields`；拼错键、缺字段、类型不符在解析阶段就失败（退出码 1），不会输出半份报告 |

真实二进制（macOS ARM64 release）实测两份脱敏拓扑：

| 拓扑 | 结果 |
| --- | --- |
| 3 个物理域，盘 4/6/8 TB，3 副本、`min_size=2`、恢复预留 200‰、3 个仲裁 | 退出码 0；`distinct=3`、`raw=18.0 TB`、`reserve=3.6 TB`、可写 **3.2 TB**（受最小域 4 TB×80% 约束，不是三域平均）、`tolerated_domain_failures=1`、`monitor_quorum=2` |
| 2 个物理域，各 1 台物理机 + 1~2 台 VM，VM 不申报磁盘 | 退出码 2；`distinct=2`、可写 **0**、`tolerated_domain_failures=null`；blocker 明说「只有 2 个故障域具备容量，放不下 3 副本」 |
| 同域物理盘 + VM 盘 | 退出码 2；blocker 报「容量会被重复计算」 |

边界：这是**规划算术**，不是存储已部署，更不是耐久性证明。它不校验 Ceph 是否真的把 OSD 分到了这些域、不测 `fsync`/崩溃恢复、不替代 [数据库恢复](#stateful-backup-recovery) 与 SSI 状态恢复。容量数字来自输入文件里申报的 `size_bytes`，不来自真实探测；盘的归属仍要先过 `storage-admission`。证据见 [evidence/storage-placement-20261107.json](evidence/storage-placement-20261107.json)。

## hardware-proof

2026-11-07 起，这条链路有可复跑的 `#[ignore]` 测试：`tests/hardware_live.rs`。它在测试进程内启动临时控制面（临时 home + 回环随机端口），由 **ARM64 工作台执行真实 CLI** 通过 `host.lima.internal` 访问该控制面，再派发到独立 x86_64 Worker。

```sh
scripts/prepare-live-workbench.sh sshpool-anchor     # 把当前源码构建到工作台，只用测试二进制
SSHPOOL_LIVE_WORKBENCH=sshpool-anchor \
SSHPOOL_LIVE_WORKER=okm182-lan \
SSHPOOL_LIVE_WORKBENCH_BIN=/tmp/sshpool-src/target/release/sshpool \
  cargo test --test hardware_live -- --ignored --test-threads=1
```

| 断言 | 实测（任务 `596ccb1d-…`） |
| --- | --- |
| 角色先核对 | 工作台 `linux/aarch64`、4 CPU、5902 MiB；Worker `x86_64`、32 CPU |
| 平台不匹配优先于优先级 | 工作台 `priority=100` 且登记了 `alpine:3.22`，但 `linux/amd64` 任务只派给 Worker，`attempts` 只有一条 |
| Worker 上确实在跑 | 该 Worker 的 `docker top sshpool-<id>-1` 含 `build.sh`（5 行），容器标签与任务 ID 一致 |
| 工作台没有执行 | 同一时刻按 `label=io.sshpool.job` 查工作台 Docker，容器数 0 |
| 产物回工作台 | 工作台执行 `sshpool fetch`，解出 `arch=x86_64`、`sum=40000`，与等差数列公式独立复算一致 |
| 清理 | 任务结束后 Worker 与工作台按标签查询均为空，工作台 job 容器总数回到提交前 |

`workbench_and_pool_capabilities_are_reported_separately`（任务 `606769ed-…`）验证「指标不合并」：统一入口的 `uname -sm` 是 `Linux aarch64`、`nproc` 是 4、`/proc/meminfo` 是工作台自己的 5902 MiB；而同一次 `sshpool status` 返回两条独立快照（`aarch64/4` 与 `x86_64/32`，内存各自报数），任务记录的 `attempt.node` 是 `worker`，客户端进度行也打印 `worker=worker platform=linux/amd64`。

跑这条测试时抓到一个真实误连：工作台登录环境里有 `SSHPOOL_TOKEN_FILE` 指向生产控制面，而 CLI 的 `--home` 只换目录、token 仍按 env 回退解析，于是客户端拿着**生产 token** 去打临时控制面并得到 `unauthorized`。测试现在显式传 `--token-file`；这也说明「换一个 home 就等于换一套凭据」是错的。证据在 [evidence/hardware-20261107.json](evidence/hardware-20261107.json)。

### 手工记录（2026-11-05）

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
