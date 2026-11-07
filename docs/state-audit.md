# 应用状态与持久化约定审核（`state-audit`）

迁移方案的第一步不是搬运数据，而是弄清**哪些数据丢了会出事**。`sshpool state-audit` 把这一步做成可核对的动作：人写一份清单声明「应用依赖哪些状态、承诺什么 RPO/RTO」，工具用只读探针到主机上核对，然后给出**可复核的结论和退出码**。

它不迁移、不备份、不创建容器、不改任何配置。它回答的只有一个问题：**这份清单能否作为制定迁移方案的前提。**

```sh
sshpool state-audit --inventory examples/state-audit/sub2api.json --ssh okm182 --output /tmp/audit.json
# 复核别人采集的现场结果，不需要网络：
sshpool state-audit --inventory examples/state-audit/sub2api.json --probe /tmp/probe.json
```

| 退出码 | 含义 |
| --- | --- |
| `0` | 清单与事实一致，`migration_plan_approved: true`，可以据此制定迁移方案 |
| `2` | 审核完成但**被拒**：有 blocker 或 violation，报告里逐条写明原因 |
| `1` | 输入非法（清单/探针 JSON 不合协议、`--ssh` 与 `--probe` 没有二选一、`--output` 已存在） |

`0` 只表示「清单被核对了」，不表示「迁移会成功」。被拒（`2`）通常才是真实现状。

## 两个输入

**清单**（人工维护，进版本库）：应用版本、镜像、RPO/RTO 目标、每个状态面的声明。完整字段见 `src/state_audit.rs` 的 `Inventory`；未知字段一律拒绝，避免拼错的键被当成默认值。

**探针**（现场采集，可离线复核）：`--ssh` 时由远端只读脚本生成，`--probe` 时读取已经采集好的 JSON。探针只用 `docker inspect` / `docker exec ... psql|redis-cli` 的只读命令与 `stat` / `du`，并且：

- 宿主绝对路径只以 `sha256` 前 16 位出现在报告里（`source_digest`），不进证据文件。
- Redis 口令只从容器自己的 `Cmd` 里取（它本来就在那里），用完即弃，绝不进入输出。
- 报告只带事实与判断，不带密码、连接串、业务行。

自动化测试：`tests/state_audit.rs`（7 条，离线跑在 CI 上）验证退出码与拒绝语义；`tests/state_audit_live.rs`（3 条，`#[ignore]`）在真实主机上跑同一份清单，其中一条是阳性对照 —— 只有把声明改成与事实相符才应通过。

## 三态备份：为什么 `manual` 是 `null` 而不是一个大数

`Backup` 只有三种形态：

```json
{ "kind": "scheduled", "interval_seconds": 3600, "evidence": "cron.d:pg-backup#9f2c81d6a4b70e13" }
{ "kind": "manual" }
{ "kind": "none" }
```

`evidence` 不是给人看的备注，而是**要在探针结果里对上号的宿主调度来源**。探针会记录三类任务：

| 来源写法 | 对应 |
| --- | --- |
| `crontab:root` | `crontab -l` 里的一行（探针只以 root 身份读，其他用户的 crontab 看不到） |
| `cron.d:<文件名>` | `/etc/cron.d/` 下的某个文件里的一行（行首的用户字段已去掉） |
| `systemd-timer:<单元名>` | `systemctl list-timers --all` 里的一个 `.timer` 单元 |

只有 `scheduled` 才有 `interval_seconds`；人工备份没有可证明的节奏，没有备份更是如此，两者都返回 `None`。这个 `None` 会一路传到 `SurfaceReport.achievable_rpo_seconds` 与 `Report.achievable_rpo_seconds`，含义是**RPO 没有上界**。

这不是抠字眼：把「说不清多久备份一次」写成 86400，就等于凭空承诺「最多丢一天」，而审核并没有证据支撑这句话。所以报告里出现 `null` 时，正确读法是「按现有事实给不出上界」，而不是「0」或「很大」。

## 定时备份的声明不能自己证明自己

`scheduled` 是**主张**，不是证据。审核要求主机上确实存在能指认的定时任务，否则按「没有定时备份」计 RPO。三条判定：

| code | 触发 | 后果 |
| --- | --- | --- |
| `backup_schedule_unverified` | 探针在 crontab / `cron.d` / systemd timer 里都找不到 `evidence` 命中的任务 | 该面上界退回 `null` |
| `backup_schedule_ambiguous` | `evidence` 命中了**多条**任务 | 同上：挑不出「哪条是备份」，任何一条都不算数 |
| `backup_schedule_unparsed` | 命中了唯一一条，但周期无法从表达式解析 | 同上：「说不清多久一次」换不来上界 |

**为什么要求唯一命中。** 只写来源是没有指向性的：`crontab:root` 里通常还躺着 `sysstat` 之类的琐碎任务，正好每 10 分钟跑一次。如果「来源对上就算数」，那么主机上有一条每 10 分钟的任务，就能让任意清单拿到「RPO ≤ 10 分钟」——这正是本工具要防的自我保证。所以当同一来源下有多条任务时，`evidence` 必须补 `#<命令摘要>` 精确指向其中一条：

```json
{ "kind": "scheduled", "interval_seconds": 3600,
  "evidence": "cron.d:pg-backup#9f2c81d6a4b70e13" }
```

摘要就在探针结果的 `backup_schedules[].command_digest` 里（命令行的 `sha256` 前 16 位）。命令行原文不进报告，避免把连接串或口令带进仓库。

上界成立时，该状态面的 `detail` 会写明**信的是哪一条**（例如「只能回到最近一次逻辑备份（间隔 ≤ 3600 秒）（证据 `cron.d:pg-backup#9f2c81d6a4b70e13`）」）。只报一个秒数的话，评审者无法判断 `systemd-timer:sysstat-collect.timer` 这类明显不是备份的任务有没有被误当成证据；点名之后这种错误一眼可见。

**周期只认观测值。** 即使清单写 600 秒、主机上的任务实际每 3600 秒一次，报告也按 3600 秒计 —— 声明的数字不能覆盖实测的数字。解析规则：

- 只有「每天重复」的形态（`分 时 * * *`）才给周期；限定了某日/某月/某星期时触发时刻不固定，回答 `null`。
- 周期取相邻触发时刻的**最大**间隔，因为 RPO 关心的是「最久要等多久」。`* */2 * * *`（只在偶数小时每分钟）因此是 3660 秒，不是 60 秒。
- 支持 `@daily` / `@hourly` 等宏与 `a-b`、`a,b`、`*/n` 字段；解析不了就是无上界，不猜。
- systemd timer 只读 `OnUnitActiveSec`；只写 `OnCalendar` 的单元目前给不出周期。

## 判定规则

**阻塞项（blockers，让结论本身无效）**

| code | 触发 |
| --- | --- |
| `probe_failed` | 探针报告了错误（连不上、没权限、解析失败） |
| `probe_schema` | 探针协议版本不符 |
| `image_not_pinned` | 没有任何镜像带 `@sha256:` 摘要 |
| `image_not_observed` | 声明的镜像没出现在主机的运行容器里 |
| `postgres_target_missing` / `redis_target_missing` / `volume_target_missing` | 声明的容器、库或挂载点不存在 |
| `declared_table_missing` | 声明的关键表在库里不存在 |
| `dedup_index_missing` | 去重声明要求的唯一索引不存在（或列不匹配） |
| `rpo_not_declared` | 清单里 `rpo_seconds` 是 `null`：从未承诺过 RPO |
| `rpo_zero_unproven` | RPO 声明为 0；只读审核无法证明每次提交都已落盘 |
| `rto_unrehearsed` | 声明了 RTO 但 `rto_rehearsal` 是 `none` |

**违背项（violations，声明与事实冲突，且会降级该声明）**

| code | 触发 | 后果 |
| --- | --- | --- |
| `redis_cache_claim_refused` | 声明 `derived`（可丢弃缓存），但无 TTL 键数超过 `cache_persistent_allowance` | 该面 `effective_disposition` 改为 `authoritative`，RPO 按权威状态计 |
| `redis_prefix_absent` | 声明某个前缀保存状态，但所有库里都没有该前缀的键 | 结论被拒，且不反过来假设「那它一定只是缓存」 |
| `unlogged_declared_table` | 声明的关键表是 UNLOGGED | 崩溃后会被截断，不能算权威状态 |
| `rpo_claim_unachievable` | 声明 RPO 小于按事实算出的最差状态面 | 结论被拒 |
| `rto_full_stack_unproven` | 声称整套栈的 RTO 已演练 | 只读审核没有切入口、没有打断长连接 |
| `failure_domain_claim_refused` | 宣称状态面在独立故障域，但探到的设备号相同 | 同盘不能算独立域 |

定时备份的三条判定（`backup_schedule_unverified` / `backup_schedule_ambiguous` / `backup_schedule_unparsed`）属于违背项，后果都是「该面上界退回 `null`」，见上一节。

**提示项（warnings，不阻塞）**：`no_wal_archive`（`archive_mode=off`，无法做时间点恢复）、`rto_scope_data_layer`（RTO 只对数据层成立）、`undeclared_database_containers`（主机上还有别的数据库容器不在本次范围）、`writable_binds_outside_scope`（声明的状态面之外还有别的可写挂载）、`unlogged_table`、`declared_table_without_primary_key`、`failure_domain_unknown`、`redis_all_databases_empty`（报了库但全 0 键，要确认探针连对了实例）。

整体 `achievable_rpo_seconds` 取所有 `authoritative` 状态面中最差的那个；只要有一处是 `None`，整体就是 `None`。

## 现状实测（`okm182` 上的 `sub2api`，2026-11-08）

```sh
sshpool state-audit --inventory examples/state-audit/sub2api.json --ssh okm182
# exit 2
```

| 状态面 | 事实 | RPO 上界 |
| --- | --- | --- |
| `postgres::sub2api` | `archive_mode=off`、0 副本、只有人工备份；3188.5 MiB、116 表、78 序列 | `null` |
| `redis` | AOF + `appendfsync everysec`、0 副本；3 个库、**4346 个无 TTL 键** | 声明 `derived` 被拒 → 按权威状态计 1 秒 |
| `sub2api:/app/data` | 可写挂载、2976.2 MiB、设备 2049（与两份数据库目录同一块盘） | `null` |

结论：`migration_plan_approved: false`，violations 是 `redis_cache_claim_refused` + `rpo_claim_unachievable`，没有 blocker —— 也就是说审核本身是有效的，被拒的是清单里的承诺。

## 边界

- 只读审核，**不执行迁移**。`0` 不是「迁移已演练」，更不是「生产可以故障切换」。
- 探针抓的是采集那一刻的状态；备份节奏、AOF 配置、表结构变化后要重跑。
- 只覆盖清单列出的应用。主机上别的数据库容器只会作为 `undeclared_database_containers` 提示，不在结论内。
- `achievable_rpo_seconds` 是**按配置推的上界**（AOF `everysec` → 1 秒、备份间隔 → 间隔、WAL 归档 → 段切换），不是压测出来的实测丢失量；`fsync` 是否真的生效、盘是否真的持久，这条链路不会证明。
