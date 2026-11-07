//! 应用状态与持久化约定的只读核对：把「哪些数据必须一致迁移」变成可核对的清单。
//!
//! 与 `migration` 的分工：那边负责**真的搬一次**并比较两侧指纹；这里不搬任何数据，
//! 只回答三个在动手搬迁之前必须回答的问题：
//!
//! 1. 这个应用到底有哪些状态面（数据库、缓存、宿主机目录），有没有漏掉的；
//! 2. 声明的 RPO/RTO 有没有事实支撑（归档开着吗、有副本吗、备份间隔多长）；
//! 3. Redis 里真的只有可丢弃的缓存吗（有多少键没有 TTL、调度/会话前缀在不在）。
//!
//! 三条硬规则，全部 fail-closed：
//! - 声明了却探不到、探到了却与声明的镜像/表/唯一索引不符 → 审核**结论无效**（blocker）；
//! - 事实与声明冲突（RPO 太小、Redis 说是缓存却有持久键、同盘却宣称独立故障域）
//!   → 拒绝该声明（violation），而不是把它写成「已确认」；
//! - 只读：探针不改库、不改配置、不删数据，也不读取业务行内容。
use crate::{config::Node, transport};
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

/// 清单与探针的协议版本；只增不改。
pub const SCHEMA: u32 = 1;
/// 清单大小上限：一份人工核对的清单不会到 1 MiB。
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
/// 单库表数上限；超出说明「声明几张关键表」这件事本身已经不成立。
pub const MAX_TABLES: usize = 5000;
/// 报告里最多列出的名字个数，避免一台忙碌主机的发现清单淹没结论。
const MAX_LISTED: usize = 20;

/// `archive_timeout=0` 时 WAL 只在写满一个段或触发检查点时切换。这里用 1 小时作为
/// 保守上界，并在报告里写明这是假设值——不把假设伪装成测量结果。
const ARCHIVE_TIMEOUT_FALLBACK_SECONDS: u64 = 3600;

/// 状态面被声明成什么。`derived` 表示可以重建，因此不参与 RPO 汇总。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// 丢了就是数据丢失，必须被复制或备份覆盖。
    Authoritative,
    /// 可以重建；只有核实「确实可以重建」之后才按 0 RPO 计算。
    Derived,
}

/// RTO 只可能被演练到什么程度。没有演练就不允许写 RTO 目标。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Rehearsal {
    None,
    /// 只演练过数据层（备份/恢复/切回），不含入口与长连接。
    DataLayer,
    /// 声称整套栈都演练过；只读审核无法验证，一律拒绝。
    FullStack,
}

/// 一份状态面当前实际拥有的离线备份节奏。
///
/// 不提供「随便填个秒数」的入口：只有人工备份时，RPO 根本没有上界，
/// 写成一个大数字会让人误以为「最坏也就丢这么多」。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Backup {
    /// 定时备份，间隔秒数。
    Scheduled { interval_seconds: u64 },
    /// 只有人工触发的备份：没有固定间隔，RPO 无上界。
    Manual,
    /// 完全没有备份。
    None,
}

impl Backup {
    /// 回到最近一次可用副本所需的最长等待；`None` 表示没有上界。
    fn rpo_bound(self) -> Option<u64> {
        match self {
            Backup::Scheduled { interval_seconds } => Some(interval_seconds),
            Backup::Manual | Backup::None => None,
        }
    }
    fn describe(self) -> &'static str {
        match self {
            Backup::Scheduled { .. } => "定时备份",
            Backup::Manual => "只有人工备份",
            Backup::None => "没有备份",
        }
    }
}

/// 一份人工维护的状态清单。未知字段直接拒绝，避免拼错的键被当成默认值。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema: u32,
    pub application: String,
    pub version: String,
    /// 应用镜像，至少一条必须带 `@sha256:` 摘要；只有 tag 的声明无法固定版本。
    pub images: Vec<String>,
    /// 应用整体 RPO 目标（秒）：允许丢失多长的写入。
    ///
    /// `null` 表示**没有**承诺过 RPO。这是最常见的真实状态，也必须是显式的：
    /// 默认成 0 会伪装成同步持久化，默认成一个大数字会伪装成「最坏也还好」。
    pub rpo_seconds: Option<u64>,
    /// 应用整体 RTO 目标（秒）。
    pub rto_seconds: u64,
    /// RTO 被演练到的范围。
    pub rto_rehearsal: Rehearsal,
    #[serde(default)]
    pub postgres: Vec<PostgresTarget>,
    #[serde(default)]
    pub redis: Vec<RedisTarget>,
    #[serde(default)]
    pub volumes: Vec<VolumeTarget>,
    pub failure_domains: FailureDomains,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FailureDomains {
    /// 是否宣称这些状态面分布在不同物理故障域。
    pub claim_independent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresTarget {
    pub container: String,
    pub database: String,
    /// 探针用的库内角色；只做只读会话，不写入。
    pub user: String,
    /// 这份数据当前实际拥有的离线备份（归档关闭时它就是 RPO 的来源）。
    pub backup: Backup,
    /// 按用途分组的关键表：会话、计费、后台任务等。组名由人决定，表必须真实存在。
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// 幂等/去重声明：某张表上有唯一索引覆盖这些列。
    #[serde(default)]
    pub dedup: Vec<Dedup>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dedup {
    /// 这条去重保护的是哪个动作，例如「客户端重试不得重复计费」。
    pub purpose: String,
    pub table: String,
    pub columns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisTarget {
    pub container: String,
    pub disposition: Disposition,
    /// 离线快照/备份；AOF 关闭时 RPO 只能到这里。
    pub backup: Backup,
    /// 必须真实存在的键前缀，用来证明 Redis 承担的是状态而不是纯缓存。
    #[serde(default)]
    pub required_prefixes: Vec<String>,
    /// 声明 `derived` 时允许存在的、没有 TTL 的键数。超过就说明这个声明不成立。
    #[serde(default)]
    pub cache_persistent_allowance: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeTarget {
    pub container: String,
    /// 容器内路径，例如 `/app/data`。
    pub destination: String,
    pub disposition: Disposition,
    pub backup: Backup,
}

/// 探针原始结果；由远端只读脚本生成，也可离线复核。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub schema: u32,
    pub collected_at_unix: u64,
    #[serde(default)]
    pub discovered: Vec<Discovered>,
    #[serde(default)]
    pub postgres: Vec<PostgresFacts>,
    #[serde(default)]
    pub redis: Vec<RedisFacts>,
    #[serde(default)]
    pub mounts: Vec<MountFacts>,
    /// 单个目标探测失败也要保留原因；非空即表示审核不完整。
    #[serde(default)]
    pub errors: Vec<String>,
}

/// 主机上实际在跑的容器；用来发现清单漏掉的状态面。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Discovered {
    pub name: String,
    pub image: String,
    pub image_id: String,
    /// 识别出的数据库引擎名；空串表示不是已知状态引擎。
    pub engine: String,
    #[serde(default)]
    pub writable_binds: Vec<WritableBind>,
}

/// 一个可写挂载点。只保留容器内路径与宿主路径的摘要：报告要能指认「哪个目录」，
/// 但不必把宿主机的绝对路径带进仓库或证据文件。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WritableBind {
    pub destination: String,
    /// 宿主源路径的 SHA-256 前 16 位；相同摘要即同一个目录。
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresFacts {
    pub container: String,
    pub database: String,
    pub server_version: String,
    pub archive_mode: String,
    pub wal_level: String,
    pub archive_timeout_seconds: u64,
    pub replicas: usize,
    pub size_bytes: u64,
    pub sequences: usize,
    pub tables: Vec<String>,
    #[serde(default)]
    pub unlogged: Vec<String>,
    #[serde(default)]
    pub without_primary_key: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub unique_indexes: Vec<UniqueIndex>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UniqueIndex {
    pub table: String,
    pub name: String,
    pub columns: Vec<String>,
    pub primary: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisFacts {
    pub container: String,
    pub version: String,
    pub appendonly: bool,
    pub appendfsync: String,
    pub save_rules: String,
    pub replicas: usize,
    pub databases: Vec<RedisDb>,
    /// 声明前缀在**所有**库里命中的键数。
    #[serde(default)]
    pub prefix_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisDb {
    pub index: u32,
    pub keys: u64,
    pub expires: u64,
}

/// 宿主机上的数据目录；只保留容器内路径、用量与设备号，不保留主机绝对路径。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MountFacts {
    pub container: String,
    /// `volume`（清单声明）或 `engine-data`（数据库容器自己的数据目录）。
    pub role: String,
    pub destination: String,
    pub read_only: bool,
    pub bytes: Option<u64>,
    /// 宿主文件系统设备号；相同即同一块盘。
    pub device: Option<String>,
}

/// 一条结论：`code` 稳定可断言，`detail` 给人看。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SurfaceReport {
    pub kind: &'static str,
    pub name: String,
    pub declared_disposition: Disposition,
    /// 声明被拒之后按 `authoritative` 计入，而不是继续按 0 RPO 计算。
    pub effective_disposition: Disposition,
    /// `null` 表示按现有事实给不出 RPO 上界（例如只有人工备份或完全没有备份）。
    pub achievable_rpo_seconds: Option<u64>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub containers: usize,
    pub database_containers: Vec<String>,
    pub undeclared_database_containers: Vec<String>,
    pub writable_binds_outside_scope: Vec<String>,
    pub writable_binds_outside_scope_total: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Report {
    pub schema: u32,
    pub scope: &'static str,
    pub read_only: bool,
    pub application: String,
    pub version: String,
    pub collected_at_unix: u64,
    pub declared_rpo_seconds: Option<u64>,
    pub declared_rto_seconds: u64,
    pub rto_rehearsal: Rehearsal,
    /// 按事实算出的最差权威状态面；`null` 表示无法给出上界。
    pub achievable_rpo_seconds: Option<u64>,
    pub rpo_claim_supported: bool,
    pub surfaces: Vec<SurfaceReport>,
    pub discovery: DiscoveryReport,
    /// 与事实冲突、被拒绝的声明。
    pub violations: Vec<Finding>,
    /// 让审核结论本身无效的问题（探不到、声明对不上）。
    pub blockers: Vec<Finding>,
    pub warnings: Vec<Finding>,
    /// 只有审核完整且没有未获支持的声明时才是 true。
    pub migration_plan_approved: bool,
}

/// 读取清单；大小、结构、标识符都在这里拒绝，后面的规则只看到干净输入。
pub fn read_inventory(path: &Path) -> Result<Inventory> {
    let bytes = read_bounded(path, "inventory")?;
    let inventory: Inventory = serde_json::from_slice(&bytes)
        .context("清单不是协议 1 的 JSON（未知字段、缺字段或类型不符）")?;
    validate(&inventory)?;
    Ok(inventory)
}

/// 读取离线探针结果；与 `read_inventory` 一样先做大小与结构检查。
pub fn read_probe(path: &Path) -> Result<Probe> {
    let bytes = read_bounded(path, "probe")?;
    let probe: Probe = serde_json::from_slice(&bytes).context("探针结果不是协议 1 的 JSON")?;
    ensure!(probe.schema == SCHEMA, "unsupported probe schema");
    Ok(probe)
}

fn read_bounded(path: &Path, what: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("{what} {} is not readable", path.display()))?;
    ensure!(metadata.is_file(), "{what} must be a regular file");
    ensure!(
        metadata.len() <= MAX_DOCUMENT_BYTES,
        "{what} exceeds {MAX_DOCUMENT_BYTES} bytes"
    );
    Ok(std::fs::read(path)?)
}

/// 清单自身的形状校验：不做任何远端判断，只保证后续规则面对的是合法输入。
pub fn validate(inventory: &Inventory) -> Result<()> {
    ensure!(inventory.schema == SCHEMA, "unsupported inventory schema");
    ensure!(
        !inventory.application.trim().is_empty(),
        "application is empty"
    );
    ensure!(!inventory.version.trim().is_empty(), "version is empty");
    ensure!(!inventory.images.is_empty(), "no image is declared");
    for image in &inventory.images {
        ensure!(
            image.len() <= 256 && !image.chars().any(|c| c.is_control() || c.is_whitespace()),
            "image reference contains whitespace or control characters"
        );
    }
    ensure!(
        inventory.postgres.len() + inventory.redis.len() + inventory.volumes.len() > 0,
        "no state surface is declared"
    );
    for target in &inventory.postgres {
        validate_container(&target.container)?;
        validate_identifier(&target.database, "database")?;
        validate_identifier(&target.user, "user")?;
        for (group, tables) in &target.groups {
            ensure!(!group.trim().is_empty(), "a table group has no name");
            for table in tables {
                validate_table_name(table)?;
            }
        }
        for dedup in &target.dedup {
            ensure!(
                !dedup.purpose.trim().is_empty(),
                "a dedup claim has no purpose"
            );
            validate_table_name(&dedup.table)?;
            ensure!(!dedup.columns.is_empty(), "a dedup claim has no columns");
            for column in &dedup.columns {
                validate_identifier(column, "column")?;
            }
        }
    }
    for target in &inventory.redis {
        validate_container(&target.container)?;
        for prefix in &target.required_prefixes {
            ensure!(
                !prefix.is_empty()
                    && prefix.len() <= 64
                    && !prefix.chars().any(|c| c.is_control() || c.is_whitespace()),
                "key prefix contains whitespace or control characters"
            );
        }
    }
    for target in &inventory.volumes {
        validate_container(&target.container)?;
        ensure!(
            target.destination.starts_with('/')
                && !target.destination.contains("..")
                && !target
                    .destination
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace()),
            "volume destination must be an absolute container path without `..`"
        );
    }
    Ok(())
}

fn validate_container(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')),
        "container name has characters OpenSSH/docker cannot take verbatim"
    );
    Ok(())
}

fn validate_identifier(value: &str, what: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "{what} must be a plain SQL identifier"
    );
    Ok(())
}

fn validate_table_name(value: &str) -> Result<()> {
    let name = value.rsplit('.').next().unwrap_or(value);
    validate_identifier(name, "table")?;
    if value.contains('.') {
        let schema = value.split('.').next().unwrap_or("");
        validate_identifier(schema, "schema")?;
    }
    Ok(())
}

fn finding(code: &'static str, detail: impl Into<String>) -> Finding {
    Finding {
        code: code.to_string(),
        detail: detail.into(),
    }
}

/// 纯函数判定：同样的事实必须得到同样的结论，且不触碰磁盘与网络。
pub fn assess(inventory: &Inventory, probe: &Probe) -> Report {
    let mut blockers = Vec::new();
    let mut violations = Vec::new();
    let mut warnings = Vec::new();
    let mut surfaces = Vec::new();

    if probe.schema != SCHEMA {
        blockers.push(finding(
            "probe_schema",
            format!("探针协议为 {}，期望 {SCHEMA}", probe.schema),
        ));
    }
    for error in &probe.errors {
        blockers.push(finding("probe_failed", error.clone()));
    }

    check_images(inventory, probe, &mut blockers);

    let mut declared_volumes: BTreeSet<(String, String)> = BTreeSet::new();
    for target in &inventory.volumes {
        declared_volumes.insert((target.container.clone(), target.destination.clone()));
    }
    let discovery = discover(probe, inventory, &declared_volumes, &mut warnings);

    for target in &inventory.postgres {
        match probe
            .postgres
            .iter()
            .find(|facts| facts.container == target.container && facts.database == target.database)
        {
            None => blockers.push(finding(
                "postgres_target_missing",
                format!(
                    "声明的库 {}@{} 在探针结果里不存在（容器名、库名或权限不符）",
                    target.database, target.container
                ),
            )),
            Some(facts) => {
                let mut declared_tables: BTreeSet<&str> = BTreeSet::new();
                for (group, tables) in &target.groups {
                    for table in tables {
                        declared_tables.insert(table.as_str());
                        if !facts.tables.iter().any(|name| name == table) {
                            blockers.push(finding(
                                "declared_table_missing",
                                format!(
                                    "{}::{} 组 {group} 声明的表 `{table}` 在库中不存在",
                                    target.container, target.database
                                ),
                            ));
                        }
                    }
                }
                for dedup in &target.dedup {
                    let expected: BTreeSet<&str> =
                        dedup.columns.iter().map(String::as_str).collect();
                    let matched = facts.unique_indexes.iter().any(|index| {
                        index.table == dedup.table
                            && index.columns.len() == expected.len()
                            && index
                                .columns
                                .iter()
                                .all(|column| expected.contains(column.as_str()))
                    });
                    if !matched {
                        let seen = facts
                            .unique_indexes
                            .iter()
                            .filter(|index| index.table == dedup.table)
                            .map(|index| format!("{}（{}）", index.name, index.columns.join(",")))
                            .collect::<Vec<_>>();
                        blockers.push(finding(
                            "dedup_index_missing",
                            format!(
                                "去重声明「{}」要求 {}.{} 上有唯一索引 ({})，实际: {}",
                                dedup.purpose,
                                dedup.table,
                                target.container,
                                dedup.columns.join(","),
                                if seen.is_empty() {
                                    "该表没有任何唯一索引".to_string()
                                } else {
                                    seen.join("; ")
                                }
                            ),
                        ));
                    }
                }
                for table in &facts.unlogged {
                    if declared_tables.contains(table.as_str()) {
                        violations.push(finding(
                            "unlogged_declared_table",
                            format!(
                                "{}::{} 的关键表 `{table}` 是 UNLOGGED：崩溃后会被截断，不能作为权威状态",
                                target.container, target.database
                            ),
                        ));
                    } else {
                        warnings.push(finding(
                            "unlogged_table",
                            format!(
                                "{}::{} 有 UNLOGGED 表 `{table}`（范围外，仅提示）",
                                target.container, target.database
                            ),
                        ));
                    }
                }
                let missing_pk = facts
                    .without_primary_key
                    .iter()
                    .filter(|table| declared_tables.contains(table.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                if !missing_pk.is_empty() {
                    warnings.push(finding(
                        "declared_table_without_primary_key",
                        format!(
                            "{}::{} 的关键表没有主键（重放/去重只能靠唯一索引）：{}",
                            target.container,
                            target.database,
                            missing_pk.join(", ")
                        ),
                    ));
                }
                let (rpo, how) = postgres_rpo(target, facts);
                if facts.archive_mode != "on" {
                    warnings.push(finding(
                        "no_wal_archive",
                        format!(
                            "{}::{} 的 archive_mode={}：只能回到最近一次逻辑备份，无法做时间点恢复",
                            target.container, target.database, facts.archive_mode
                        ),
                    ));
                }
                surfaces.push(SurfaceReport {
                    kind: "postgres",
                    name: format!("{}::{}", target.container, target.database),
                    declared_disposition: Disposition::Authoritative,
                    effective_disposition: Disposition::Authoritative,
                    achievable_rpo_seconds: rpo,
                    detail: format!(
                        "{how}；{:.1} MiB，{} 表，{} 序列，{} 副本，扩展 {}",
                        facts.size_bytes as f64 / 1048576.0,
                        facts.tables.len(),
                        facts.sequences,
                        facts.replicas,
                        if facts.extensions.is_empty() {
                            "-".to_string()
                        } else {
                            facts.extensions.join(",")
                        }
                    ),
                });
            }
        }
    }

    for target in &inventory.redis {
        match probe
            .redis
            .iter()
            .find(|facts| facts.container == target.container)
        {
            None => blockers.push(finding(
                "redis_target_missing",
                format!("声明的 Redis 容器 {} 在探针结果里不存在", target.container),
            )),
            Some(facts) => {
                let persistent: u64 = facts
                    .databases
                    .iter()
                    .map(|db| db.keys.saturating_sub(db.expires))
                    .sum();
                let cache_supported = persistent <= target.cache_persistent_allowance;
                let mut effective = target.disposition;
                if target.disposition == Disposition::Derived && !cache_supported {
                    violations.push(finding(
                        "redis_cache_claim_refused",
                        format!(
                            "{} 被声明为可丢弃缓存，但有 {persistent} 个键没有 TTL（允许 {}）：\
                             这些键在丢失后无法重建，必须按权威状态计算 RPO",
                            target.container, target.cache_persistent_allowance
                        ),
                    ));
                    effective = Disposition::Authoritative;
                }
                for prefix in &target.required_prefixes {
                    let count = facts.prefix_counts.get(prefix).copied().unwrap_or(0);
                    if count == 0 {
                        violations.push(finding(
                            "redis_prefix_absent",
                            format!(
                                "声明 {} 以 `{prefix}` 前缀保存状态，但所有库里都没有该前缀的键：\
                                 「Redis 只存缓存」这个说法在这里不成立，也不应反过来假设",
                                target.container
                            ),
                        ));
                    }
                }
                // 防「解析失败看起来像空库」：报告了库却全为 0 键时不能当作已经核实过。
                if !facts.databases.is_empty() && facts.databases.iter().all(|db| db.keys == 0) {
                    warnings.push(finding(
                        "redis_all_databases_empty",
                        format!(
                            "{} 报告了 {} 个库但每个库都是 0 键：请确认探针确实连上了正确的实例",
                            target.container,
                            facts.databases.len()
                        ),
                    ));
                }
                let (rpo, how) = redis_rpo(target, facts);
                let rpo = if effective == Disposition::Derived {
                    Some(0)
                } else {
                    rpo
                };
                surfaces.push(SurfaceReport {
                    kind: "redis",
                    name: target.container.clone(),
                    declared_disposition: target.disposition,
                    effective_disposition: effective,
                    achievable_rpo_seconds: rpo,
                    detail: format!(
                        "{how}；v{}，AOF={}（{}），save={}，{} 副本；{} 个库，{persistent} 个无 TTL 键",
                        facts.version,
                        if facts.appendonly { "on" } else { "off" },
                        if facts.appendfsync.is_empty() { "-" } else { &facts.appendfsync },
                        if facts.save_rules.is_empty() { "-" } else { &facts.save_rules },
                        facts.replicas,
                        facts.databases.len()
                    ),
                });
            }
        }
    }

    for target in &inventory.volumes {
        match probe.mounts.iter().find(|mount| {
            mount.container == target.container && mount.destination == target.destination
        }) {
            None => blockers.push(finding(
                "volume_target_missing",
                format!(
                    "声明的目录 {}:{} 不是该容器的挂载点：应用写的文件可能在容器层，随容器删除而丢",
                    target.container, target.destination
                ),
            )),
            Some(mount) => {
                let rpo = if target.disposition == Disposition::Derived {
                    Some(0)
                } else {
                    target.backup.rpo_bound()
                };
                surfaces.push(SurfaceReport {
                    kind: "volume",
                    name: format!("{}:{}", target.container, target.destination),
                    declared_disposition: target.disposition,
                    effective_disposition: target.disposition,
                    achievable_rpo_seconds: rpo,
                    detail: format!(
                        "{}；{}；设备 {}",
                        if mount.read_only {
                            "只读挂载"
                        } else {
                            "可写挂载"
                        },
                        match mount.bytes {
                            Some(bytes) => format!("{:.1} MiB", bytes as f64 / 1048576.0),
                            None => "用量未知".to_string(),
                        },
                        mount.device.clone().unwrap_or_else(|| "-".into())
                    ),
                });
            }
        }
    }

    check_failure_domains(inventory, probe, &mut violations, &mut warnings);

    // 无上界的状态面会覆盖任何有限值：只要有一处 `None`，整体结论就是 `None`。
    let mut achievable: Option<u64> = Some(0);
    for surface in surfaces
        .iter()
        .filter(|surface| surface.effective_disposition == Disposition::Authoritative)
    {
        achievable = match (achievable, surface.achievable_rpo_seconds) {
            (Some(left), Some(right)) => Some(left.max(right)),
            _ => None,
        };
    }
    let mut rpo_supported = false;
    match inventory.rpo_seconds {
        None => blockers.push(finding(
            "rpo_not_declared",
            "没有声明 RPO 目标：在决定「允许丢多少写入」之前，这份清单不能支撑迁移方案",
        )),
        Some(0) => blockers.push(finding(
            "rpo_zero_unproven",
            "RPO 声明为 0（同步持久化），只读审核无法证明每次提交都已落盘；请给出可测量的目标",
        )),
        Some(declared) => {
            rpo_supported = achievable.is_some_and(|value| value <= declared);
            if !rpo_supported {
                violations.push(finding(
                    "rpo_claim_unachievable",
                    format!(
                        "声明 RPO {declared} 秒，但按现有事实最差的状态面是 {}",
                        match achievable {
                            Some(value) => format!("{value} 秒"),
                            None => "没有任何上界（人工备份或完全没有备份）".to_string(),
                        }
                    ),
                ));
            }
        }
    }

    match inventory.rto_rehearsal {
        Rehearsal::None => blockers.push(finding(
            "rto_unrehearsed",
            format!(
                "声明 RTO {} 秒但没有记录任何恢复演练：未演练的 RTO 只是愿望",
                inventory.rto_seconds
            ),
        )),
        Rehearsal::DataLayer => warnings.push(finding(
            "rto_scope_data_layer",
            format!(
                "RTO {} 秒只对数据层成立（备份/恢复/切回）；入口切换、长连接与客户端重连未计入",
                inventory.rto_seconds
            ),
        )),
        Rehearsal::FullStack => violations.push(finding(
            "rto_full_stack_unproven",
            "声称整套栈的 RTO 已演练；只读审核没有切换入口、没有中断长连接，不能确认",
        )),
    }

    Report {
        schema: SCHEMA,
        scope: "read-only-application-state-audit",
        read_only: true,
        application: inventory.application.clone(),
        version: inventory.version.clone(),
        collected_at_unix: probe.collected_at_unix,
        declared_rpo_seconds: inventory.rpo_seconds,
        declared_rto_seconds: inventory.rto_seconds,
        rto_rehearsal: inventory.rto_rehearsal,
        achievable_rpo_seconds: achievable,
        rpo_claim_supported: rpo_supported,
        surfaces,
        discovery,
        migration_plan_approved: blockers.is_empty() && violations.is_empty(),
        violations,
        blockers,
        warnings,
    }
}

/// 版本固定：至少要有一条带 `@sha256:` 的镜像，且它必须与主机上实际镜像一致。
fn check_images(inventory: &Inventory, probe: &Probe, blockers: &mut Vec<Finding>) {
    let digests = inventory
        .images
        .iter()
        .filter_map(|image| image.split_once('@').map(|(_, digest)| digest))
        .filter(|digest| digest.starts_with("sha256:") && digest.len() == 71)
        .collect::<Vec<_>>();
    if digests.is_empty() {
        blockers.push(finding(
            "image_not_pinned",
            "没有任何镜像带 `@sha256:` 摘要：tag 可以移动，审核结论绑定不到具体版本",
        ));
        return;
    }
    for (position, image) in inventory.images.iter().enumerate() {
        let observed = probe.discovered.iter().any(|container| {
            container.image == *image
                || image
                    .split_once('@')
                    .is_some_and(|(_, digest)| container.image_id == digest)
        });
        if !observed {
            blockers.push(finding(
                "image_not_observed",
                format!(
                    "第 {} 条镜像 {image} 没有出现在主机的运行容器里（{} 个容器已扫描）",
                    position + 1,
                    probe.discovered.len()
                ),
            ));
        }
    }
}

fn discover(
    probe: &Probe,
    inventory: &Inventory,
    declared_volumes: &BTreeSet<(String, String)>,
    warnings: &mut Vec<Finding>,
) -> DiscoveryReport {
    let declared_containers = inventory
        .postgres
        .iter()
        .map(|target| target.container.as_str())
        .chain(
            inventory
                .redis
                .iter()
                .map(|target| target.container.as_str()),
        )
        .chain(
            inventory
                .volumes
                .iter()
                .map(|target| target.container.as_str()),
        )
        .collect::<BTreeSet<_>>();
    let database_containers = probe
        .discovered
        .iter()
        .filter(|container| !container.engine.is_empty())
        .map(|container| format!("{}（{}）", container.name, container.engine))
        .collect::<Vec<_>>();
    let undeclared = probe
        .discovered
        .iter()
        .filter(|container| {
            !container.engine.is_empty() && !declared_containers.contains(container.name.as_str())
        })
        .map(|container| format!("{}（{}）", container.name, container.engine))
        .collect::<Vec<_>>();
    if !undeclared.is_empty() {
        warnings.push(finding(
            "undeclared_database_containers",
            format!(
                "主机上还有 {} 个未声明的数据库容器，它们的状态不在本次审核范围内：{}",
                undeclared.len(),
                undeclared
                    .iter()
                    .take(MAX_LISTED)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    // 逐 (容器, 容器内路径) 比对：只要该容器声明过一个目录就豁免它的全部挂载，
    // 会让同一容器里第二个可写目录（例如插件缓存）被静默当成「已在范围内」。
    let mut outside = Vec::new();
    for container in &probe.discovered {
        for bind in &container.writable_binds {
            let declared =
                declared_volumes.contains(&(container.name.clone(), bind.destination.clone()));
            let label = format!("{}:{}", container.name, bind.destination);
            if !declared && !outside.contains(&label) {
                outside.push(label);
            }
        }
    }
    let total = outside.len();
    if total > 0 {
        warnings.push(finding(
            "writable_binds_outside_scope",
            format!(
                "主机上有 {total} 个可写目录挂载在本次声明的状态面之外；它们不是本应用的约定，但不能被当作不存在"
            ),
        ));
    }
    outside.truncate(MAX_LISTED);
    DiscoveryReport {
        containers: probe.discovered.len(),
        database_containers,
        undeclared_database_containers: undeclared,
        writable_binds_outside_scope: outside,
        writable_binds_outside_scope_total: total,
    }
}

/// 同一块盘就是同一个故障域。宣称独立却没有第二个设备号，直接拒绝。
fn check_failure_domains(
    inventory: &Inventory,
    probe: &Probe,
    violations: &mut Vec<Finding>,
    warnings: &mut Vec<Finding>,
) {
    let devices = probe
        .mounts
        .iter()
        .filter_map(|mount| mount.device.clone())
        .collect::<BTreeSet<_>>();
    if devices.is_empty() {
        warnings.push(finding(
            "failure_domain_unknown",
            "探针没有取到任何设备号，无法判断状态面是否落在不同物理故障域",
        ));
        return;
    }
    if inventory.failure_domains.claim_independent && devices.len() == 1 {
        violations.push(finding(
            "failure_domain_claim_refused",
            format!(
                "声明状态面分布在不同故障域，但所有数据目录都在同一个设备（{}）：\
                 这块盘丢失会同时带走数据库、缓存与应用文件",
                devices.iter().next().cloned().unwrap_or_default()
            ),
        ));
    }
}

fn postgres_rpo(target: &PostgresTarget, facts: &PostgresFacts) -> (Option<u64>, String) {
    if facts.replicas > 0 {
        return (
            Some(0),
            format!("{} 个流复制副本，提交即被复制", facts.replicas),
        );
    }
    if facts.archive_mode == "on" {
        let window = if facts.archive_timeout_seconds == 0 {
            ARCHIVE_TIMEOUT_FALLBACK_SECONDS
        } else {
            facts.archive_timeout_seconds
        };
        let how = if facts.archive_timeout_seconds == 0 {
            format!("WAL 归档开启但 archive_timeout=0，按 {window} 秒的段切换上界估算")
        } else {
            format!("WAL 归档开启，archive_timeout={window} 秒")
        };
        return (Some(window), how);
    }
    let bound = target.backup.rpo_bound();
    let how = match bound {
        Some(seconds) => format!(
            "archive_mode={}，只能回到最近一次逻辑备份（间隔 ≤ {seconds} 秒）",
            facts.archive_mode
        ),
        None => format!(
            "archive_mode={} 且{}：没有 WAL 归档又没有定时备份，丢多少取决于上次备份",
            facts.archive_mode,
            target.backup.describe()
        ),
    };
    (bound, how)
}

fn redis_rpo(target: &RedisTarget, facts: &RedisFacts) -> (Option<u64>, String) {
    if facts.replicas > 0 {
        return (Some(0), format!("{} 个副本", facts.replicas));
    }
    if !facts.appendonly {
        let bound = target.backup.rpo_bound();
        let how = match bound {
            Some(seconds) => format!("AOF 关闭，只能回到最近一次快照（间隔 ≤ {seconds} 秒）"),
            None => format!(
                "AOF 关闭且{}：只能回到上一次快照，时刻不可预期",
                target.backup.describe()
            ),
        };
        return (bound, how);
    }
    match facts.appendfsync.as_str() {
        "always" => (Some(0), "AOF + appendfsync=always（每条命令落盘）".into()),
        "everysec" => (Some(1), "AOF + appendfsync=everysec（最多丢 1 秒）".into()),
        "no" => (
            Some(30),
            "AOF + appendfsync=no（由内核决定刷盘，按 30 秒上界估算）".into(),
        ),
        other => (
            target.backup.rpo_bound(),
            format!("AOF 开启但 appendfsync={other} 未知，退回备份节奏"),
        ),
    }
}

/// 探针规格：只传容器名、库名与要统计的前缀，不传口令。
#[derive(Serialize)]
struct ProbeSpec<'a> {
    postgres: Vec<ProbePg<'a>>,
    redis: Vec<ProbeRedis<'a>>,
    volumes: Vec<ProbeVolume<'a>>,
}

#[derive(Serialize)]
struct ProbePg<'a> {
    container: &'a str,
    database: &'a str,
    user: &'a str,
}

#[derive(Serialize)]
struct ProbeRedis<'a> {
    container: &'a str,
    prefixes: &'a [String],
}

#[derive(Serialize)]
struct ProbeVolume<'a> {
    container: &'a str,
    destination: &'a str,
}

/// 通过已有 OpenSSH 跑只读探针；不创建 Node、不改远端配置、不执行写语句。
pub async fn probe(inventory: &Inventory, ssh: &str, ssh_config: Option<&Path>) -> Result<Probe> {
    validate(inventory)?;
    let node = Node {
        name: "state-audit".into(),
        ssh: ssh.into(),
        images: Vec::new(),
        ssh_config: ssh_config.map(Path::to_path_buf),
        enabled: false,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
    };
    crate::config::validate_node(&node)?;
    let spec = ProbeSpec {
        postgres: inventory
            .postgres
            .iter()
            .map(|target| ProbePg {
                container: &target.container,
                database: &target.database,
                user: &target.user,
            })
            .collect(),
        redis: inventory
            .redis
            .iter()
            .map(|target| ProbeRedis {
                container: &target.container,
                prefixes: &target.required_prefixes,
            })
            .collect(),
        volumes: inventory
            .volumes
            .iter()
            .map(|target| ProbeVolume {
                container: &target.container,
                destination: &target.destination,
            })
            .collect(),
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&spec)?);
    let script = format!(
        "export SSHPOOL_STATE_AUDIT_SPEC={}\n{}",
        transport::quote(&encoded),
        PROBE_SCRIPT
    );
    let output = transport::checked(&node, &script, 240).await?;
    let probe: Probe = serde_json::from_slice(&output)
        .context("状态探针返回了不完整或未知格式（协议 1 的 JSON）")?;
    ensure!(
        probe.schema == SCHEMA,
        "probe returned an unsupported schema"
    );
    Ok(probe)
}

/// 远端只读探针：只用 `docker inspect/exec` 与 `stat/du` 观察，不写任何东西。
///
/// 口令只从容器自己的命令行里取（它本来就在那里），用完即弃，绝不进入输出。
const PROBE_SCRIPT: &str = r#"python3 - <<'PY'
import base64, hashlib, json, os, subprocess, time

def run(argv, timeout=120):
    try:
        done = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        return done.returncode, done.stdout, done.stderr.strip()
    except Exception as exc:
        return 1, '', type(exc).__name__

def docker_json(template, name):
    code, out, err = run(['docker', 'inspect', '-f', template, name], 30)
    if code != 0:
        return None, err or 'docker inspect failed'
    try:
        return json.loads(out), ''
    except Exception:
        return None, 'docker inspect returned unparsable JSON'

ENGINES = {
    'postgres': 'postgres', 'postgresql': 'postgres', 'pgvector': 'postgres',
    'redis': 'redis', 'valkey': 'redis',
    'mysql': 'mysql', 'mariadb': 'mysql',
    'mongo': 'mongo', 'mongodb': 'mongo',
    'memcached': 'memcached', 'minio': 'minio',
    'clickhouse': 'clickhouse', 'clickhouse-server': 'clickhouse',
    'elasticsearch': 'elasticsearch', 'cassandra': 'cassandra',
    'neo4j': 'neo4j', 'influxdb': 'influxdb',
}

def engine_of(image):
    repo = image.split('@')[0]
    last = repo.rsplit('/', 1)[-1]
    return ENGINES.get(last.split(':')[0], '')

spec = json.loads(base64.b64decode(os.environ['SSHPOOL_STATE_AUDIT_SPEC']).decode())
errors = []
probe = {'schema': 1, 'collected_at_unix': int(time.time()),
         'discovered': [], 'postgres': [], 'redis': [], 'mounts': [], 'errors': errors}

names = []
code, out, err = run(['docker', 'ps', '--format', '{{.Names}}'], 30)
if code != 0:
    errors.append('docker ps failed: ' + (err or 'nonzero exit'))
else:
    names = [line.strip() for line in out.splitlines() if line.strip()]

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]

def writable_binds(mounts):
    # 只带回容器内路径与宿主路径摘要：宿主绝对路径不进入报告与证据文件。
    return [{'destination': m.get('Destination', ''), 'source_digest': digest(m.get('Source', ''))}
            for m in mounts
            if m.get('RW') and m.get('Type') == 'bind' and m.get('Source')]

def mount_device(mount):
    if mount.get('Type') == 'bind':
        return mount.get('Source', '')
    if mount.get('Type') == 'volume':
        code, out, _ = run(['docker', 'volume', 'inspect', '-f', '{{.Mountpoint}}', mount.get('Name', '')], 20)
        return out.strip() if code == 0 else ''
    return ''

for name in names:
    info, problem = docker_json(
        '{"image":{{json .Config.Image}},"id":{{json .Image}},"mounts":{{json .Mounts}},'
        '"cmd":{{json .Config.Cmd}}}', name)
    if info is None:
        errors.append(name + ': ' + problem)
        continue
    probe['discovered'].append({
        'name': name,
        'image': info.get('image') or '',
        'image_id': info.get('id') or '',
        'engine': engine_of(info.get('image') or ''),
        'writable_binds': writable_binds(info.get('mounts') or []),
    })

def device_of(path):
    code, out, _ = run(['stat', '-c', '%d', path], 15)
    return out.strip() if code == 0 and out.strip() else None

def bytes_of(path):
    code, out, _ = run(['du', '-sb', path], 120)
    if code != 0 or not out.split():
        return None
    try:
        return int(out.split()[0])
    except ValueError:
        return None

PG_SQL = """
select 'meta','version',current_setting('server_version'),'' 
union all select 'meta','archive_mode',current_setting('archive_mode'),''
union all select 'meta','wal_level',current_setting('wal_level'),''
union all select 'meta','archive_timeout',current_setting('archive_timeout'),''
union all select 'meta','replicas',(select count(*)::text from pg_stat_replication),''
union all select 'meta','size_bytes',pg_database_size(current_database())::text,''
union all select 'meta','sequences',(select count(*)::text from information_schema.sequences
  where sequence_schema not in ('pg_catalog','information_schema')),''
union all select 'meta','extensions',coalesce((select string_agg(extname,',' order by extname)
  from pg_extension),'-'),''
union all select 'table',c.relname,case when c.relpersistence='u' then 'unlogged' else 'logged' end,''
  from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where c.relkind='r' and n.nspname not in ('pg_catalog','information_schema')
union all select 'unique',c.relname||'.'||i.relname,string_agg(a.attname,',' order by k.ord),
  case when x.indisprimary then 'p' else 'u' end
  from pg_index x join pg_class c on c.oid=x.indrelid
  join pg_namespace n on n.oid=c.relnamespace join pg_class i on i.oid=x.indexrelid
  join unnest(x.indkey::smallint[]) with ordinality k(attnum,ord) on true
  join pg_attribute a on a.attrelid=c.oid and a.attnum=k.attnum
  where x.indisunique and n.nspname not in ('pg_catalog','information_schema')
  group by 1,2,4
order by 1,2
"""

for target in spec.get('postgres', []):
    container = target['container']
    args = ['docker', 'exec', container, 'psql',
            '-U', target['user'], '-d', target['database'],
            '-X', '-q', '-t', '-A', '-F', '\x1f', '-v', 'ON_ERROR_STOP=1',
            '-c', PG_SQL]
    code, out, err = run(args, 120)
    if code != 0:
        errors.append('postgres %s: %s' % (container, (err or out).strip()[:400]))
        continue
    facts = {'container': container, 'database': target['database'],
             'server_version': '', 'archive_mode': 'unknown', 'wal_level': '',
             'archive_timeout_seconds': 0, 'replicas': 0, 'size_bytes': 0,
             'sequences': 0, 'tables': [], 'unlogged': [],
             'without_primary_key': [], 'extensions': [], 'unique_indexes': []}
    primary = set()
    for line in out.splitlines():
        fields = line.split('\x1f')
        if len(fields) < 4:
            continue
        kind, key, value, extra = fields[0], fields[1], fields[2], fields[3]
        if kind == 'meta':
            if key == 'version':
                facts['server_version'] = value
            elif key == 'archive_mode':
                facts['archive_mode'] = value
            elif key == 'wal_level':
                facts['wal_level'] = value
            elif key == 'archive_timeout':
                try:
                    facts['archive_timeout_seconds'] = int(value.split()[0])
                except (ValueError, IndexError):
                    facts['archive_timeout_seconds'] = 0
            elif key == 'replicas':
                facts['replicas'] = int(value)
            elif key == 'size_bytes':
                facts['size_bytes'] = int(value)
            elif key == 'sequences':
                facts['sequences'] = int(value)
            elif key == 'extensions':
                facts['extensions'] = [] if value in ('', '-') else value.split(',')
        elif kind == 'table':
            facts['tables'].append(key)
            if value == 'unlogged':
                facts['unlogged'].append(key)
        elif kind == 'unique':
            table, _, index = key.rpartition('.')
            columns = [c for c in value.split(',') if c] if value else []
            facts['unique_indexes'].append({'table': table, 'name': index,
                                            'columns': columns,
                                            'primary': extra == 'p'})
            if extra == 'p':
                primary.add(table)
    facts['without_primary_key'] = sorted(t for t in facts['tables'] if t not in primary)
    if len(facts['tables']) > 5000:
        errors.append('postgres %s: table list exceeds 5000 entries' % container)
    probe['postgres'].append(facts)

PREFIX_LUA = """
local db = ARGV[1]
redis.call('SELECT', db)
local out = {}
for i = 2, #ARGV do
  local cursor = '0'
  local rounds = 0
  local hits = 0
  repeat
    local reply = redis.call('SCAN', cursor, 'MATCH', ARGV[i] .. '*', 'COUNT', 500)
    cursor = reply[1]
    hits = hits + #reply[2]
    rounds = rounds + 1
  until cursor == '0' or rounds >= 40 or hits > 100000
  out[#out + 1] = ARGV[i] .. '=' .. hits
end
return table.concat(out, ',')
"""

def keyspace(text):
    # `db0:keys=9129,expires=4809,avg_ttl=...`：键数在 `keys=` 之后不带名字，必须单独取，
    # 否则 `dict(split('='))` 会把它当成「没有等号所以忽略」，把 9000 多个键读成 0。
    dbs = []
    for line in text.splitlines():
        if not (line.startswith('db') and ':keys=' in line):
            continue
        head, _, tail = line.partition(':keys=')
        first, _, rest = tail.partition(',')
        fields = dict(p.split('=', 1) for p in rest.split(',') if '=' in p)
        try:
            keys = int(first)
            expires = int(fields.get('expires', 0))
        except ValueError:
            errors.append('redis keyspace line is unparsable: ' + line[:120])
            continue
        if expires > keys:
            errors.append('redis keyspace reports more expiring keys than keys: ' + line[:120])
        dbs.append({'index': int(head[2:]), 'keys': keys, 'expires': expires})
    return sorted(dbs, key=lambda item: item['index'])

for target in spec.get('redis', []):
    container = target['container']
    info, problem = docker_json('{{json .Config.Cmd}}', container)
    if info is None:
        errors.append('redis %s: %s' % (container, problem))
        continue
    password = ''
    if isinstance(info, list) and '--requirepass' in info:
        at = info.index('--requirepass')
        if at + 1 < len(info):
            password = info[at + 1]
    base = ['docker', 'exec', container, 'redis-cli', '--no-auth-warning']
    if password:
        base += ['-a', password]
    code, out, err = run(base + ['info'], 60)
    if code != 0:
        errors.append('redis %s: %s' % (container, (err or out).strip()[:400]))
        continue
    facts = {'container': container, 'version': '', 'appendonly': False,
             'appendfsync': '', 'save_rules': '', 'replicas': 0,
             'databases': [], 'prefix_counts': {}}
    section = ''
    for line in out.splitlines():
        if line.startswith('#'):
            section = line.strip('# ').strip()
            continue
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        if section == 'Server' and key == 'redis_version':
            facts['version'] = value.strip()
        elif section == 'Persistence':
            if key == 'aof_enabled':
                facts['appendonly'] = value.strip() == '1'
            elif key == 'aof_current_size' or key == 'loading':
                pass
        elif section == 'Replication' and key == 'connected_slaves':
            facts['replicas'] = int(value.strip() or 0)
        elif section == 'Keyspace':
            facts['databases'] = keyspace(out)
    code, out, err = run(base + ['config', 'get', 'appendonly', 'appendfsync', 'save'], 60)
    if code != 0:
        errors.append('redis %s config: %s' % (container, (err or out).strip()[:400]))
    else:
        words = out.splitlines()
        for at in range(0, len(words) - 1, 2):
            key, value = words[at].strip(), words[at + 1].strip()
            if key == 'appendonly':
                facts['appendonly'] = value == 'yes'
            elif key == 'appendfsync':
                facts['appendfsync'] = value
            elif key == 'save':
                facts['save_rules'] = value
    prefixes = [p for p in target.get('prefixes', []) if p]
    if prefixes and facts['databases']:
        counts = {}
        for db in facts['databases']:
            code, out, err = run(base + ['eval', PREFIX_LUA, '0', str(db['index'])] + prefixes, 120)
            if code != 0:
                errors.append('redis %s prefixes: %s' % (container, (err or out).strip()[:400]))
                continue
            for pair in out.strip().split(','):
                if '=' in pair:
                    name, _, number = pair.partition('=')
                    counts[name] = counts.get(name, 0) + int(number or 0)
        facts['prefix_counts'] = counts
    probe['redis'].append(facts)

def resolve_mountpoint(mount):
    if mount.get('Type') == 'bind':
        return mount.get('Source', '')
    if mount.get('Type') == 'volume':
        code, out, _ = run(['docker', 'volume', 'inspect', '-f', '{{.Mountpoint}}', mount.get('Name', '')], 20)
        return out.strip() if code == 0 else ''
    return ''

def record_mount(container, role, destination, mount):
    path = resolve_mountpoint(mount)
    probe['mounts'].append({
        'container': container,
        'role': role,
        'destination': destination,
        'read_only': not mount.get('RW', True),
        'bytes': bytes_of(path) if path else None,
        'device': device_of(path) if path else None,
    })

def mounts_of(name):
    info, problem = docker_json('{{json .Mounts}}', name)
    return info or [], problem

for target in spec.get('volumes', []):
    container = target['container']
    mounts, problem = mounts_of(container)
    hit = next((m for m in mounts if m.get('Destination') == target['destination']), None)
    if hit is None:
        continue
    record_mount(container, 'volume', target['destination'], hit)
    if problem:
        errors.append('volume %s: %s' % (container, problem))

engine_containers = set()
for target in spec.get('postgres', []):
    engine_containers.add(target['container'])
for target in spec.get('redis', []):
    engine_containers.add(target['container'])
for container in sorted(engine_containers):
    mounts, problem = mounts_of(container)
    if problem:
        errors.append('engine mounts %s: %s' % (container, problem))
        continue
    for mount in mounts:
        if mount.get('RW') and mount.get('Destination'):
            record_mount(container, 'engine-data', mount.get('Destination'), mount)

print(json.dumps(probe, sort_keys=True))
PY"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inventory() -> Inventory {
        Inventory {
            schema: SCHEMA,
            application: "demo".into(),
            version: "v1".into(),
            images: vec![
                "demo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            ],
            rpo_seconds: Some(3600),
            rto_seconds: 1800,
            rto_rehearsal: Rehearsal::DataLayer,
            postgres: vec![PostgresTarget {
                container: "pg".into(),
                database: "app".into(),
                user: "app".into(),
                backup: Backup::Scheduled {
                    interval_seconds: 600,
                },
                groups: BTreeMap::from([("billing".to_string(), vec!["charge".to_string()])]),
                dedup: vec![Dedup {
                    purpose: "retry must not double charge".into(),
                    table: "charge".into(),
                    columns: vec!["request_id".into(), "api_key_id".into()],
                }],
            }],
            redis: vec![RedisTarget {
                container: "cache".into(),
                disposition: Disposition::Derived,
                backup: Backup::Scheduled {
                    interval_seconds: 600,
                },
                required_prefixes: vec!["sched:".into()],
                cache_persistent_allowance: 0,
            }],
            volumes: vec![VolumeTarget {
                container: "app".into(),
                destination: "/app/data".into(),
                disposition: Disposition::Authoritative,
                backup: Backup::Scheduled {
                    interval_seconds: 600,
                },
            }],
            failure_domains: FailureDomains {
                claim_independent: false,
            },
        }
    }

    fn fixture_probe() -> Probe {
        Probe {
            schema: SCHEMA,
            collected_at_unix: 1_800_000_000,
            discovered: vec![
                Discovered {
                    name: "pg".into(),
                    image: "postgres:16-alpine".into(),
                    image_id: "sha256:1".into(),
                    engine: "postgres".into(),
                    writable_binds: Vec::new(),
                },
                Discovered {
                    name: "app".into(),
                    image: "demo/app:latest".into(),
                    image_id:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into(),
                    engine: String::new(),
                    // 与声明的卷一致：容器自己的可写目录必须能被认出来，不算「范围外」。
                    writable_binds: vec![WritableBind {
                        destination: "/app/data".into(),
                        source_digest: "0123456789abcdef".into(),
                    }],
                },
            ],
            postgres: vec![PostgresFacts {
                container: "pg".into(),
                database: "app".into(),
                server_version: "16.4".into(),
                archive_mode: "off".into(),
                wal_level: "replica".into(),
                archive_timeout_seconds: 0,
                replicas: 0,
                size_bytes: 1024,
                sequences: 1,
                tables: vec!["charge".into()],
                unlogged: Vec::new(),
                without_primary_key: Vec::new(),
                extensions: vec!["plpgsql".into()],
                unique_indexes: vec![UniqueIndex {
                    table: "charge".into(),
                    name: "charge_request".into(),
                    columns: vec!["api_key_id".into(), "request_id".into()],
                    primary: false,
                }],
            }],
            redis: vec![RedisFacts {
                container: "cache".into(),
                version: "8.0".into(),
                appendonly: true,
                appendfsync: "everysec".into(),
                save_rules: "3600 1".into(),
                replicas: 0,
                databases: vec![RedisDb {
                    index: 0,
                    keys: 10,
                    expires: 10,
                }],
                prefix_counts: BTreeMap::from([("sched:".to_string(), 4)]),
            }],
            mounts: vec![
                MountFacts {
                    container: "app".into(),
                    role: "volume".into(),
                    destination: "/app/data".into(),
                    read_only: false,
                    bytes: Some(2048),
                    device: Some("2049".into()),
                },
                MountFacts {
                    container: "pg".into(),
                    role: "engine-data".into(),
                    destination: "/var/lib/postgresql/data".into(),
                    read_only: false,
                    bytes: Some(8192),
                    device: Some("2049".into()),
                },
            ],
            errors: Vec::new(),
        }
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|item| item.code.as_str()).collect()
    }

    #[test]
    fn a_consistent_inventory_is_approved_with_the_declared_scope() {
        let report = assess(&fixture_inventory(), &fixture_probe());
        assert!(report.blockers.is_empty(), "{:?}", report.blockers);
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert!(report.migration_plan_approved);
        assert!(report.read_only);
        assert_eq!(report.achievable_rpo_seconds, Some(600));
        assert!(report.rpo_claim_supported);
        assert_eq!(report.surfaces.len(), 3);
    }

    #[test]
    fn a_declared_table_that_does_not_exist_invalidates_the_audit() {
        let mut inventory = fixture_inventory();
        inventory.postgres[0]
            .groups
            .insert("sessions".into(), vec!["session".into()]);
        let report = assess(&inventory, &fixture_probe());
        assert!(!report.migration_plan_approved);
        assert_eq!(codes(&report.blockers), vec!["declared_table_missing"]);
    }

    #[test]
    fn a_dedup_claim_without_a_matching_unique_index_is_refused() {
        let mut probe = fixture_probe();
        probe.postgres[0].unique_indexes[0].columns = vec!["request_id".into()];
        let report = assess(&fixture_inventory(), &probe);
        assert_eq!(codes(&report.blockers), vec!["dedup_index_missing"]);
        assert!(!report.migration_plan_approved);
    }

    #[test]
    fn redis_is_not_assumed_to_be_disposable_cache() {
        let mut probe = fixture_probe();
        probe.redis[0].databases = vec![RedisDb {
            index: 7,
            keys: 28,
            expires: 1,
        }];
        let report = assess(&fixture_inventory(), &probe);
        let codes = codes(&report.violations);
        assert!(codes.contains(&"redis_cache_claim_refused"), "{codes:?}");
        let redis = report
            .surfaces
            .iter()
            .find(|surface| surface.kind == "redis")
            .unwrap();
        assert_eq!(redis.effective_disposition, Disposition::Authoritative);
        assert!(redis.achievable_rpo_seconds.is_some_and(|value| value > 0));
        assert!(!report.migration_plan_approved);
    }

    #[test]
    fn required_prefix_absent_means_the_declaration_is_wrong() {
        let mut probe = fixture_probe();
        probe.redis[0].prefix_counts.clear();
        let report = assess(&fixture_inventory(), &probe);
        assert!(codes(&report.violations).contains(&"redis_prefix_absent"));
    }

    #[test]
    fn an_rpo_smaller_than_the_backup_interval_is_refused() {
        let mut inventory = fixture_inventory();
        inventory.rpo_seconds = Some(60);
        let report = assess(&inventory, &fixture_probe());
        assert_eq!(codes(&report.violations), vec!["rpo_claim_unachievable"]);
        assert_eq!(report.achievable_rpo_seconds, Some(600));
        assert!(!report.rpo_claim_supported);
    }

    #[test]
    fn a_manual_backup_has_no_rpo_bound_at_all() {
        let mut inventory = fixture_inventory();
        inventory.postgres[0].backup = Backup::Manual;
        let report = assess(&inventory, &fixture_probe());
        assert_eq!(report.achievable_rpo_seconds, None);
        assert_eq!(codes(&report.violations), vec!["rpo_claim_unachievable"]);
        let pg = report
            .surfaces
            .iter()
            .find(|surface| surface.kind == "postgres")
            .unwrap();
        assert!(pg.detail.contains("人工备份"), "{}", pg.detail);
    }

    #[test]
    fn an_undeclared_rpo_is_a_blocker_not_a_default() {
        let mut inventory = fixture_inventory();
        inventory.rpo_seconds = None;
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.blockers).contains(&"rpo_not_declared"));
        assert!(!report.rpo_claim_supported);
        assert!(!report.migration_plan_approved);
    }

    #[test]
    fn a_derived_volume_is_not_counted_in_the_achievable_rpo() {
        let mut inventory = fixture_inventory();
        inventory.volumes[0].backup = Backup::Manual;
        inventory.volumes[0].disposition = Disposition::Derived;
        let report = assess(&inventory, &fixture_probe());
        assert_eq!(report.achievable_rpo_seconds, Some(600));
    }

    #[test]
    fn wal_archive_and_replicas_improve_the_achievable_rpo() {
        let mut probe = fixture_probe();
        probe.postgres[0].replicas = 1;
        let report = assess(&fixture_inventory(), &probe);
        let pg = report
            .surfaces
            .iter()
            .find(|surface| surface.kind == "postgres")
            .unwrap();
        assert_eq!(pg.achievable_rpo_seconds, Some(0));
        probe.postgres[0].replicas = 0;
        probe.postgres[0].archive_mode = "on".into();
        probe.postgres[0].archive_timeout_seconds = 60;
        let report = assess(&fixture_inventory(), &probe);
        let pg = report
            .surfaces
            .iter()
            .find(|surface| surface.kind == "postgres")
            .unwrap();
        assert_eq!(pg.achievable_rpo_seconds, Some(60));
    }

    #[test]
    fn same_device_cannot_be_claimed_as_independent_failure_domains() {
        let mut inventory = fixture_inventory();
        inventory.failure_domains.claim_independent = true;
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.violations).contains(&"failure_domain_claim_refused"));
        probe_two_devices_refute_nothing();
    }

    fn probe_two_devices_refute_nothing() {
        let mut probe = fixture_probe();
        probe.mounts[1].device = Some("2050".into());
        let mut inventory = fixture_inventory();
        inventory.failure_domains.claim_independent = true;
        let report = assess(&inventory, &probe);
        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn an_unrehearsed_rto_is_only_a_wish() {
        let mut inventory = fixture_inventory();
        inventory.rto_rehearsal = Rehearsal::None;
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.blockers).contains(&"rto_unrehearsed"));
        inventory.rto_rehearsal = Rehearsal::FullStack;
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.violations).contains(&"rto_full_stack_unproven"));
    }

    #[test]
    fn a_zero_rpo_needs_synchronous_proof() {
        let mut inventory = fixture_inventory();
        inventory.rpo_seconds = Some(0);
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.blockers).contains(&"rpo_zero_unproven"));
    }

    #[test]
    fn a_mutable_tag_or_an_unobserved_image_blocks_the_audit() {
        let mut inventory = fixture_inventory();
        inventory.images = vec!["demo/app:latest".into()];
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.blockers).contains(&"image_not_pinned"));
        inventory.images = vec![
            "demo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
        ];
        let report = assess(&inventory, &fixture_probe());
        assert!(codes(&report.blockers).contains(&"image_not_observed"));
    }

    #[test]
    fn unlogged_critical_tables_and_undeclared_engines_are_reported() {
        let mut probe = fixture_probe();
        probe.postgres[0].unlogged = vec!["charge".into()];
        probe.discovered.push(Discovered {
            name: "other-db".into(),
            image: "redis:8-alpine".into(),
            image_id: "sha256:2".into(),
            engine: "redis".into(),
            writable_binds: Vec::new(),
        });
        let report = assess(&fixture_inventory(), &probe);
        assert!(codes(&report.violations).contains(&"unlogged_declared_table"));
        assert!(
            codes(&report.warnings).contains(&"undeclared_database_containers"),
            "{:?}",
            report.warnings
        );
        assert_eq!(report.discovery.undeclared_database_containers.len(), 1);
    }

    #[test]
    fn a_second_writable_directory_in_a_declared_container_is_still_outside_scope() {
        let mut probe = fixture_probe();
        probe.discovered[1].writable_binds.push(WritableBind {
            destination: "/var/lib/plugin-cache".into(),
            source_digest: "fedcba9876543210".into(),
        });
        let report = assess(&fixture_inventory(), &probe);
        assert_eq!(report.discovery.writable_binds_outside_scope_total, 1);
        assert_eq!(
            report.discovery.writable_binds_outside_scope,
            vec!["app:/var/lib/plugin-cache"]
        );
        assert!(
            codes(&report.warnings).contains(&"writable_binds_outside_scope"),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn a_probe_error_invalidates_the_whole_report() {
        let mut probe = fixture_probe();
        probe.errors.push("postgres pg: permission denied".into());
        let report = assess(&fixture_inventory(), &probe);
        assert!(codes(&report.blockers).contains(&"probe_failed"));
        assert!(!report.migration_plan_approved);
    }

    #[test]
    fn inventory_rejects_shell_syntax_and_unknown_fields() {
        let mut broken = fixture_inventory();
        broken.postgres[0].container = "pg; rm -rf /".into();
        assert!(validate(&broken).is_err());
        broken.postgres[0].container = "pg".into();
        broken.volumes[0].destination = "/app/../etc".into();
        assert!(validate(&broken).is_err());
        broken.volumes[0].destination = "/app/data".into();
        assert!(validate(&broken).is_ok());
        let text = serde_json::to_string(&fixture_inventory())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":1,\"surprise\":true");
        assert!(serde_json::from_str::<Inventory>(&text).is_err());
    }
}
