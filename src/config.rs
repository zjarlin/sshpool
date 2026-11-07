use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// 控制面配置；本地文件保存节点地址，公开仓库只提交示例。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api_listen: SocketAddr,
    pub ssh_listen: SocketAddr,
    pub ssh_backend: SocketAddr,
    pub max_upload_mib: u64,
    pub max_log_mib: u64,
    pub max_artifact_mib: u64,
    pub min_free_disk_mib: u64,
    pub max_active_jobs: usize,
    /// 包括本地权威状态在内、必须成功的独立故障域数；零仅用于没有副本配置的本地开发。
    #[serde(default)]
    pub replica_min_ack: usize,
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub replicas: Vec<Replica>,
    /// Prometheus 抓取端点；不设置时不监听。它是独立端口，不写入访问审计，
    /// 但要求根 token 才能抓取。
    #[serde(default)]
    pub metrics_listen: Option<SocketAddr>,
    /// 是否允许指标端点绑定非回环地址。指标端口是明文 HTTP，远端抓取会把
    /// 根 token 送上网络，因此默认 false，只有部署者显式打开才放行。
    #[serde(default)]
    pub metrics_allow_remote: bool,
    /// PEM 证书链；与 `tls_key` 必须同时设置，否则 API 只监听明文 HTTP。
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// PEM 私钥；权限必须是 `0600`，否则启动直接失败。
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            api_listen: SocketAddr::from(([127, 0, 0, 1], 8877)),
            ssh_listen: SocketAddr::from(([127, 0, 0, 1], 2222)),
            ssh_backend: SocketAddr::from(([127, 0, 0, 1], 2223)),
            max_upload_mib: 256,
            max_log_mib: 8,
            max_artifact_mib: 256,
            min_free_disk_mib: 10240,
            max_active_jobs: 4,
            replica_min_ack: 0,
            nodes: Vec::new(),
            replicas: Vec::new(),
            metrics_listen: None,
            metrics_allow_remote: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// 任务状态的跨主机副本；只使用已有 SSH 别名，不在远端安装常驻 Agent。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replica {
    pub name: String,
    pub ssh: String,
    /// 同一账号可承载多个相互隔离的控制面状态集合。
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// 独立物理故障域；同一宿主机的多个地址不能重复计数。
    pub failure_domain: String,
    /// 首次登记时固定远端稳定机器身份，重装或替换主机后拒绝继续写入。
    pub expected_host_id_sha256: String,
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
    #[serde(default = "yes")]
    pub enabled: bool,
}
/// 一个 SSH 可达的容器执行节点；同一业务节点应保留足够内存。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub ssh: String,
    #[serde(default)]
    pub images: Vec<String>,
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "one")]
    pub max_jobs: usize,
    #[serde(default = "reserve_memory")]
    pub reserve_memory_mib: u64,
    #[serde(default = "reserve_disk")]
    pub reserve_disk_mib: u64,
    #[serde(default = "max_load")]
    pub max_load_per_cpu: f64,
    #[serde(default)]
    pub priority: i32,
    /// 宿主业务预算：超预算时这台节点暂停接单。
    ///
    /// 默认全部关闭，保持既有部署的调度行为不变；显式打开后缺测量一律按
    /// 「超预算」处理 —— 没测过不等于健康。
    #[serde(default)]
    pub slo: Slo,
}

/// 宿主业务的资源预算。每一项都是「最多允许到达多少」，不是「还剩多少」。
///
/// `None` 表示不设这项门槛。设置之后若探测拿不到对应数字（老内核没有 PSI、
/// 平台不提供 swap），调度按超预算拒绝，而不是当成 0 放行。
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Slo {
    /// 已用 swap 的上限（MiB）。swap 被大量占用意味着内存已经在换页，
    /// 再加构建负载会把业务拖进更深的抖动。
    pub max_swap_used_mib: Option<u64>,
    /// 内存 PSI `some avg10` 的上限（百分比，0–100）。它衡量「有多少时间
    /// 至少有一个任务在等内存」，比单点可用内存更能反映业务是否已在受挤压。
    pub max_memory_pressure_percent: Option<f64>,
    /// IO PSI `some avg10` 的上限（百分比，0–100）。
    pub max_io_pressure_percent: Option<f64>,
}

impl Slo {
    pub fn is_empty(&self) -> bool {
        self.max_swap_used_mib.is_none()
            && self.max_memory_pressure_percent.is_none()
            && self.max_io_pressure_percent.is_none()
    }
}

fn yes() -> bool {
    true
}
fn default_namespace() -> String {
    "default".into()
}
fn one() -> usize {
    1
}
fn reserve_memory() -> u64 {
    4096
}
fn reserve_disk() -> u64 {
    10240
}
fn max_load() -> f64 {
    0.8
}

/// 项目配置明确选择命令、运行平台和资源，CLI 与构建包装器共用。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Build {
    pub image: String,
    pub platform: String,
    pub command: Vec<String>,
    pub outputs: Vec<String>,
    pub memory_mib: u64,
    pub scratch_mib: u64,
    pub cpus: f64,
    pub timeout_secs: u64,
    pub pids: u32,
    pub network: bool,
    pub retries: usize,
    pub idempotent: bool,
    /// 无可用 Worker 时允许等待的秒数；零保持立即失败。
    pub queue_timeout_secs: u64,
    /// 有限队列内的优先级；仅在允许等待时生效。
    pub queue_priority: i32,
}
impl Default for Build {
    fn default() -> Self {
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        Self {
            image: "alpine:3.22".into(),
            platform: format!("linux/{arch}"),
            command: vec!["sh".into(), "-c".into(), "uname -a".into()],
            outputs: vec![],
            memory_mib: 1024,
            scratch_mib: 512,
            cpus: 1.0,
            timeout_secs: 900,
            pids: 256,
            network: false,
            retries: 0,
            idempotent: false,
            queue_timeout_secs: 0,
            queue_priority: 0,
        }
    }
}
impl Build {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.command.is_empty() && !self.command[0].is_empty(),
            "command must not be empty"
        );
        ensure!(
            self.command.iter().all(|v| !v.contains('\0')),
            "NUL in command"
        );
        ensure!(
            !self.image.starts_with('-')
                && !self.image.is_empty()
                && !self.image.chars().any(char::is_whitespace),
            "invalid container image"
        );
        ensure!(
            ["linux/amd64", "linux/arm64"].contains(&self.platform.as_str()),
            "platform must be linux/amd64 or linux/arm64"
        );
        ensure!(
            self.memory_mib >= 128 && self.memory_mib <= 1_048_576,
            "memory_mib out of range"
        );
        ensure!(
            self.scratch_mib >= 16 && self.scratch_mib < self.memory_mib,
            "scratch_mib must be >= 16 and smaller than memory_mib (tmpfs is charged to memory)"
        );
        ensure!(
            self.cpus.is_finite() && self.cpus > 0.0 && self.cpus <= 1024.0,
            "invalid cpus"
        );
        ensure!(
            self.timeout_secs > 0 && self.timeout_secs <= 86400,
            "timeout_secs must be 1..86400"
        );
        ensure!(
            self.pids >= 16 && self.pids <= 4096,
            "pids must be 16..4096"
        );
        ensure!(self.retries <= 3, "at most three retries");
        ensure!(
            self.queue_timeout_secs <= 604_800,
            "queue_timeout_secs must not exceed seven days"
        );
        ensure!(
            (-1000..=1000).contains(&self.queue_priority),
            "queue_priority must be between -1000 and 1000"
        );
        ensure!(
            self.queue_timeout_secs > 0 || self.queue_priority == 0,
            "queue_priority requires queue_timeout_secs"
        );
        ensure!(
            self.retries == 0 || (self.idempotent && !self.network),
            "retry requires idempotent=true and network=false"
        );
        for output in &self.outputs {
            crate::archive::relative_path(Path::new(output))?;
        }
        Ok(())
    }
}
pub fn default_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --home")?;
    Ok(PathBuf::from(home).join(".sshpool"))
}
pub fn read(home: &Path) -> Result<Config> {
    let config: Config = toml::from_str(&fs::read_to_string(home.join("config.toml"))?)?;
    validate(&config)?;
    Ok(config)
}

/// 配置、CLI 修改和启动共用同一组故障域与 quorum 的不变量。
pub fn validate(config: &Config) -> Result<()> {
    ensure!(
        config.max_active_jobs > 0 && config.max_active_jobs <= 64,
        "max_active_jobs must be 1..64"
    );
    ensure!(
        config.max_upload_mib > 0 && config.max_upload_mib <= 4096,
        "invalid max_upload_mib"
    );
    ensure!(
        config.max_artifact_mib > 0 && config.max_log_mib > 0,
        "invalid output limits"
    );
    ensure!(
        config.ssh_listen != config.ssh_backend,
        "SSH proxy cannot forward to itself"
    );
    // 指标端点与控制面共端口会让指标请求落进带鉴权与审计的路由，
    // 而且抓取会冲掉有界审计；这里显式拒绝，而不是等 bind 报 address in use。
    if let Some(metrics) = config.metrics_listen {
        ensure!(
            metrics != config.api_listen && metrics != config.ssh_listen,
            "metrics_listen must not reuse api_listen or ssh_listen"
        );
        // 指标端口是明文 HTTP，抓取要带根 token：绑定非回环地址等于把运维 token
        // 交给整个网络。默认只允许回环，远端抓取必须由部署者显式确认。
        ensure!(
            metrics.ip().is_loopback() || config.metrics_allow_remote,
            "metrics_listen is not loopback; set metrics_allow_remote = true to expose it"
        );
        // 远端抓取必须加密：明文 HTTP 上的 Bearer token 等于公开凭据。
        ensure!(
            metrics.ip().is_loopback() || config.tls_cert.is_some(),
            "a non-loopback metrics_listen requires TLS (tls_cert and tls_key)"
        );
    }
    // TLS 只能「全有或全无」：只配一半会让启动悄悄退回明文，是最危险的失败模式。
    ensure!(
        config.tls_cert.is_some() == config.tls_key.is_some(),
        "tls_cert and tls_key must be configured together"
    );
    for path in [config.tls_cert.as_ref(), config.tls_key.as_ref()]
        .into_iter()
        .flatten()
    {
        ensure!(
            path.is_absolute(),
            "TLS paths must be absolute: {}",
            path.display()
        );
    }
    let mut names = HashSet::new();
    for node in &config.nodes {
        validate_node(node)?;
        ensure!(names.insert(&node.name), "duplicate node: {}", node.name);
    }
    let enabled_replicas = config
        .replicas
        .iter()
        .filter(|replica| replica.enabled)
        .collect::<Vec<_>>();
    ensure!(
        config.replica_min_ack <= enabled_replicas.len() + 1,
        "replica_min_ack exceeds enabled replicas plus local state"
    );
    ensure!(
        config.replicas.is_empty() || config.replica_min_ack > 0,
        "configured replicas require replica_min_ack > 0"
    );
    ensure!(
        !config.replicas.is_empty() || config.replica_min_ack == 0,
        "local-only configuration cannot claim a cross-host quorum"
    );
    ensure!(
        config.replicas.is_empty() || config.replica_min_ack >= 2,
        "configured replicas require local plus at least one remote acknowledgement"
    );
    let mut replica_names = HashSet::new();
    let mut replica_hosts = HashSet::new();
    let mut failure_domains = HashSet::new();
    for replica in &config.replicas {
        validate_replica(replica)?;
        ensure!(
            replica.name != "local",
            "replica name 'local' is reserved for controller state"
        );
        ensure!(
            replica.failure_domain != "local",
            "failure domain 'local' is reserved for controller state"
        );
        ensure!(
            replica_names.insert(&replica.name),
            "duplicate replica: {}",
            replica.name
        );
        if replica.enabled {
            ensure!(
                replica_hosts.insert(&replica.expected_host_id_sha256),
                "duplicate enabled replica host identity: {}",
                replica.name
            );
            ensure!(
                failure_domains.insert(&replica.failure_domain),
                "duplicate enabled failure domain: {}",
                replica.failure_domain
            );
        }
    }
    Ok(())
}

pub fn validate_replica(replica: &Replica) -> Result<()> {
    validate_label("replica", &replica.name)?;
    validate_label("replica namespace", &replica.namespace)?;
    validate_label("failure_domain", &replica.failure_domain)?;
    ensure!(
        replica.failure_domain != "local",
        "failure domain 'local' is reserved for controller state"
    );
    ensure!(
        replica.expected_host_id_sha256.len() == 64
            && replica
                .expected_host_id_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid replica host identity"
    );
    validate_ssh_target(&replica.ssh)
}

fn validate_label(kind: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character)),
        "invalid {kind}"
    );
    Ok(())
}

fn validate_ssh_target(target: &str) -> Result<()> {
    ensure!(
        !target.is_empty()
            && !target.starts_with('-')
            && target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@:+[]".contains(c)),
        "use an SSH alias or user@host, without shell syntax"
    );
    Ok(())
}
pub fn validate_node(node: &Node) -> Result<()> {
    ensure!(
        !node.name.is_empty()
            && node
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)),
        "invalid node name"
    );
    validate_ssh_target(&node.ssh)?;
    ensure!(node.max_jobs > 0 && node.max_jobs <= 64, "invalid max_jobs");
    ensure!(
        node.max_load_per_cpu.is_finite() && node.max_load_per_cpu > 0.0,
        "invalid max_load_per_cpu"
    );
    for (label, value) in [
        (
            "max_memory_pressure_percent",
            node.slo.max_memory_pressure_percent,
        ),
        ("max_io_pressure_percent", node.slo.max_io_pressure_percent),
    ] {
        if let Some(value) = value {
            // PSI 的 avg10 本来就是 0–100 的百分比；写出 100 以上只会让人以为
            // 门槛被放宽了，实际永远不会触发。
            ensure!(
                value.is_finite() && (0.0..=100.0).contains(&value),
                "invalid {label}: must be 0..=100"
            );
        }
    }
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    use std::io::Write;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
pub fn save(home: &Path, config: &Config) -> Result<()> {
    atomic_write(
        &home.join("config.toml"),
        toml::to_string_pretty(config)?.as_bytes(),
    )
}
