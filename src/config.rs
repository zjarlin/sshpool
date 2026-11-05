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
    pub nodes: Vec<Node>,
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
            nodes: Vec::new(),
        }
    }
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
}
fn yes() -> bool {
    true
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
    let mut names = HashSet::new();
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
    for node in &config.nodes {
        validate_node(node)?;
        ensure!(names.insert(&node.name), "duplicate node: {}", node.name);
    }
    Ok(config)
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
    ensure!(
        !node.ssh.is_empty()
            && !node.ssh.starts_with('-')
            && node
                .ssh
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@:+[]".contains(c)),
        "use an SSH alias or user@host, without shell syntax"
    );
    ensure!(node.max_jobs > 0 && node.max_jobs <= 64, "invalid max_jobs");
    ensure!(
        node.max_load_per_cpu.is_finite() && node.max_load_per_cpu > 0.0,
        "invalid max_load_per_cpu"
    );
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}
pub fn save(home: &Path, config: &Config) -> Result<()> {
    atomic_write(
        &home.join("config.toml"),
        toml::to_string_pretty(config)?.as_bytes(),
    )
}
