use crate::config::Build;
use serde::{Deserialize, Serialize};

/// 节点快照来自只读探测，不把主机内存当成可相加的进程内存。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub name: String,
    pub os: String,
    pub arch: String,
    pub cpus: u32,
    pub memory_available_mib: u64,
    pub disk_available_mib: u64,
    pub load: f64,
    pub runtime_memory_mib: u64,
    pub runtime_arch: String,
    pub error: Option<String>,
}
impl Health {
    pub fn failed(name: &str, error: String) -> Self {
        Self {
            name: name.into(),
            os: String::new(),
            arch: String::new(),
            cpus: 0,
            memory_available_mib: 0,
            disk_available_mib: 0,
            load: 0.0,
            runtime_memory_mib: 0,
            runtime_arch: String::new(),
            error: Some(error),
        }
    }
}
/// 任务状态写入控制面磁盘；重启后会核对未完成容器。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
}
impl Phase {
    pub fn terminal(&self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub node: String,
    pub container: String,
    pub started_at: u64,
    pub outcome: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: uuid::Uuid,
    pub build: Build,
    pub phase: Phase,
    pub created_at: u64,
    pub finished_at: Option<u64>,
    pub attempts: Vec<Attempt>,
    pub exit_code: Option<i32>,
    pub message: Option<String>,
    pub artifacts: bool,
    pub cancel_requested: bool,
    #[serde(default)]
    pub cleanup_confirmed: bool,
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}
