use crate::config::Build;
use serde::{Deserialize, Serialize};

/// 节点快照来自只读探测，不把主机内存当成可相加的进程内存。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub name: String,
    // 远端普通探测不返回控制面的启用状态；旧协议缺字段时按关闭处理。
    #[serde(default)]
    pub enabled: bool,
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
            enabled: false,
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
impl Job {
    /// 每次可观察状态变化增加版本；溢出时失败，不能回绕成旧版本。
    pub fn bump_revision(&mut self) -> anyhow::Result<u64> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("job revision overflow"))?;
        Ok(self.revision)
    }
    /// 判断当前时刻是否仍可按显式期限等待；已尝试或旧记录均不重放。
    pub fn queue_open_at(&self, timestamp: u64) -> bool {
        self.phase == Phase::Queued
            && self.attempts.is_empty()
            && self.build.queue_timeout_secs > 0
            && self
                .queue_deadline
                .is_some_and(|deadline| timestamp < deadline)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub node: String,
    pub container: String,
    pub started_at: u64,
    pub outcome: Option<String>,
    /// 每次尝试单独记录清理结果，避免后续成功覆盖旧节点的不确定状态。
    #[serde(default)]
    pub cleanup_confirmed: Option<bool>,
    /// 远端看门狗租约到期时刻：容器入口自带 `sleep` 寿命，到期后不可能仍有进程。
    /// 只有 SSH 探测失败时才用它作为「旧容器一定已结束」的时间证据。
    #[serde(default)]
    pub watchdog_deadline: Option<u64>,
    /// 解除「清理未确认」时使用的证据来源；为空表示从未确认。
    #[serde(default)]
    pub cleanup_proof: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: uuid::Uuid,
    /// 单调状态版本；恢复时先选最高版本，旧目录保留为备份。
    #[serde(default)]
    pub revision: u64,
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
    /// 新任务的有限排队绝对截止时间；旧记录缺失时不自动重放。
    #[serde(default)]
    pub queue_deadline: Option<u64>,
    /// 客户端上传归档的 SHA-256；旧记录可能没有摘要，恢复时按谨慎语义处理。
    #[serde(default)]
    pub source_sha256: Option<String>,
    /// 提交该任务的主体名；根 token 固定写成 `root`（保留名，不能签成凭据主体）。
    ///
    /// 旧记录没有这个字段，恢复成 `None` =「属主未知」。属主未知一律按最严处理：
    /// 只有根 token 与带 `admin` 的运维凭据能看到，其他凭据既不列表也不可访问。
    #[serde(default)]
    pub owner: Option<String>,
}

/// 有限队列按优先级降序、提交时间升序和稳定任务标识排序。
pub fn queue_precedes(left: &Job, right: &Job) -> bool {
    if left.phase != Phase::Queued || right.phase != Phase::Queued {
        return false;
    }
    if left.build.queue_priority != right.build.queue_priority {
        return left.build.queue_priority > right.build.queue_priority;
    }
    if left.created_at != right.created_at {
        return left.created_at < right.created_at;
    }
    left.id < right.id
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}
