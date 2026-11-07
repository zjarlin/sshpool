use crate::{
    config::{self, Config},
    mirror,
    model::{Job, Phase, now},
};
use anyhow::{Context, Result, ensure};
use std::{collections::HashMap, fs, path::Path, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore, watch};
use uuid::Uuid;

/// 控制面共享状态：同一把锁同时保护节点配额与任务状态转换。
pub struct State {
    pub home: PathBuf,
    pub config: Config,
    pub token: String,
    pub jobs: Mutex<HashMap<Uuid, Job>>,
    node_overrides: Mutex<HashMap<String, bool>>,
    queue_changed: watch::Sender<u64>,
    pub uploads: Arc<Semaphore>,
    pub scheduling: Mutex<()>,
    /// 串行化所有需要跨主机确认的状态转换，避免两个候选复用同一版本。
    pub transitions: Mutex<()>,
    pub audit: Mutex<()>,
}

impl State {
    pub fn load(home: PathBuf, config: Config) -> Result<Arc<Self>> {
        let token = fs::read_to_string(home.join("token"))?.trim().to_string();
        ensure!(token.len() >= 32, "token is too short");
        fs::create_dir_all(home.join("jobs"))?;
        let mut jobs = HashMap::new();
        for entry in fs::read_dir(home.join("jobs"))? {
            let entry = entry?;
            let Ok(id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            let record = entry.path().join("job.json");
            if !record.exists() {
                continue;
            }
            let mut job: Job = serde_json::from_slice(&fs::read(record)?)?;
            ensure!(id == job.id, "job directory identity mismatch");
            // 失败写入留下的版本占位也是恢复下限；进程重启不能回退或复用。
            job.revision = job.revision.max(read_reserved_revision(&entry.path())?);
            jobs.insert(id, job);
        }
        let uploads = Arc::new(Semaphore::new(config.max_active_jobs));
        let (queue_changed, _) = watch::channel(0);
        Ok(Arc::new(Self {
            home,
            config,
            token,
            jobs: Mutex::new(jobs),
            node_overrides: Mutex::new(HashMap::new()),
            queue_changed,
            uploads,
            scheduling: Mutex::new(()),
            transitions: Mutex::new(()),
            audit: Mutex::new(()),
        }))
    }

    /// 返回应用运行时节点开关后的配置副本，供状态查询和调度共同使用。
    pub async fn nodes(&self) -> Vec<crate::config::Node> {
        let overrides = self.node_overrides.lock().await;
        self.nodes_with_overrides(&overrides)
    }

    /// 在线切换节点接单状态；已有活动任务必须先确认结束，避免维护期遗漏容器。
    pub async fn set_node_enabled(&self, name: &str, enabled: bool) -> Result<crate::config::Node> {
        let _scheduling = self.scheduling.lock().await;
        let mut overrides = self.node_overrides.lock().await;
        let mut config = self.config_with_overrides(&overrides);
        let node = config
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| anyhow::anyhow!("unknown node"))?;
        if !enabled {
            let active = self.jobs.lock().await.values().any(|job| {
                !job.phase.terminal()
                    && job
                        .attempts
                        .last()
                        .is_some_and(|attempt| attempt.node == name)
            });
            ensure!(
                !active,
                "node still owns an active job; wait for confirmed completion before disabling"
            );
        }
        node.enabled = enabled;
        let changed = node.clone();
        config::save(&self.home, &config)?;
        overrides.insert(name.into(), enabled);
        self.wake_queue();
        Ok(changed)
    }

    /// 订阅队列或节点容量变化；接收端可在一次探测之后等待新的调度机会。
    pub fn queue_changed(&self) -> watch::Receiver<u64> {
        self.queue_changed.subscribe()
    }

    /// 唤醒有限队列的等待者；不改变任务期限或执行状态。
    pub fn wake_queue(&self) {
        self.queue_changed.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }

    fn config_with_overrides(&self, overrides: &HashMap<String, bool>) -> Config {
        let mut config = self.config.clone();
        for node in &mut config.nodes {
            if let Some(enabled) = overrides.get(&node.name) {
                node.enabled = *enabled;
            }
        }
        config
    }

    fn nodes_with_overrides(&self, overrides: &HashMap<String, bool>) -> Vec<crate::config::Node> {
        self.config_with_overrides(overrides).nodes
    }

    pub fn dir(&self, id: Uuid) -> PathBuf {
        self.home.join("jobs").join(id.to_string())
    }

    /// 发布本机状态并分配新版本；此函数不宣称已经达到跨机持久 quorum。
    pub fn persist(&self, job: &mut Job) -> Result<()> {
        job.revision = reserve_revision(&self.home, job.id, job.revision)?;
        write_local_job(&self.dir(job.id), job)
    }

    /// 发起远端写入前先分配并落盘版本号；失败和掉电都只会消耗版本，不会复用。
    pub async fn checkpoint(&self, id: Uuid) -> Result<Vec<String>> {
        let _transition = self.transitions.lock().await;
        let job = self
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .context("unknown job")?;
        let (_, acknowledgements) = self.checkpoint_candidate_locked(job).await?;
        Ok(acknowledgements)
    }

    /// 复制并发布一个候选状态；调用方必须先持有 transitions。
    pub(crate) async fn checkpoint_candidate_locked(
        &self,
        mut candidate: Job,
    ) -> Result<(Job, Vec<String>)> {
        candidate.revision = reserve_revision(&self.home, candidate.id, candidate.revision)?;
        let acknowledgements = mirror::sync_job_state(&self.config, &self.home, &candidate).await?;
        let directory = self.dir(candidate.id);
        write_local_job(&directory, &candidate)?;
        self.jobs
            .lock()
            .await
            .insert(candidate.id, candidate.clone());
        Ok((candidate, acknowledgements))
    }

    /// 首次提交等无并发候选的路径自行获取状态转换锁。
    pub async fn checkpoint_candidate(&self, candidate: Job) -> Result<(Job, Vec<String>)> {
        let _transition = self.transitions.lock().await;
        self.checkpoint_candidate_locked(candidate).await
    }

    /// 顺序追加有界阶段事件，不写 token、私钥或完整命令行。
    pub async fn event(&self, id: Uuid, kind: &str, detail: &str) -> Result<()> {
        use std::io::Write;
        let _guard = self.audit.lock().await;
        let event = serde_json::json!({"time": now(), "job": id, "kind": kind, "detail": detail});
        let mut bytes = serde_json::to_vec(&event)?;
        bytes.push(10);
        let path = self.dir(id).join("events.jsonl");
        let created = !path.exists();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        if created && let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// 成功达到副本 quorum 并发布本地终态后，才向调用方返回成功。
    pub async fn finish(
        &self,
        id: Uuid,
        phase: Phase,
        code: Option<i32>,
        message: String,
        artifacts: bool,
    ) -> Result<()> {
        let _transition = self.transitions.lock().await;
        let mut candidate = self
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .context("unknown job")?;
        candidate.phase = phase.clone();
        candidate.exit_code = code;
        candidate.message = Some(message);
        candidate.finished_at = Some(now());
        candidate.artifacts = artifacts;
        // 事件必须先于最后一次跨机提交落盘：恢复包只包含提交时刻目录里的文件，
        // 先提交再写事件会让「任务已经结束」这条审计记录永远进不了任何副本，
        // 从远端恢复出来的任务就缺少终态事件。job.json 仍是阶段的权威来源，
        // 因此提交失败时多出的这条事件不会让任务被误认为已结束。
        self.event(id, "finished", &format!("{:?}", phase)).await?;
        self.checkpoint_candidate_locked(candidate).await?;
        self.wake_queue();
        Ok(())
    }

    /// 副本承诺失败时保留本机终态供诊断；这不是跨主机持久成功。
    pub async fn finish_local(
        &self,
        id: Uuid,
        phase: Phase,
        code: Option<i32>,
        message: String,
        artifacts: bool,
    ) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        let job = jobs.get_mut(&id).context("unknown job")?;
        job.phase = phase;
        job.exit_code = code;
        job.message = Some(format!(
            "{message}; local-only state, cross-host durability not promised"
        ));
        job.finished_at = Some(now());
        job.artifacts = artifacts;
        self.persist(job)
    }

    pub fn local_artifacts_available(&self, id: Uuid) -> bool {
        self.dir(id).join("artifacts.tar").is_file()
    }

    pub async fn cancelled(&self, id: Uuid) -> bool {
        self.jobs
            .lock()
            .await
            .get(&id)
            .is_some_and(|job| job.cancel_requested)
    }
}

fn write_local_job(directory: &Path, job: &Job) -> Result<()> {
    config::atomic_write(
        &directory.join("job.json"),
        &serde_json::to_vec_pretty(job)?,
    )
}

fn read_reserved_revision(directory: &Path) -> Result<u64> {
    let path = directory.join(".revision");
    match fs::read_to_string(&path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .with_context(|| format!("invalid revision reservation {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

/// 预留下一版本；写入失败时也可能已消耗版本，因此调用方不能重新发布旧版本。
pub fn reserve_revision(home: &Path, id: Uuid, current: u64) -> Result<u64> {
    let directory = home.join("jobs").join(id.to_string());
    fs::create_dir_all(&directory)?;
    let reserved = read_reserved_revision(&directory)?;
    let revision = current
        .max(reserved)
        .checked_add(1)
        .context("job revision overflow")?;
    config::atomic_write(
        &directory.join(".revision"),
        revision.to_string().as_bytes(),
    )?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::{State, reserve_revision};
    use crate::{
        config::Config,
        model::{Job, Phase},
    };
    use anyhow::Result;
    use std::fs;

    fn state() -> Result<(tempfile::TempDir, std::sync::Arc<State>, Job)> {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("token"),
            "test-only-token-not-a-production-secret",
        )?;
        let state = State::load(root.path().to_path_buf(), Config::default())?;
        let id = uuid::Uuid::new_v4();
        fs::create_dir_all(state.dir(id))?;
        let job = Job {
            id,
            revision: 0,
            build: Default::default(),
            phase: Phase::Queued,
            created_at: 0,
            finished_at: None,
            attempts: Vec::new(),
            exit_code: None,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: false,
            queue_deadline: None,
            source_sha256: None,
        };
        Ok((root, state, job))
    }

    #[tokio::test]
    async fn failed_write_cannot_reuse_a_reserved_revision() -> Result<()> {
        let (_root, state, mut job) = state()?;
        state.persist(&mut job)?;
        assert_eq!(job.revision, 1);
        let failed = reserve_revision(&state.home, job.id, job.revision)?;
        assert_eq!(failed, 2);
        // 模拟远端失败后重载；job.json 仍是 1，但预留文件必须抬回已消耗版本。
        let reloaded = State::load(state.home.clone(), state.config.clone())?;
        let mut stored = reloaded
            .jobs
            .lock()
            .await
            .get(&job.id)
            .cloned()
            .unwrap_or_else(|| job.clone());
        assert_eq!(stored.revision, 2);
        state.persist(&mut stored)?;
        assert_eq!(stored.revision, 3);
        Ok(())
    }

    #[test]
    fn revision_reservations_never_wrap() -> Result<()> {
        let (_root, state, job) = state()?;
        assert!(reserve_revision(&state.home, job.id, u64::MAX).is_err());
        Ok(())
    }
}
