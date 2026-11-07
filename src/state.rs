use crate::{
    config::{self, Config},
    model::{Job, Phase, now},
};
use anyhow::{Result, ensure};
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

/// 控制面共享状态：同一把锁同时保护节点配额与任务状态转换。
pub struct State {
    pub home: PathBuf,
    pub config: Config,
    pub token: String,
    pub jobs: Mutex<HashMap<Uuid, Job>>,
    node_overrides: Mutex<HashMap<String, bool>>,
    pub uploads: Arc<Semaphore>,
    pub scheduling: Mutex<()>,
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
            let job: Job = serde_json::from_slice(&fs::read(record)?)?;
            ensure!(id == job.id, "job directory identity mismatch");
            jobs.insert(id, job);
        }
        let uploads = Arc::new(Semaphore::new(config.max_active_jobs));
        Ok(Arc::new(Self {
            home,
            config,
            token,
            jobs: Mutex::new(jobs),
            node_overrides: Mutex::new(HashMap::new()),
            uploads,
            scheduling: Mutex::new(()),
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
        Ok(changed)
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
    pub fn persist(&self, job: &Job) -> Result<()> {
        config::atomic_write(
            &self.dir(job.id).join("job.json"),
            &serde_json::to_vec_pretty(job)?,
        )
    }
    /// 顺序追加有界阶段事件，不写 token、私钥或完整命令行。
    pub async fn event(&self, id: Uuid, kind: &str, detail: &str) -> Result<()> {
        use std::io::Write;
        let _guard = self.audit.lock().await;
        let event = serde_json::json!({"time": now(), "job": id, "kind": kind, "detail": detail});
        let mut bytes = serde_json::to_vec(&event)?;
        bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir(id).join("events.jsonl"))?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        Ok(())
    }
    pub async fn finish(
        &self,
        id: Uuid,
        phase: Phase,
        code: Option<i32>,
        message: String,
        artifacts: bool,
    ) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("unknown job"))?;
        job.phase = phase;
        job.exit_code = code;
        job.message = Some(message);
        job.finished_at = Some(now());
        job.artifacts = artifacts;
        self.persist(job)?;
        let phase = format!("{:?}", job.phase);
        drop(jobs);
        self.event(id, "finished", &phase).await
    }
    pub async fn cancelled(&self, id: Uuid) -> bool {
        self.jobs
            .lock()
            .await
            .get(&id)
            .is_some_and(|job| job.cancel_requested)
    }
}
