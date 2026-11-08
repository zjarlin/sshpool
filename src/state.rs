use crate::{
    config::{self, Config, Node, NodePatch},
    mirror,
    model::{Health, Job, Phase, now},
};
use anyhow::{Context, Result, ensure};
use futures_util::future::BoxFuture;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, Semaphore, watch};
use uuid::Uuid;

/// 节点健康快照的最长可用年龄。
///
/// 调度必须在锁外探测：一台不可达节点会让 `ssh` 一直等到 `ConnectTimeout`（5s），
/// 而探测若在调度锁内进行，这段时间里所有任务派发都会被串行阻塞。快照带 TTL
/// 是为了不让「刚恢复的节点」长期被旧结论挡住——过期后下一次调度会重新探测。
pub const HEALTH_TTL: Duration = Duration::from_secs(15);

/// 在 Worker 上真实拉取镜像的唯一入口。
///
/// 单独抽出来是为了让「先拉取、再落盘」的顺序可以被离线验证：拉取失败必须不
/// 改动配置，而这件事只能靠一个可替换的远端动作来断言。生产实现只有
/// [`SshImagePuller`] 一种，它就是把 `docker pull` 交给既有的 OpenSSH 通道。
pub trait ImagePuller: Send + Sync {
    fn pull<'a>(&'a self, node: &'a Node, image: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// 经 `transport::checked` 执行 `docker pull`；输出只进日志，不参与判定。
pub struct SshImagePuller;

impl ImagePuller for SshImagePuller {
    fn pull<'a>(&'a self, node: &'a Node, image: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let script = format!("docker pull {}", crate::transport::quote(image));
            let output = crate::transport::checked(node, &script, 300).await?;
            eprintln!(
                "sshpool: pulled {image} on {}: {}",
                node.name,
                String::from_utf8_lossy(&output).trim()
            );
            Ok(())
        })
    }
}

/// 控制面共享状态：同一把锁同时保护节点配额与任务状态转换。
pub struct State {
    pub home: PathBuf,
    pub config: Config,
    pub token: String,
    pub jobs: Mutex<HashMap<Uuid, Job>>,
    /// 当前生效的节点视图。启动时来自 `config.toml`，运行时只由 `update_node` 替换，
    /// 替换时先原子落盘再改内存，因此「状态接口看到的」与「重启后会读到的」始终一致。
    nodes: RwLock<Vec<Node>>,
    queue_changed: watch::Sender<u64>,
    pub uploads: Arc<Semaphore>,
    pub scheduling: Mutex<()>,
    /// 最近一次锁外探测结果；锁内只读它，绝不在持锁时等待 SSH。
    health: RwLock<Vec<(Instant, Health)>>,
    /// 合并并发探测：同一时刻只有一次 `probe::all`，其余调用者等待并复用结果。
    /// 任务派发与 `/v1/status` 都会触发探测，没有这把锁时一次抖动会被放大成多轮 SSH。
    probing: Mutex<()>,
    /// 串行化所有需要跨主机确认的状态转换，避免两个候选复用同一版本。
    pub transitions: Mutex<()>,
    pub audit: Mutex<()>,
    /// 串行化访问审计的追加与滚动，避免两行交错或滚动时丢记录。
    pub access: Mutex<()>,
    /// 拉取镜像的远端入口；默认经 SSH，测试可以替换成受控实现。
    images: Arc<dyn ImagePuller>,
}

impl State {
    pub fn load(home: PathBuf, config: Config) -> Result<Arc<Self>> {
        Self::load_with_puller(home, config, Arc::new(SshImagePuller))
    }

    /// 用指定的镜像拉取器构造状态；生产只经 [`State::load`] 使用 SSH 实现。
    pub fn load_with_puller(
        home: PathBuf,
        config: Config,
        images: Arc<dyn ImagePuller>,
    ) -> Result<Arc<Self>> {
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
            nodes: RwLock::new(config.nodes.clone()),
            config,
            token,
            jobs: Mutex::new(jobs),
            queue_changed,
            uploads,
            scheduling: Mutex::new(()),
            health: RwLock::new(Vec::new()),
            probing: Mutex::new(()),
            transitions: Mutex::new(()),
            audit: Mutex::new(()),
            access: Mutex::new(()),
            images,
        }))
    }

    /// 锁内使用：只返回已知快照，绝不发起远端命令。
    ///
    /// 返回的向量长度与 `nodes` 一一对应；没有探测过的节点用「未探测」占位，
    /// 调度据此拒绝分配（fail-closed），而不是把它当成资源充足。
    pub async fn health_snapshot(&self, nodes: &[crate::config::Node]) -> Vec<Health> {
        let cached = self.health.read().await;
        nodes
            .iter()
            .map(|node| {
                cached
                    .iter()
                    .find(|(_, health)| health.name == node.name)
                    .map(|(_, health)| {
                        let mut health = health.clone();
                        health.enabled = node.enabled;
                        health
                    })
                    .unwrap_or_else(|| Health::failed(&node.name, "health not probed yet".into()))
            })
            .collect()
    }

    /// 锁外探测并刷新快照；调用方不得持有 `scheduling`。
    ///
    /// 并发调用会排队，拿到探测锁后先看缓存是否已被前一个调用者刷成新鲜快照；
    /// 是则直接复用，避免一次抖动被多个等待者放大成多轮 SSH。
    pub async fn refresh_health(&self, nodes: &[crate::config::Node]) -> Vec<Health> {
        let _probing = self.probing.lock().await;
        self.probe_locked(nodes).await
    }

    /// 调度路径：只有快照过期才探测，避免每次派发都打一轮 SSH。
    ///
    /// 与 `refresh_health` 共用 `probing` 锁，因此并发调用只会产生一轮探测。
    pub async fn ensure_health(&self, nodes: &[crate::config::Node]) -> Vec<Health> {
        let _probing = self.probing.lock().await;
        if !self.health_is_stale(nodes).await {
            return self.health_snapshot(nodes).await;
        }
        self.probe_locked(nodes).await
    }

    /// 调用方必须持有 `probing`；探测本身在 `scheduling` 之外执行。
    async fn probe_locked(&self, nodes: &[crate::config::Node]) -> Vec<Health> {
        let probed = crate::probe::all(nodes).await;
        let at = Instant::now();
        let mut cache = self.health.write().await;
        cache.retain(|(_, health)| nodes.iter().any(|node| node.name == health.name));
        for health in &probed {
            match cache
                .iter_mut()
                .find(|(_, entry)| entry.name == health.name)
            {
                Some(entry) => *entry = (at, health.clone()),
                None => cache.push((at, health.clone())),
            }
        }
        probed
    }

    /// 快照是否已过期；过期时必须先在锁外重新探测，再进入调度。
    pub async fn health_is_stale(&self, nodes: &[crate::config::Node]) -> bool {
        let cache = self.health.read().await;
        nodes.iter().any(|node| {
            !cache
                .iter()
                .any(|(at, health)| health.name == node.name && at.elapsed() < HEALTH_TTL)
        })
    }

    /// 返回当前生效的节点视图，供状态查询、指标和调度共同使用。
    pub async fn nodes(&self) -> Vec<Node> {
        self.nodes.read().await.clone()
    }

    /// 单节点视图；未知节点与在线更新一样按拒绝处理。
    pub async fn node(&self, name: &str) -> Result<Node> {
        self.nodes
            .read()
            .await
            .iter()
            .find(|node| node.name == name)
            .cloned()
            .context("unknown node")
    }

    /// 在线切换节点接单状态；已有活动任务必须先确认结束，避免维护期遗漏容器。
    pub async fn set_node_enabled(&self, name: &str, enabled: bool) -> Result<Node> {
        let patch = NodePatch {
            enabled: Some(enabled),
            ..NodePatch::default()
        };
        let (node, _) = self.update_node(name, &patch).await?;
        Ok(node)
    }

    /// 在线更新单个节点的调度设置：业务预算、资源预留、并发槽位、负载上限与优先级。
    ///
    /// 顺序是「校验 → 落盘 → 换内存」，三步都在 `scheduling` 锁内完成，所以不会出现
    /// 任务按半套设置被派发的中间态。落盘前重新读一次 `config.toml` 并与内存比对：
    /// 有人在控制面运行时手改了这台节点，就拒绝并提示重启加载，而不是把他的手改覆盖掉。
    pub async fn update_node(&self, name: &str, patch: &NodePatch) -> Result<(Node, Vec<String>)> {
        let _scheduling = self.scheduling.lock().await;
        let current = self.node(name).await?;
        let (patched, changes) = patch.apply(&current)?;
        config::validate_node(&patched)?;
        if !patched.enabled {
            self.ensure_no_active_job(name).await?;
        }
        self.ensure_config_matches_memory(&current).await?;
        let mut file = config::read(&self.home)?;
        let index = file
            .nodes
            .iter()
            .position(|node| node.name == name)
            .expect("the node was just located");
        file.nodes[index] = patched.clone();
        // 整份配置的不变量（唯一名字、副本 quorum 等）仍然必须成立，不能只校验这一台。
        config::validate(&file)?;
        config::save(&self.home, &file)?;
        {
            let mut nodes = self.nodes.write().await;
            if let Some(entry) = nodes.iter_mut().find(|node| node.name == name) {
                *entry = patched.clone();
            }
        }
        // 槽位或预算可能刚刚放宽，等待中的任务应当立刻重试一次而不是等下一个 TTL。
        self.wake_queue();
        Ok((patched, changes))
    }

    /// 在线准备镜像：先确认控制面内存与 `config.toml` 一致，再在 Worker 上真实拉取，
    /// 拉取成功之后才把镜像写进该节点的允许清单。
    ///
    /// 判据是「配置里有了它之前，它已经在这台机器上」：授权顺序反过来（先写清单
    /// 再拉取）会让一次失败的拉取留下「已授权但不存在」的镜像，任务随后在派发时
    /// 才失败，且没人知道是拉取没做完。
    ///
    /// `docker pull` 是幂等且不碰配置的远端动作，所以在 `scheduling` 锁外执行：
    /// 一个大镜像可能拉几分钟，持锁会让所有任务的派发一起停住。锁内只做
    /// 「重读配置比对 → 校验 → 原子落盘 → 换内存 → 唤醒队列」，与 `update_node`
    /// 用同一条顺序，因此并发 prepare 与在线改设置不会互相覆盖。
    ///
    /// 返回 `(节点, 是否真的执行了拉取)`；镜像已在清单里时直接返回，不重复拉。
    pub async fn prepare_node(&self, name: &str, image: &str) -> Result<(Node, bool)> {
        config::validate_image(image)?;
        let current = self.node(name).await?;
        // 先做一次「外部手改」判定：明知配置已被别人改过还去拉镜像，
        // 等于在错误的前提下产生远端副作用。
        self.ensure_config_matches_memory(&current).await?;
        if current.images.iter().any(|approved| approved == image) {
            return Ok((current, false));
        }
        // 第二轮检查与落盘之间仍有窗口；这里靠 `docker pull` 的幂等性与锁内重读兜住。
        self.images.pull(&current, image).await?;
        let _scheduling = self.scheduling.lock().await;
        // 拉取期间可能有人在线改了别的字段，也可能并发了同一张镜像的 prepare：
        // 锁内以内存里的当前值为准重建，而不是拿拉取前那份快照覆盖回去。
        let latest = self.node(name).await?;
        self.ensure_config_matches_memory(&latest).await?;
        if latest.images.iter().any(|approved| approved == image) {
            return Ok((latest, false));
        }
        let mut file = config::read(&self.home)?;
        let mut patched = latest;
        patched.images.push(image.to_string());
        config::validate_node(&patched)?;
        let index = file
            .nodes
            .iter()
            .position(|node| node.name == name)
            .expect("the node was just located");
        file.nodes[index] = patched.clone();
        config::validate(&file)?;
        config::save(&self.home, &file)?;
        {
            let mut nodes = self.nodes.write().await;
            if let Some(entry) = nodes.iter_mut().find(|node| node.name == name) {
                *entry = patched.clone();
            }
        }
        // 新镜像可能正是等待中的任务缺的那一个授权。
        self.wake_queue();
        Ok((patched, true))
    }

    /// 在线撤销镜像授权：只收缩允许清单，不删除 Worker 上的镜像层。
    ///
    /// 与 [`State::prepare_node`] 正好反向：那条路由要让远端真的具备镜像，这条只
    /// 改变「谁可以申请它」。因此它没有远端副作用，整段在 `scheduling` 锁内完成，
    /// 与 `update_node` 用同一条写入顺序。
    ///
    /// 撤销不会杀死已经启动的容器，所以「容器还在跑、授权已经没了」是一种只会在
    /// 事后才被发现的错位状态。正在这台节点上执行这张镜像时直接拒绝，让运维先
    /// `cancel` 或等清理确认 —— 需要立刻止血的场景应当先取消任务。
    ///
    /// 返回 `(节点, 是否真的删掉了授权)`；清单里本来就没有时返回 `false`，不写盘。
    pub async fn revoke_node_image(&self, name: &str, image: &str) -> Result<(Node, bool)> {
        config::validate_image(image)?;
        let _scheduling = self.scheduling.lock().await;
        let current = self.node(name).await?;
        self.ensure_config_matches_memory(&current).await?;
        if !current.images.iter().any(|approved| approved == image) {
            return Ok((current, false));
        }
        self.ensure_image_not_running(name, image).await?;
        let mut file = config::read(&self.home)?;
        let mut patched = current;
        patched.images.retain(|approved| approved != image);
        // 撤销之后这份清单仍然必须自洽：重复项、空串之类的问题不能靠一次缩小蒙过去。
        config::validate_node(&patched)?;
        let index = file
            .nodes
            .iter()
            .position(|node| node.name == name)
            .expect("the node was just located");
        file.nodes[index] = patched.clone();
        config::validate(&file)?;
        config::save(&self.home, &file)?;
        {
            let mut nodes = self.nodes.write().await;
            if let Some(entry) = nodes.iter_mut().find(|node| node.name == name) {
                *entry = patched.clone();
            }
        }
        // 撤销会让排在后面的任务变得「前面那个已经跑不了」，队列需要重算一次。
        self.wake_queue();
        Ok((patched, true))
    }

    /// 这张镜像是否正由这台节点上的活动任务执行。
    ///
    /// 只看「最末一次尝试 + 未终止」：更早的尝试已经收尾，它的容器不该再存在。
    async fn ensure_image_not_running(&self, name: &str, image: &str) -> Result<()> {
        let jobs = self.jobs.lock().await;
        let running = jobs.values().find(|job| {
            !job.phase.terminal()
                && job.build.image == image
                && job
                    .attempts
                    .last()
                    .is_some_and(|attempt| attempt.node == name)
        });
        let running = running.map(|job| (job.id, job.build.image.clone()));
        drop(jobs);
        if let Some((id, image)) = running {
            anyhow::bail!(
                "{image} is still running on {name} (job {id}); cancel it or wait for confirmed completion before revoking the approval"
            );
        }
        Ok(())
    }

    /// 控制面内存里的节点是否仍是 `config.toml` 里的那一份。
    ///
    /// 在线改动（`update_node`、`prepare_node`、`revoke_node_image`）都以此为前提：
    /// 手改过的配置要先重启加载，否则「落盘」会把别人的修改整份覆盖掉。
    async fn ensure_config_matches_memory(&self, current: &Node) -> Result<()> {
        let file = config::read(&self.home)?;
        let stored = file
            .nodes
            .iter()
            .find(|node| node.name == current.name)
            .cloned()
            .context("unknown node in config.toml")?;
        ensure!(
            stored == *current,
            "nodes/{} was edited outside the controller; restart the controller to load config.toml before changing it online",
            current.name
        );
        Ok(())
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

    /// 禁用一个仍持有活动任务的节点会让那份容器失去归属；必须在改动前拒绝。
    async fn ensure_no_active_job(&self, name: &str) -> Result<()> {
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
        Ok(())
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
            owner: None,
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
