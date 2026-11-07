use crate::{
    archive,
    config::{Build, Node},
    isolation, lifecycle,
    model::{Attempt, Job, Phase, now, queue_precedes},
    probe, scheduler,
    state::State,
    transport, watchdog,
};
use anyhow::{Context, Result, bail, ensure};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, OwnedSemaphorePermit, watch},
};
use uuid::Uuid;

fn docker(args: &[String]) -> String {
    format!("docker {}", transport::words(args))
}
/// `docker exec` 的结束方式；停止原因与被停止的命令分开记录。
///
/// `stop` 表示「我们主动请求停止」，`stop_confirmed` 才表示「远端确实停了」。
/// 两者不能合并：请求发出但无法确认时，任务既不是成功也不是干净取消。
struct Execution {
    code: i32,
    stop: Option<lifecycle::StopCause>,
    stop_confirmed: bool,
}
/// 一次尝试的可审计结果。停止原因决定终态，不能靠退出码猜测。
struct RunResult {
    outcome: String,
    code: Option<i32>,
    artifacts: bool,
    stop: Option<lifecycle::StopCause>,
    stop_confirmed: bool,
}
impl RunResult {
    fn from_execution(execution: Execution, artifacts: bool) -> Self {
        match execution.stop {
            Some(cause) => Self {
                outcome: format!("{}; remote container stopped", cause.as_str()),
                code: None,
                artifacts: false,
                stop: Some(cause),
                stop_confirmed: execution.stop_confirmed,
            },
            None => Self {
                outcome: format!("exit {}", execution.code),
                code: Some(execution.code),
                artifacts,
                stop: None,
                stop_confirmed: false,
            },
        }
    }
    /// 控制面自己失败（SSH 掉线、隔离校验拒绝）时没有停止原因，也不是取消。
    fn failed(error: &anyhow::Error) -> Self {
        Self {
            outcome: format!("{error:#}"),
            code: None,
            artifacts: false,
            stop: None,
            stop_confirmed: false,
        }
    }
}
/// 清理确认、幂等和禁网同时成立时，才允许在另一台 Worker 上重新执行。
fn failover_allowed(
    execution_failed: bool,
    cleanup_confirmed: bool,
    attempts: usize,
    build: &Build,
) -> bool {
    cleanup_confirmed
        && execution_failed
        && attempts <= build.retries
        && build.idempotent
        && !build.network
}
/// 清理时同时校验不可猜测的任务标识和容器标签，不接受外部路径。
async fn remove(node: &Node, id: Uuid, container: &str) -> Result<()> {
    let inspect = format!(
        "docker inspect --format {} {}",
        transport::quote("{{index .Config.Labels \"io.sshpool.job\"}}"),
        transport::quote(container)
    );
    let (code, output, error) = transport::capture(node, &inspect, 15).await?;
    if code != 0 {
        let error = String::from_utf8_lossy(&error).to_lowercase();
        if error.contains("no such object") || error.contains("no such container") {
            return Ok(());
        }
        bail!("cannot confirm container identity: {error}");
    }
    ensure!(
        String::from_utf8_lossy(&output).trim() == id.to_string(),
        "container label mismatch; refusing removal"
    );
    transport::checked(
        node,
        &format!("docker rm -f {}", transport::quote(container)),
        20,
    )
    .await?;
    Ok(())
}
async fn log_stream(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    output: Arc<Mutex<(tokio::fs::File, u64)>>,
    limit: u64,
) -> Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        let mut output = output.lock().await;
        ensure!(output.1 + count as u64 <= limit, "log quota exceeded");
        output.0.write_all(&buffer[..count]).await?;
        output.1 += count as u64;
    }
}
async fn execute(
    state: &Arc<State>,
    id: Uuid,
    node: &Node,
    container: &str,
    build: &Build,
    deadline: u64,
) -> Result<Execution> {
    let mut args = vec!["exec".into(), container.into()];
    args.extend(build.command.clone());
    let mut child = transport::spawn(node, &docker(&args))?;
    let stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.dir(id).join("log.txt"))
        .await?;
    let length = file.metadata().await?.len();
    let output = Arc::new(Mutex::new((file, length)));
    let limit = state.config.max_log_mib * 1048576;
    let run = async {
        let (status, _, _) = tokio::try_join!(
            async { Ok::<_, anyhow::Error>(child.wait().await?) },
            log_stream(stdout, output.clone(), limit),
            log_stream(stderr, output, limit)
        )?;
        Ok::<_, anyhow::Error>(status.code().unwrap_or(255))
    };
    tokio::pin!(run);
    // 取消或到期时先向远端请求停止，再等 `docker exec` 客户端退出。
    // 只杀掉本机 SSH 客户端不会停止远端进程，任务会继续占配额并继续写产物。
    let report = loop {
        tokio::select! {
            result = &mut run => {
                return Ok(Execution { code: result?, stop: None, stop_confirmed: false });
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                let cause = if state.cancelled(id).await {
                    lifecycle::StopCause::ClientCancel
                } else if now() >= deadline {
                    lifecycle::StopCause::Deadline
                } else {
                    continue;
                };
                let requested = lifecycle::request_stop(
                    node,
                    id,
                    container,
                    lifecycle::STOP_GRACE_SECS,
                )
                .await;
                break (cause, lifecycle::describe(cause, &requested));
            }
        }
    };
    state.event(id, "stop_requested", &report.1.detail).await?;
    let code = match tokio::time::timeout(Duration::from_secs(lifecycle::EXEC_DRAIN_SECS), &mut run)
        .await
    {
        // 客户端被信号杀掉时退出码没有意义；停止结论以上一步的状态读取为准。
        Ok(Ok(code)) => code,
        Ok(Err(_)) | Err(_) => 143,
    };
    Ok(Execution {
        code,
        stop: Some(report.0),
        stop_confirmed: report.1.confirmed,
    })
}
async fn collect(
    state: &State,
    id: Uuid,
    node: &Node,
    container: &str,
    build: &Build,
) -> Result<bool> {
    if build.outputs.is_empty() {
        return Ok(false);
    }
    let mut args = vec![
        "exec".into(),
        container.into(),
        "tar".into(),
        "-cf".into(),
        "-".into(),
        "--".into(),
    ];
    args.extend(build.outputs.clone());
    let mut child = transport::spawn(node, &docker(&args))?;
    let mut stdout = child.stdout.take().context("missing output")?;
    let mut stderr = child.stderr.take().context("missing errors")?;
    let archive = state.dir(id).join("artifacts.partial");
    let mut file = tokio::fs::File::create(&archive).await?;
    let limit = state.config.max_artifact_mib * 1048576;
    let transfer = async {
        let size = tokio::io::copy(&mut (&mut stdout).take(limit + 1), &mut file).await?;
        ensure!(size <= limit, "artifact quota exceeded");
        file.flush().await?;
        Ok::<_, anyhow::Error>(())
    };
    let errors = async {
        let mut errors = Vec::new();
        (&mut stderr).take(65536).read_to_end(&mut errors).await?;
        Ok::<_, anyhow::Error>(errors)
    };
    let operation = async {
        let (_, errors, status) = tokio::try_join!(transfer, errors, async {
            Ok::<_, anyhow::Error>(child.wait().await?)
        })?;
        ensure!(
            status.success(),
            "artifact export failed: {}",
            String::from_utf8_lossy(&errors)
        );
        archive::validate(&archive, limit, Some(&build.outputs))?;
        tokio::fs::rename(&archive, state.dir(id).join("artifacts.tar")).await?;
        Ok::<_, anyhow::Error>(true)
    };
    match tokio::time::timeout(Duration::from_secs(60), operation).await {
        Ok(result) => result,
        Err(_) => bail!("artifact export timed out"),
    }
}
/// 在阶段边界上检查是否已经需要停止；返回原因时调用方应立即收尾。
///
/// 取消可能落在「容器已创建但还没启动」或「源码导入中」这些窗口里。只在
/// `execute` 内每秒轮询会让这些窗口等到启动之后才生效，白跑一次完整构建。
async fn pending_stop(state: &Arc<State>, id: Uuid, deadline: u64) -> Option<lifecycle::StopCause> {
    if state.cancelled(id).await {
        Some(lifecycle::StopCause::ClientCancel)
    } else if now() >= deadline {
        Some(lifecycle::StopCause::Deadline)
    } else {
        None
    }
}
async fn attempt(
    state: &Arc<State>,
    id: Uuid,
    node: &Node,
    container: &str,
    build: &Build,
    deadline: u64,
) -> Result<(Execution, bool)> {
    state.event(id, "image_check", &node.name).await?;
    // 默认只用预先准备好的镜像，避免构建请求在业务磁盘上触发无限拉取。
    let image = transport::checked(
        node,
        &format!("docker image inspect {}", transport::quote(&build.image)),
        15,
    )
    .await?;
    let images: Vec<serde_json::Value> = serde_json::from_slice(&image)?;
    let image = images.first().context("missing image metadata")?;
    let arch = image["Architecture"]
        .as_str()
        .context("missing image architecture")?;
    ensure!(
        build.platform == format!("linux/{}", probe::platform_arch(arch)),
        "image architecture does not match requested platform"
    );
    ensure!(
        image["Config"]["Volumes"]
            .as_object()
            .is_none_or(|volumes| volumes.is_empty()),
        "images declaring VOLUME are not allowed: use a build image without persistent volumes"
    );
    // 已经取消或到期时连容器都不必创建：省掉一次完整创建/校验往返。
    if let Some(cause) = pending_stop(state, id, deadline).await {
        // 容器尚未创建，等价于远端确认「不存在」，因此停止是可信的。
        return Ok((
            Execution {
                code: 0,
                stop: Some(cause),
                stop_confirmed: true,
            },
            false,
        ));
    }
    state.event(id, "container_create", &node.name).await?;
    let args = isolation::container_args(id, container, build);
    transport::checked(node, &docker(&args), 20).await?;
    // 命令行声明可能被 Docker 改写（例如 tmpfs 默认 noexec）；启动前按真实配置复核，
    // 任何一项不满足就停在 Created 状态，由调用方的清理路径删除。
    isolation::verify_created(node, container, id, build).await?;
    // 容器仍停在 Created：此时没有任何进程可停止，直接按「从未启动」收尾。
    if let Some(cause) = pending_stop(state, id, deadline).await {
        return Ok((
            Execution {
                code: 0,
                stop: Some(cause),
                stop_confirmed: true,
            },
            false,
        ));
    }
    transport::checked(
        node,
        &format!("docker start {}", transport::quote(container)),
        20,
    )
    .await?;
    // 容器 PID1 只是 `sleep timeout+grace`；把真实启动时刻换算成租约到期并立即持久化，
    // 这样即使之后 SSH 掉线，也有一条不依赖远端连接的终止证据。
    let lease = watchdog::started_at(node, container)
        .await
        .map(|started| started.saturating_add(build.timeout_secs + watchdog::LEASE_GRACE_SECS));
    record_watchdog_deadline(state, id, container, lease).await?;
    let import = format!(
        "docker exec -i {} sh -c {}",
        transport::quote(container),
        transport::quote("tar -xf - -C /work && mkdir -p /work/.home")
    );
    state.event(id, "source_import", &node.name).await?;
    transport::upload(node, &import, &state.dir(id).join("source.tar")).await?;
    // 导入可能耗时较久（大归档）；在启动命令前再确认一次，避免白跑。
    if let Some(cause) = pending_stop(state, id, deadline).await {
        let requested =
            lifecycle::request_stop(node, id, container, lifecycle::STOP_GRACE_SECS).await;
        let report = lifecycle::describe(cause, &requested);
        state.event(id, "stop_requested", &report.detail).await?;
        return Ok((
            Execution {
                code: 0,
                stop: Some(cause),
                stop_confirmed: report.confirmed,
            },
            false,
        ));
    }
    state.event(id, "execution", &node.name).await?;
    let execution = execute(state, id, node, container, build, deadline).await?;
    if execution.code == 255 && execution.stop.is_none() {
        bail!("SSH connection interrupted; remote completion unknown");
    }
    // 被取消或到期停止的执行不导出产物：结果已经不属于这次请求。
    let artifacts = if execution.code == 0 && execution.stop.is_none() {
        state.event(id, "artifact_export", &node.name).await?;
        collect(state, id, node, container, build).await?
    } else {
        false
    };
    Ok((execution, artifacts))
}
/// 立即发布看门狗租约；读取启动时刻失败时保持为空，等价于「暂无终止证据」。
async fn record_watchdog_deadline(
    state: &Arc<State>,
    id: Uuid,
    container: &str,
    deadline: Result<u64>,
) -> Result<()> {
    let mut candidate = state
        .jobs
        .lock()
        .await
        .get(&id)
        .cloned()
        .context("unknown job")?;
    let Some(attempt) = candidate
        .attempts
        .iter_mut()
        .find(|attempt| attempt.container == container)
    else {
        return Ok(());
    };
    match deadline {
        Ok(value) => attempt.watchdog_deadline = Some(value),
        Err(error) => {
            attempt.watchdog_deadline = None;
            state
                .event(id, "watchdog_unavailable", &format!("{error:#}"))
                .await?;
        }
    }
    state.checkpoint_candidate(candidate).await?;
    Ok(())
}

/// 已经执行过本任务的 Worker；重跑只能换机器，不能回到旧机器。
///
/// 不按 `outcome` 过滤：控制面在容器仍运行时崩溃会留下 `outcome: None`，
/// 那台机器同样执行过本次任务，必须继续排除。
fn attempted_nodes(job: &Job) -> Vec<String> {
    job.attempts
        .iter()
        .map(|attempt| attempt.node.clone())
        .collect()
}

async fn mark_queue_waiting(state: &State, id: Uuid, reason: &str) -> Result<()> {
    let mut candidate = state
        .jobs
        .lock()
        .await
        .get(&id)
        .cloned()
        .context("unknown job")?;
    candidate.phase = Phase::Queued;
    candidate.message = Some(format!("waiting for an eligible worker: {reason}"));
    state.checkpoint_candidate(candidate).await?;
    Ok(())
}

async fn queue_deadline(state: &State, id: Uuid) -> Option<u64> {
    state
        .jobs
        .lock()
        .await
        .get(&id)
        .and_then(|job| job.queue_deadline)
}

/// 所有队列都使用同一资源快照，较早且在此快照中可运行的任务必须先领取资源。
fn earlier_job_is_eligible(
    jobs: &std::collections::HashMap<Uuid, Job>,
    id: Uuid,
    nodes: &[Node],
    health: &[crate::model::Health],
    active: &[Job],
    timestamp: u64,
) -> bool {
    let Some(current) = jobs.get(&id) else {
        return false;
    };
    jobs.values()
        .filter(|job| job.id != id && job.queue_open_at(timestamp) && queue_precedes(job, current))
        .any(|job| {
            nodes
                .iter()
                .zip(health)
                .any(|(node, health)| scheduler::score(node, health, &job.build, active).is_ok())
        })
}

async fn wait_for_queue_change(receiver: &mut watch::Receiver<u64>, deadline: u64) -> Result<()> {
    let remaining = deadline.saturating_sub(now());
    let delay = Duration::from_secs(remaining.min(30));
    tokio::select! {
        changed = receiver.changed() => {
            changed.context("queue wake channel closed")?;
            Ok(())
        }
        _ = tokio::time::sleep(delay) => Ok(()),
    }
}

fn source_can_resume(state: &State, job: &Job) -> Result<()> {
    let source = state.dir(job.id).join("source.tar");
    ensure!(source.is_file(), "source archive is missing");
    let limit = state.config.max_upload_mib * 1048576;
    archive::validate(&source, limit, None)?;
    let expected = job
        .source_sha256
        .as_deref()
        .context("source digest is missing")?;
    let actual = archive::sha256_file(&source)?;
    ensure!(actual == expected, "source digest does not match");
    Ok(())
}

pub async fn run(state: Arc<State>, id: Uuid) -> Result<()> {
    let build = state
        .jobs
        .lock()
        .await
        .get(&id)
        .context("unknown job")?
        .build
        .clone();
    let mut queue_receiver = state.queue_changed();
    let mut wait_event_recorded = false;
    // 已执行过的节点不能再次接单，否则重试额度会被绕过；
    // 恢复后的重跑也必须继承历史，而不是从零开始计次。
    // 不按 `outcome` 过滤：控制面在容器仍运行时崩溃会留下 `outcome: None`，
    // 那台机器同样已经执行过本次任务，绝不能再被选中。
    let mut tried = state
        .jobs
        .lock()
        .await
        .get(&id)
        .map(attempted_nodes)
        .unwrap_or_default();
    loop {
        if state.cancelled(id).await {
            return state
                .finish(id, Phase::Cancelled, None, "cancelled".into(), false)
                .await;
        }
        let guard = state.scheduling.lock().await;
        let nodes = state.nodes().await;
        let health = probe::all(&nodes).await;
        let active = state
            .jobs
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let current = state
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .context("unknown job")?;
        let first_attempt = current.attempts.is_empty();
        if first_attempt
            && current.build.queue_timeout_secs > 0
            && current
                .queue_deadline
                .is_some_and(|deadline| now() >= deadline)
        {
            drop(guard);
            return state
                .finish(
                    id,
                    Phase::Failed,
                    None,
                    "queue deadline exceeded before worker assignment".into(),
                    false,
                )
                .await;
        }
        let queue_open = current.queue_open_at(now());
        let earlier_ready = queue_open && {
            let jobs = state.jobs.lock().await;
            earlier_job_is_eligible(&jobs, id, &nodes, &health, &active, now())
        };
        let mut reasons = Vec::new();
        let mut candidates = Vec::new();
        for (node, health) in nodes.iter().zip(&health) {
            // 重试只换机器：这台 Worker 已经执行过本次任务，不能再接单。
            if tried.contains(&node.name) {
                reasons.push(format!(
                    "{}: already attempted this job; retries only switch workers",
                    node.name
                ));
                continue;
            }
            match scheduler::score(node, health, &build, &active) {
                Ok(score) => candidates.push((node.clone(), score)),
                Err(reason) => reasons.push(format!("{}: {reason}", node.name)),
            }
        }
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1));
        if earlier_ready {
            reasons.push("higher-priority queue item is eligible".into());
        }
        // 原因列表为空会让消息显示成「no eligible worker: 」；兜底说明必须有内容。
        if reasons.is_empty() {
            reasons.push(if tried.is_empty() {
                "no workers are configured".into()
            } else {
                format!(
                    "all workers already attempted ({}); reservations and quarantine still apply",
                    tried.join(", ")
                )
            });
        }
        let Some((node, _)) = candidates.into_iter().next() else {
            drop(guard);
            if first_attempt && queue_open {
                if !wait_event_recorded {
                    let reason = reasons.join("; ");
                    mark_queue_waiting(&state, id, &reason).await?;
                    state.event(id, "queue_wait", &reason).await?;
                    wait_event_recorded = true;
                }
                let deadline = queue_deadline(&state, id)
                    .await
                    .context("queue deadline is missing")?;
                if now() >= deadline {
                    return state
                        .finish(
                            id,
                            Phase::Failed,
                            None,
                            "queue deadline exceeded while waiting for an eligible worker".into(),
                            false,
                        )
                        .await;
                }
                wait_for_queue_change(&mut queue_receiver, deadline).await?;
                continue;
            }
            return state
                .finish(
                    id,
                    Phase::Failed,
                    None,
                    format!("no eligible worker: {}", reasons.join("; ")),
                    false,
                )
                .await;
        };
        if earlier_ready {
            drop(guard);
            wait_for_queue_change(
                &mut queue_receiver,
                queue_deadline(&state, id)
                    .await
                    .context("queue deadline is missing")?,
            )
            .await?;
            continue;
        }
        tried.push(node.name.clone());
        let container = format!("sshpool-{id}-{}", tried.len());
        let mut assigned = current;
        assigned.phase = Phase::Running;
        assigned.cleanup_confirmed = false;
        assigned.attempts.push(Attempt {
            node: node.name.clone(),
            container: container.clone(),
            started_at: now(),
            outcome: None,
            cleanup_confirmed: None,
            // 容器尚未启动，还不存在可用的租约；启动后立即补写。
            watchdog_deadline: None,
            cleanup_proof: None,
        });
        // 创建远端容器前先达到状态 quorum；失败时仍保持未领取状态。
        state.checkpoint_candidate(assigned).await?;
        drop(guard);
        state.event(id, "assigned", &node.name).await?;
        // 执行期限从派发时刻起算；`execute` 每秒核对，到期时向远端请求停止，
        // 而不是只杀掉本机 SSH 客户端。外层超时只是最后兜底，正常路径不会触发。
        let deadline = now().saturating_add(build.timeout_secs);
        let backstop = Duration::from_secs(
            build.timeout_secs + lifecycle::STOP_GRACE_SECS + lifecycle::EXEC_DRAIN_SECS + 60,
        );
        let executed = tokio::time::timeout(
            backstop,
            attempt(&state, id, &node, &container, &build, deadline),
        )
        .await;
        // 控制面侧失败（SSH 掉线、隔离校验拒绝）与被停止的执行都收敛成同一种记录，
        // 区别只体现在 `stop`：有停止原因时终态由原因决定，没有时才可能换机重试。
        let (result, failure) = match executed {
            Ok(Ok((execution, artifacts))) => {
                (RunResult::from_execution(execution, artifacts), false)
            }
            Ok(Err(error)) => (RunResult::failed(&error), true),
            // 连停止请求都没能在兜底期限内完成：不能宣称远端已经停下。
            Err(_) => (
                RunResult::failed(&anyhow::anyhow!(
                    "execution backstop expired; remote stop not confirmed"
                )),
                true,
            ),
        };
        let cleanup = remove(&node, id, &container).await;
        state
            .event(
                id,
                "cleanup",
                if cleanup.is_ok() {
                    "confirmed"
                } else {
                    "unconfirmed"
                },
            )
            .await?;
        let outcome = result.outcome.clone();
        let mut completed = state
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .context("unknown job")?;
        completed.cleanup_confirmed = cleanup.is_ok();
        if let Some(attempt) = completed.attempts.last_mut() {
            attempt.outcome = Some(outcome.clone());
            attempt.cleanup_confirmed = Some(cleanup.is_ok());
        }
        // 重试或终态发布前先记录本次尝试与清理结果。
        state.checkpoint_candidate(completed).await?;
        if let Err(error) = cleanup {
            // SSH 超时不能证明旧容器已经停止。缺少远端看门狗确认时禁止换机重跑，
            // 否则两个执行者可能同时生成或提交结果。
            return state
                .finish(
                    id,
                    Phase::Interrupted,
                    None,
                    format!(
                        "{outcome}; cleanup unconfirmed: {error:#}. Worker quarantined until `sshpool node reconcile {}` proves the old container is gone",
                        node.name
                    ),
                    false,
                )
                .await;
        }
        // 已确认停止就不再看退出码，也不再参与重试：停止原因本身就是终态理由。
        let cancel_requested = state.cancelled(id).await;
        if result.stop.is_some() && !result.stop_confirmed {
            // 停止请求发出但没有拿到「已停止」的证据：既不能算取消成功，
            // 也不能换机重跑，否则旧进程可能与新尝试同时提交结果。
            return state
                .finish(
                    id,
                    Phase::Interrupted,
                    None,
                    format!(
                        "{outcome}; remote stop unconfirmed on {}; quarantine until `sshpool node reconcile {}` proves the container is gone",
                        node.name, node.name
                    ),
                    false,
                )
                .await;
        }
        if let Some(cause) = result.stop {
            return match cause {
                lifecycle::StopCause::ClientCancel => {
                    state
                        .finish(
                            id,
                            Phase::Cancelled,
                            None,
                            format!("cancelled by client; {outcome} and removed"),
                            false,
                        )
                        .await
                }
                // 期限届满是确定的失败，重试只会再烧一次同样的时间。
                lifecycle::StopCause::Deadline => {
                    state
                        .finish(
                            id,
                            Phase::Failed,
                            None,
                            format!("job deadline exceeded; {outcome} and removed"),
                            false,
                        )
                        .await
                }
            };
        }
        if let Some(code) = result.code {
            // 命令在自己结束时，停止请求可能刚好晚一步到达；照实报告执行结果，
            // 不把已经完成的任务改写成「取消」。
            let late = if cancel_requested {
                " (cancel arrived after the command finished)"
            } else {
                ""
            };
            return state
                .finish(
                    id,
                    if code == 0 {
                        Phase::Succeeded
                    } else {
                        Phase::Failed
                    },
                    Some(code),
                    format!("{outcome}{late}"),
                    result.artifacts,
                )
                .await;
        }
        // 走到这里说明没有观察到退出码：要么控制面侧失败，要么停止没能确认。
        if cancel_requested && !failure {
            return state
                .finish(
                    id,
                    Phase::Interrupted,
                    None,
                    format!(
                        "{outcome}; cancellation not confirmed on {}. Run `sshpool node reconcile {}` once the container is proven stopped",
                        node.name, node.name
                    ),
                    false,
                )
                .await;
        }
        // 控制面侧失败里只有「清理已确认 + 幂等禁网 + 仍有额度」才允许换机。
        if !failover_allowed(true, true, tried.len(), &build) {
            return state.finish(id, Phase::Failed, None, outcome, false).await;
        }
    }
}

/// 在独立任务中持有上传配额；控制器错误只会中断仍未落入终态的任务。
pub fn spawn_job(state: Arc<State>, id: Uuid, permit: OwnedSemaphorePermit) {
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(error) = run(state.clone(), id).await {
            let should_finish = state
                .jobs
                .lock()
                .await
                .get(&id)
                .is_some_and(|job| !job.phase.terminal());
            if should_finish
                && let Err(save_error) = state
                    .finish(
                        id,
                        Phase::Interrupted,
                        None,
                        format!("controller error: {error:#}"),
                        false,
                    )
                    .await
            {
                let artifacts = state.local_artifacts_available(id);
                if let Err(local_error) = state
                    .finish_local(
                        id,
                        Phase::Interrupted,
                        None,
                        format!(
                            "durability quorum failed: {save_error:#}; local artifacts retained={artifacts}"
                        ),
                        artifacts,
                    )
                    .await
                {
                    eprintln!("cannot save failure for {id}: {local_error:#}");
                }
            }
        }
    });
}

/// 控制面重启只恢复仍处于原始等待期限内且源码完整的未领取任务。
pub async fn recover(state: &Arc<State>) -> Result<()> {
    let unfinished = state
        .jobs
        .lock()
        .await
        .values()
        .filter(|job| {
            !job.phase.terminal() || (job.phase == Phase::Interrupted && !job.cleanup_confirmed)
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut queued = Vec::new();
    for job in unfinished {
        if job.phase == Phase::Queued && job.cancel_requested {
            state
                .finish(
                    job.id,
                    Phase::Cancelled,
                    None,
                    "cancelled while queued before controller restart".into(),
                    false,
                )
                .await?;
            continue;
        }
        let can_retain = job.queue_open_at(now()) && source_can_resume(state, &job).is_ok();
        if can_retain {
            let mut candidate = job.clone();
            candidate.cleanup_confirmed = true;
            candidate.message =
                Some("controller restarted; queue retained with the original deadline".into());
            state.checkpoint_candidate(candidate).await?;
            state
                .event(
                    job.id,
                    "queue_recovered",
                    "source validated; original deadline retained",
                )
                .await?;
            queued.push(job);
            continue;
        }
        let mut cleanups = Vec::new();
        for attempt in &job.attempts {
            let cleanup = match state
                .config
                .nodes
                .iter()
                .find(|node| node.name == attempt.node)
            {
                Some(node) => remove(node, job.id, &attempt.container).await,
                None => Err(anyhow::anyhow!("worker removed from configuration")),
            };
            // 删除失败时先看容器租约：PID1 的 `sleep` 到期即证明没有进程可以继续提交结果，
            // 这比"重启控制面才能解隔离"更早、也更有依据。
            cleanups.push(match cleanup {
                Ok(()) => Ok(None),
                Err(error) => {
                    let proven = watchdog::decide(
                        attempt,
                        Err(format!("{error:#}")),
                        now(),
                        crate::reconcile::LEASE_CLOCK_SKEW_SECS,
                    );
                    if proven.proven {
                        Ok(proven.proof)
                    } else {
                        Err(error)
                    }
                }
            });
        }
        let confirmed = cleanups.iter().all(Result::is_ok);
        let errors = cleanups
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(|error| format!("{error:#}"))
            .collect::<Vec<_>>();
        let message = if errors.is_empty() {
            "controller restarted; all prior containers absent, removed, or past their watchdog lease"
                .into()
        } else {
            format!(
                "controller restarted; cleanup unconfirmed: {}; run `sshpool node reconcile` after the watchdog lease expires",
                errors.join("; ")
            )
        };
        let mut candidate = state
            .jobs
            .lock()
            .await
            .get(&job.id)
            .cloned()
            .context("unknown job")?;
        candidate.cleanup_confirmed = confirmed;
        for (attempt, cleanup) in candidate.attempts.iter_mut().zip(&cleanups) {
            attempt.cleanup_confirmed = Some(cleanup.is_ok());
            attempt.cleanup_proof = cleanup
                .as_ref()
                .ok()
                .and_then(|proof| *proof)
                .map(|proof| proof.as_str().to_string());
        }
        state.checkpoint_candidate(candidate).await?;
        state
            .finish(job.id, Phase::Interrupted, None, message, false)
            .await?;
    }
    queued.sort_by(|left, right| {
        if queue_precedes(left, right) {
            std::cmp::Ordering::Less
        } else if queue_precedes(right, left) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    for job in queued {
        let Ok(permit) = state.uploads.clone().try_acquire_owned() else {
            state
                .finish(
                    job.id,
                    Phase::Interrupted,
                    None,
                    "controller restart found no active-job capacity for the persistent queue; increase max_active_jobs and restart again".into(),
                    false,
                )
                .await?;
            continue;
        };
        spawn_job(state.clone(), job.id, permit);
    }
    Ok(())
}
pub fn read_build(path: &Path) -> Result<Build> {
    let build: Build = toml::from_str(&std::fs::read_to_string(path)?)?;
    build.validate()?;
    Ok(build)
}

#[cfg(test)]
mod tests {
    use super::{Execution, RunResult, attempted_nodes, failover_allowed};
    use crate::{
        config::Build,
        model::{Attempt, Job, Phase},
    };

    fn job_with_attempts(attempts: Vec<Attempt>) -> Job {
        Job {
            id: uuid::Uuid::new_v4(),
            revision: 0,
            build: Build::default(),
            phase: Phase::Interrupted,
            created_at: 0,
            finished_at: Some(0),
            attempts,
            exit_code: None,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: false,
            queue_deadline: None,
            source_sha256: None,
        }
    }

    fn attempt(node: &str, outcome: Option<&str>) -> Attempt {
        Attempt {
            node: node.into(),
            container: format!("sshpool-{node}-1"),
            started_at: 0,
            outcome: outcome.map(str::to_string),
            cleanup_confirmed: None,
            watchdog_deadline: None,
            cleanup_proof: None,
        }
    }

    /// 被停止的执行没有退出码；它必须自报停止原因，否则会被当成普通失败。
    #[test]
    fn a_stopped_execution_reports_its_cause_and_no_exit_code() {
        let cancelled = RunResult::from_execution(
            Execution {
                code: 143,
                stop: Some(crate::lifecycle::StopCause::ClientCancel),
                stop_confirmed: true,
            },
            false,
        );
        assert_eq!(
            cancelled.stop,
            Some(crate::lifecycle::StopCause::ClientCancel)
        );
        assert!(cancelled.stop_confirmed);
        assert_eq!(
            cancelled.code, None,
            "a stopped command has no meaningful code"
        );
        assert!(
            !cancelled.artifacts,
            "a stopped job must not publish artifacts"
        );

        let expired = RunResult::from_execution(
            Execution {
                code: 143,
                stop: Some(crate::lifecycle::StopCause::Deadline),
                stop_confirmed: false,
            },
            false,
        );
        // 请求了停止但没拿到证据，必须与「已确认停止」区分开。
        assert!(!expired.stop_confirmed);
    }

    /// 正常结束的执行没有停止原因，退出码与产物照常返回。
    #[test]
    fn a_normal_execution_keeps_its_exit_code() {
        let finished = RunResult::from_execution(
            Execution {
                code: 0,
                stop: None,
                stop_confirmed: false,
            },
            true,
        );
        assert_eq!(finished.code, Some(0));
        assert!(finished.artifacts);
        assert!(finished.stop.is_none());
        assert_eq!(finished.outcome, "exit 0");
    }

    /// 控制面在容器仍运行时崩溃会留下 `outcome: None`；那台机器同样执行过任务。
    #[test]
    fn attempted_nodes_include_attempts_without_a_recorded_outcome() {
        let job = job_with_attempts(vec![
            attempt("first", Some("SSH connection interrupted")),
            attempt("second", None),
        ]);
        assert_eq!(attempted_nodes(&job), vec!["first", "second"]);
        assert!(attempted_nodes(&job_with_attempts(Vec::new())).is_empty());
    }

    #[test]
    fn confirmed_cleanup_is_required_before_worker_failover() {
        let build = Build {
            retries: 1,
            idempotent: true,
            network: false,
            ..Build::default()
        };
        assert!(!failover_allowed(true, false, 1, &build));
        assert!(failover_allowed(true, true, 1, &build));
        assert!(!failover_allowed(false, true, 1, &build));
        assert!(!failover_allowed(true, true, 2, &build));
        assert!(!failover_allowed(
            true,
            true,
            1,
            &Build {
                idempotent: false,
                ..build.clone()
            }
        ));
        assert!(!failover_allowed(
            true,
            true,
            1,
            &Build {
                network: true,
                ..build
            }
        ));
    }
}
