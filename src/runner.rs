use crate::{
    archive,
    config::{Build, Node},
    model::{Attempt, Job, Phase, now, queue_precedes},
    probe, scheduler,
    state::State,
    transport,
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
fn container_args(id: Uuid, name: &str, build: &Build) -> Vec<String> {
    let mut args = vec![
        "create".into(),
        "--name".into(),
        name.into(),
        "--label".into(),
        format!("io.sshpool.job={id}"),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--user=65534:65534".into(),
        "--init".into(),
        format!("--memory={}m", build.memory_mib),
        format!("--memory-swap={}m", build.memory_mib),
        format!("--cpus={}", build.cpus),
        format!("--pids-limit={}", build.pids),
        "--ulimit=nofile=1024:1024".into(),
        "--ulimit=core=0:0".into(),
        "--restart=no".into(),
        "--log-driver=none".into(),
        format!("--platform={}", build.platform),
        format!(
            "--network={}",
            if build.network { "bridge" } else { "none" }
        ),
        format!(
            "--tmpfs=/work:rw,nosuid,nodev,size={}m,mode=1777",
            build.scratch_mib
        ),
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777".into(),
        "--workdir=/work".into(),
        "--env=HOME=/work/.home".into(),
        "--env=TMPDIR=/tmp".into(),
        "--env=CARGO_HOME=/work/.cargo".into(),
        "--env=GRADLE_USER_HOME=/work/.gradle".into(),
        "--env=npm_config_cache=/work/.npm".into(),
        "--entrypoint=/bin/sh".into(),
        build.image.clone(),
        "-c".into(),
    ];
    // 主容器有独立的最长寿命；控制面掉线时，任务也不会无限运行。
    args.push(format!("sleep {}", build.timeout_secs + 180));
    args
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
) -> Result<i32> {
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
    loop {
        tokio::select! {
            result = &mut run => return result,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if state.cancelled(id).await { bail!("cancelled by client"); }
            }
        }
    }
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
async fn attempt(
    state: &Arc<State>,
    id: Uuid,
    node: &Node,
    container: &str,
    build: &Build,
) -> Result<(i32, bool)> {
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
    state.event(id, "container_create", &node.name).await?;
    transport::checked(node, &docker(&container_args(id, container, build)), 20).await?;
    transport::checked(
        node,
        &format!("docker start {}", transport::quote(container)),
        20,
    )
    .await?;
    let import = format!(
        "docker exec -i {} sh -c {}",
        transport::quote(container),
        transport::quote("tar -xf - -C /work && mkdir -p /work/.home")
    );
    state.event(id, "source_import", &node.name).await?;
    transport::upload(node, &import, &state.dir(id).join("source.tar")).await?;
    state.event(id, "execution", &node.name).await?;
    let code = execute(state, id, node, container, build).await?;
    if code == 255 {
        bail!("SSH connection interrupted; remote completion unknown");
    }
    let artifacts = if code == 0 {
        state.event(id, "artifact_export", &node.name).await?;
        collect(state, id, node, container, build).await?
    } else {
        false
    };
    Ok((code, artifacts))
}
async fn mark_queue_waiting(state: &State, id: Uuid, reason: &str) -> Result<()> {
    let mut jobs = state.jobs.lock().await;
    let job = jobs.get_mut(&id).context("unknown job")?;
    job.phase = Phase::Queued;
    job.message = Some(format!("waiting for an eligible worker: {reason}"));
    state.persist(job)
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
    let mut tried = Vec::new();
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
            if tried.contains(&node.name) {
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
        {
            let mut jobs = state.jobs.lock().await;
            let job = jobs.get_mut(&id).context("unknown job")?;
            job.phase = Phase::Running;
            job.cleanup_confirmed = false;
            job.attempts.push(Attempt {
                node: node.name.clone(),
                container: container.clone(),
                started_at: now(),
                outcome: None,
            });
            state.persist(job)?;
        }
        drop(guard);
        state.event(id, "assigned", &node.name).await?;
        let result = tokio::time::timeout(
            Duration::from_secs(build.timeout_secs),
            attempt(&state, id, &node, &container, &build),
        )
        .await;
        let result = match result {
            Ok(value) => value,
            Err(_) => Err(anyhow::anyhow!("job deadline exceeded")),
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
        let outcome = match &result {
            Ok((code, _)) => format!("exit {code}"),
            Err(error) => format!("{error:#}"),
        };
        {
            let mut jobs = state.jobs.lock().await;
            let job = jobs.get_mut(&id).context("unknown job")?;
            job.cleanup_confirmed = cleanup.is_ok();
            if let Some(attempt) = job.attempts.last_mut() {
                attempt.outcome = Some(outcome.clone());
            }
            state.persist(job)?;
        }
        if let Err(error) = cleanup {
            return state.finish(id, Phase::Interrupted, None, format!("{outcome}; cleanup unconfirmed: {error:#}. No retry; watchdog will stop the container."), false).await;
        }
        if state.cancelled(id).await {
            return state
                .finish(
                    id,
                    Phase::Cancelled,
                    None,
                    "cancelled; remote container removed".into(),
                    false,
                )
                .await;
        }
        match result {
            Ok((code, artifacts)) => {
                return state
                    .finish(
                        id,
                        if code == 0 {
                            Phase::Succeeded
                        } else {
                            Phase::Failed
                        },
                        Some(code),
                        outcome,
                        artifacts,
                    )
                    .await;
            }
            Err(error) if tried.len() > build.retries => {
                return state
                    .finish(id, Phase::Failed, None, format!("{error:#}"), false)
                    .await;
            }
            Err(_) => {}
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
                eprintln!("cannot save failure for {id}: {save_error:#}");
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
            let mut jobs = state.jobs.lock().await;
            let record = jobs.get_mut(&job.id).context("unknown job")?;
            record.cleanup_confirmed = true;
            record.message =
                Some("controller restarted; queue retained with the original deadline".into());
            state.persist(record)?;
            drop(jobs);
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
        let cleanup = match job.attempts.last() {
            Some(attempt) => match state
                .config
                .nodes
                .iter()
                .find(|node| node.name == attempt.node)
            {
                Some(node) => remove(node, job.id, &attempt.container).await,
                None => Err(anyhow::anyhow!("worker removed from configuration")),
            },
            None => Ok(()),
        };
        let confirmed = cleanup.is_ok();
        let message = match cleanup {
            Ok(()) => "controller restarted; previous container absent or removed".into(),
            Err(error) => format!("controller restarted; cleanup unconfirmed: {error:#}"),
        };
        {
            let mut jobs = state.jobs.lock().await;
            let record = jobs.get_mut(&job.id).context("unknown job")?;
            record.cleanup_confirmed = confirmed;
            state.persist(record)?;
        }
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
