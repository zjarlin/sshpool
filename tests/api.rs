use anyhow::Result;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use sshpool::{
    config::{Build, Config, Node},
    model::{Attempt, Job, Phase, now},
    state::State,
};
use std::{fs, sync::Arc, time::Duration};
use tower::ServiceExt;

fn state() -> Result<(tempfile::TempDir, Arc<State>)> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let config = Config {
        min_free_disk_mib: 0,
        max_upload_mib: 1,
        max_artifact_mib: 1,
        max_log_mib: 1,
        max_active_jobs: 1,
        nodes: ["test-node", "second-node"]
            .into_iter()
            .map(test_node)
            .collect(),
        ..Config::default()
    };
    fs::write(
        root.path().join("config.toml"),
        toml::to_string_pretty(&config)?,
    )?;
    let state = State::load(root.path().into(), config)?;
    Ok((root, state))
}

fn test_node(name: &str) -> Node {
    Node {
        name: name.into(),
        ssh: "127.0.0.1".into(),
        images: vec!["alpine:3.22".into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
    }
}

fn active_job(node: &str) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: Build::default(),
        phase: Phase::Running,
        created_at: 0,
        finished_at: None,
        attempts: vec![Attempt {
            node: node.into(),
            container: "owned".into(),
            started_at: 0,
            outcome: None,
            cleanup_confirmed: None,
            watchdog_deadline: None,
            cleanup_proof: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
    }
}

fn queued_job(queue_timeout_secs: u64, queue_deadline: Option<u64>) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: Build {
            queue_timeout_secs,
            ..Build::default()
        },
        phase: Phase::Queued,
        created_at: now(),
        finished_at: None,
        attempts: Vec::new(),
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline,
        source_sha256: None,
    }
}

fn write_empty_source(state: &State, id: uuid::Uuid) -> Result<()> {
    let file = fs::File::create(state.dir(id).join("source.tar"))?;
    let mut archive = tar::Builder::new(file);
    archive.finish()?;
    Ok(())
}

fn source_sha256(state: &State, id: uuid::Uuid) -> Result<String> {
    sshpool::archive::sha256_file(&state.dir(id).join("source.tar"))
}

async fn wait_for_terminal(state: &State, id: uuid::Uuid) -> Result<Job> {
    for _ in 0..100 {
        let job = state
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("job disappeared"))?;
        if job.phase.terminal() {
            return Ok(job);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("job did not reach a terminal state")
}

#[tokio::test]
async fn node_switch_persists_and_rejects_an_active_job() -> Result<()> {
    let (root, state) = state()?;
    let job = active_job("test-node");
    state.jobs.lock().await.insert(job.id, job);
    assert!(state.set_node_enabled("test-node", false).await.is_err());
    let config = sshpool::config::read(root.path())?;
    assert!(config.nodes[0].enabled);
    state.jobs.lock().await.clear();
    state.set_node_enabled("test-node", false).await?;
    let config = sshpool::config::read(root.path())?;
    assert!(!config.nodes[0].enabled);
    assert!(!state.nodes().await[0].enabled);
    state.set_node_enabled("test-node", true).await?;
    assert!(state.nodes().await[0].enabled);
    Ok(())
}

#[tokio::test]
async fn sequential_node_switches_preserve_earlier_choices_after_reload() -> Result<()> {
    let (root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let config = sshpool::config::read(root.path())?;
    assert!(config.nodes.iter().all(|node| !node.enabled));
    let reloaded = State::load(state.home.clone(), config)?;
    assert!(reloaded.nodes().await.iter().all(|node| !node.enabled));
    Ok(())
}

/// 动态凭据与根 token 各自独立：撤销只看凭据库，坏文件也只影响动态凭据。
#[tokio::test]
async fn dynamic_credentials_authenticate_and_a_corrupt_store_still_denies() -> Result<()> {
    let (_root, state) = state()?;
    let app = sshpool::api::routes(state.clone());
    let (_summary, token) = sshpool::credentials::issue(&state.home, "workbench", 3_600, now())?;

    let allowed = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);

    // 撤销后同一请求 401，且不影响根 token。
    sshpool::credentials::revoke(&state.home, _summary.id, now())?;
    let denied = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let root = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(root.status(), StatusCode::OK);

    // 凭据库损坏：动态凭据一律拒绝，且是 401 而不是 500；
    // 根 token 不读该文件，所以仍然可用（控制面不会被一个坏文件锁在门外）。
    let (second, second_token) = sshpool::credentials::issue(&state.home, "laptop", 3_600, now())?;
    let store = sshpool::credentials::path(&state.home);
    fs::write(&store, b"{ not json")?;
    let broken = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {second_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(broken.status(), StatusCode::UNAUTHORIZED);
    let root = app
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(root.status(), StatusCode::OK);
    assert_eq!(second.subject, "laptop");
    Ok(())
}

#[tokio::test]
async fn node_switch_requires_authentication_and_preserves_unknown_names() -> Result<()> {
    let (_root, state) = state()?;
    let app = sshpool::api::routes(state.clone());
    let denied = app
        .clone()
        .oneshot(Request::post("/v1/nodes/test-node/disable").body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let unknown = app
        .oneshot(
            Request::post("/v1/nodes/not-present/disable")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fs::read_dir(_root.path().join("jobs"))?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn authenticated_node_switch_route_changes_the_effective_view() -> Result<()> {
    let (root, state) = state()?;
    let response = sshpool::api::routes(state.clone())
        .oneshot(
            Request::post("/v1/nodes/test-node/disable")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!state.nodes().await[0].enabled);
    assert!(!sshpool::config::read(root.path())?.nodes[0].enabled);
    Ok(())
}
#[tokio::test]
async fn unauthorized_upload_cannot_create_state() -> Result<()> {
    let (root, state) = state()?;
    let response = sshpool::api::routes(state)
        .oneshot(Request::post("/v1/jobs").body(Body::from("bad archive"))?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fs::read_dir(root.path().join("jobs"))?.count(), 0);
    Ok(())
}
#[tokio::test]
async fn malformed_and_oversized_uploads_remove_only_their_own_staging() -> Result<()> {
    let (root, state) = state()?;
    let sentinel = root.path().join("company-canary");
    fs::write(&sentinel, "untouched")?;
    for bytes in [b"not-a-tar".to_vec(), vec![0; 2 * 1048576]] {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&Build::default())?);
        let staged = tempfile::NamedTempFile::new()?;
        fs::write(staged.path(), &bytes)?;
        let digest = sshpool::archive::sha256_file(staged.path())?;
        let request = Request::post("/v1/jobs")
            .header(
                "authorization",
                "Bearer test-only-token-not-a-production-secret",
            )
            .header("x-sshpool-build", encoded)
            .header("x-sshpool-source-sha256", digest)
            .body(Body::from(bytes))?;
        let response = sshpool::api::routes(state.clone()).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fs::read_dir(root.path().join("jobs"))?.count(), 0);
    }
    assert_eq!(fs::read_to_string(sentinel)?, "untouched");
    Ok(())
}

#[tokio::test]
async fn source_digest_mismatch_cleans_staging_without_publishing_a_job() -> Result<()> {
    let (root, state) = state()?;
    let source = tempfile::NamedTempFile::new()?;
    let mut archive = tar::Builder::new(fs::File::create(source.path())?);
    archive.finish()?;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&Build::default())?);
    let response = sshpool::api::routes(state)
        .oneshot(
            Request::post("/v1/jobs")
                .header(
                    "authorization",
                    "Bearer test-only-token-not-a-production-secret",
                )
                .header("x-sshpool-build", encoded)
                .header("x-sshpool-source-sha256", "0".repeat(64))
                .body(Body::from(fs::read(source.path())?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fs::read_dir(root.path().join("jobs"))?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn limited_queue_waits_once_and_cancel_wakes_the_runner() -> Result<()> {
    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let source = tempfile::NamedTempFile::new()?;
    let mut archive = tar::Builder::new(fs::File::create(source.path())?);
    archive.finish()?;
    let build = Build {
        queue_timeout_secs: 30,
        ..Build::default()
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&build)?);
    let digest = sshpool::archive::sha256_file(source.path())?;
    let response = sshpool::api::routes(state.clone())
        .oneshot(
            Request::post("/v1/jobs")
                .header("authorization", format!("Bearer {}", state.token))
                .header("x-sshpool-build", encoded)
                .header("x-sshpool-source-sha256", &digest)
                .body(Body::from(fs::read(source.path())?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    let job: Job = serde_json::from_slice(&bytes)?;
    assert!(job.queue_deadline.is_some_and(|deadline| deadline > now()));
    assert_eq!(job.source_sha256.as_deref(), Some(digest.as_str()));
    for _ in 0..100 {
        if state
            .jobs
            .lock()
            .await
            .get(&job.id)
            .is_some_and(|current| current.message.is_some())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    state.wake_queue();
    state.wake_queue();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = fs::read_to_string(state.dir(job.id).join("events.jsonl"))?;
    assert_eq!(
        events
            .lines()
            .filter(|line| line.contains("\"queue_wait\""))
            .count(),
        1
    );
    let response = sshpool::api::routes(state.clone())
        .oneshot(
            Request::post(format!("/v1/jobs/{}/cancel", job.id))
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let finished = wait_for_terminal(&state, job.id).await?;
    assert_eq!(finished.phase, Phase::Cancelled);
    assert!(finished.attempts.is_empty());
    Ok(())
}

#[tokio::test]
async fn default_zero_queue_timeout_keeps_immediate_failure_semantics() -> Result<()> {
    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let job = Job {
        queue_deadline: None,
        ..queued_job(0, None)
    };
    fs::create_dir(state.dir(job.id))?;
    write_empty_source(&state, job.id)?;
    let digest = source_sha256(&state, job.id)?;
    let job = Job {
        source_sha256: Some(digest),
        ..job
    };
    let mut stored = job.clone();
    state.persist(&mut stored)?;
    state.jobs.lock().await.insert(job.id, job.clone());
    let permit = state
        .uploads
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("test queue slot unavailable"))?;
    sshpool::runner::spawn_job(state.clone(), job.id, permit);
    let failed = wait_for_terminal(&state, job.id).await?;
    assert_eq!(failed.phase, Phase::Failed);
    assert!(failed.attempts.is_empty());
    assert!(
        failed
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("no eligible worker")
    );
    Ok(())
}

#[tokio::test]
async fn restart_retains_only_a_valid_unexpired_queue_request() -> Result<()> {
    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let deadline = now() + 60;
    let job = queued_job(60, Some(deadline));
    fs::create_dir(state.dir(job.id))?;
    write_empty_source(&state, job.id)?;
    let digest = source_sha256(&state, job.id)?;
    let job = Job {
        source_sha256: Some(digest),
        ..job
    };
    let mut stored = job.clone();
    state.persist(&mut stored)?;
    state.jobs.lock().await.insert(job.id, job.clone());
    sshpool::runner::recover(&state).await?;
    let retained = state
        .jobs
        .lock()
        .await
        .get(&job.id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("retained job disappeared"))?;
    assert_eq!(retained.phase, Phase::Queued);
    assert_eq!(retained.queue_deadline, Some(deadline));
    let events = fs::read_to_string(state.dir(job.id).join("events.jsonl"))?;
    assert!(events.contains("\"queue_recovered\""));
    {
        let mut jobs = state.jobs.lock().await;
        let retained = jobs
            .get_mut(&job.id)
            .ok_or_else(|| anyhow::anyhow!("retained job disappeared"))?;
        retained.cancel_requested = true;
        state.persist(retained)?;
    }
    state.wake_queue();
    assert_eq!(
        wait_for_terminal(&state, job.id).await?.phase,
        Phase::Cancelled
    );
    Ok(())
}

#[tokio::test]
async fn restart_interrupts_expired_or_missing_source_queue_requests() -> Result<()> {
    for (deadline, source) in [
        (now().saturating_sub(1), Some(b"expired archive".as_slice())),
        (now() + 60, None),
        (now() + 60, Some(b"invalid archive".as_slice())),
    ] {
        let (_root, state) = state()?;
        let job = queued_job(60, Some(deadline));
        fs::create_dir(state.dir(job.id))?;
        if let Some(bytes) = source {
            fs::write(state.dir(job.id).join("source.tar"), bytes)?;
        }
        let digest = source
            .filter(|_| deadline > now())
            .map(|_| source_sha256(&state, job.id))
            .transpose()?;
        let job = Job {
            source_sha256: digest,
            ..job
        };
        let mut stored = job.clone();
        state.persist(&mut stored)?;
        state.jobs.lock().await.insert(job.id, job.clone());
        sshpool::runner::recover(&state).await?;
        let recovered = state
            .jobs
            .lock()
            .await
            .get(&job.id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("recovered job disappeared"))?;
        assert_eq!(recovered.phase, Phase::Interrupted);
        assert!(
            !recovered
                .attempts
                .iter()
                .any(|attempt| attempt.node == "test-node")
        );
    }
    Ok(())
}

#[tokio::test]
async fn enabling_a_node_wakes_queue_watchers() -> Result<()> {
    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    let changed = state.queue_changed();
    assert!(!changed.has_changed()?);
    state.set_node_enabled("test-node", true).await?;
    assert!(changed.has_changed()?);
    Ok(())
}
#[tokio::test]
async fn restart_marks_queued_work_interrupted_without_replaying_it() -> Result<()> {
    let (_root, state) = state()?;
    let job = Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: Build::default(),
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
    fs::create_dir(state.dir(job.id))?;
    let mut stored = job.clone();
    state.persist(&mut stored)?;
    state.jobs.lock().await.insert(job.id, job.clone());
    sshpool::runner::recover(&state).await?;
    let bytes = fs::read(state.dir(job.id).join("job.json"))?;
    let recovered: Job = serde_json::from_slice(&bytes)?;
    assert_eq!(recovered.phase, Phase::Interrupted);
    assert!(recovered.cleanup_confirmed);
    assert!(recovered.attempts.is_empty());
    Ok(())
}

#[tokio::test]
async fn audit_events_survive_state_reload_without_credentials() -> Result<()> {
    let (_root, state) = state()?;
    let id = uuid::Uuid::new_v4();
    fs::create_dir(state.dir(id))?;
    let job = Job {
        id,
        revision: 0,
        build: Build::default(),
        phase: Phase::Succeeded,
        created_at: 0,
        finished_at: Some(1),
        attempts: Vec::new(),
        exit_code: Some(0),
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: true,
        queue_deadline: None,
        source_sha256: None,
    };
    let mut stored = job.clone();
    state.persist(&mut stored)?;
    state.event(id, "submitted", "source validated").await?;
    state.event(id, "assigned", "worker-a").await?;
    let reloaded = State::load(state.home.clone(), state.config.clone())?;
    let app = sshpool::api::routes(reloaded);
    let denied = app
        .clone()
        .oneshot(Request::get(format!("/v1/jobs/{id}/events")).body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(
            Request::get(format!("/v1/jobs/{id}/events"))
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["kind"], "submitted");
    assert_eq!(events[1]["detail"], "worker-a");
    assert!(!text.contains(&state.token));
    Ok(())
}

fn unconfirmed_job(node: &str, deadline: Option<u64>, retries: usize) -> Job {
    let mut job = active_job(node);
    job.phase = Phase::Interrupted;
    job.finished_at = Some(1);
    job.build = Build {
        retries,
        idempotent: true,
        network: false,
        ..Build::default()
    };
    job.attempts[0].outcome = Some("SSH connection interrupted".into());
    job.attempts[0].cleanup_confirmed = Some(false);
    job.attempts[0].watchdog_deadline = deadline;
    job
}

/// 远端不可达时，唯一的终止证据是容器自带租约；到期前必须继续拒绝放行。
#[tokio::test]
async fn reconcile_waits_for_the_recorded_watchdog_lease() -> Result<()> {
    let (_root, state) = state()?;
    let job = unconfirmed_job("test-node", Some(now() + 3600), 0);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(job.id, job.clone());
    }
    let report = sshpool::reconcile::reconcile(&state, Some("test-node")).await?;
    assert_eq!(report.checked, 1);
    assert_eq!(report.proven, 0);
    assert!(report.resumed.is_empty());
    let stored = state.jobs.lock().await.get(&job.id).cloned().unwrap();
    assert_eq!(stored.attempts[0].cleanup_confirmed, Some(false));
    assert!(!stored.cleanup_confirmed);
    assert!(
        report.attempts[0]
            .detail
            .contains("watchdog lease releases in")
    );
    Ok(())
}

/// 租约到期即证明旧容器 PID1 已退出；不需要重启控制面。
#[tokio::test]
async fn reconcile_proves_an_expired_lease_without_restarting() -> Result<()> {
    let (_root, state) = state()?;
    let job = unconfirmed_job("test-node", Some(now() - 601), 0);
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(job.id, job.clone());
    }
    let report = sshpool::reconcile::reconcile(&state, Some("test-node")).await?;
    assert_eq!(report.proven, 1);
    assert_eq!(
        report.attempts[0].proof.as_deref(),
        Some("watchdog-lease-expired")
    );
    let stored = state.jobs.lock().await.get(&job.id).cloned().unwrap();
    assert_eq!(stored.attempts[0].cleanup_confirmed, Some(true));
    assert_eq!(
        stored.attempts[0].cleanup_proof.as_deref(),
        Some("watchdog-lease-expired")
    );
    assert!(stored.cleanup_confirmed);
    // 没有重试额度时只解除隔离，绝不重放已经执行过的命令。
    assert_eq!(stored.phase, Phase::Interrupted);
    assert!(report.resumed.is_empty());
    Ok(())
}

/// 证明之后才允许自动重跑；重跑是排队，不代表成功。
#[tokio::test]
async fn reconcile_requeues_only_proven_idempotent_offline_jobs() -> Result<()> {
    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let job = unconfirmed_job("test-node", Some(now() - 601), 1);
    fs::create_dir_all(state.dir(job.id))?;
    write_empty_source(&state, job.id)?;
    let mut job = job;
    job.source_sha256 = Some(source_sha256(&state, job.id)?);
    let id = job.id;
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id, job);
    }
    let report = sshpool::reconcile::reconcile(&state, Some("test-node")).await?;
    assert_eq!(report.resumed, vec![id]);
    let stored = wait_for_terminal(&state, id).await?;
    // 没有可用 Worker，重跑只应停在排队/失败，不会假装成功。
    assert_ne!(stored.phase, Phase::Succeeded);
    // 失败原因必须点名「已执行过的 Worker 不再参与」，不能是空理由。
    let message = stored.message.clone().unwrap_or_default();
    assert!(
        message.contains("test-node: already attempted this job"),
        "{message}"
    );
    Ok(())
}

/// 仍在 Running 的任务由执行者自己清理；外部核对不能在容器尚未创建时宣称「已证明」。
#[tokio::test]
async fn reconcile_never_claims_cleanup_for_a_running_job() -> Result<()> {
    let (_root, state) = state()?;
    let mut job = active_job("test-node");
    job.attempts[0].watchdog_deadline = Some(now() - 601);
    let id = job.id;
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(id, job);
    }
    let report = sshpool::reconcile::reconcile(&state, Some("test-node")).await?;
    assert_eq!(report.checked, 0);
    assert!(report.attempts.is_empty());
    let stored = state.jobs.lock().await.get(&id).cloned().unwrap();
    assert_eq!(stored.attempts[0].cleanup_confirmed, None);
    assert!(stored.attempts[0].cleanup_proof.is_none());
    assert!(!stored.cleanup_confirmed);
    Ok(())
}

#[tokio::test]
async fn reconcile_requires_authentication() -> Result<()> {
    let (_root, state) = state()?;
    let response = sshpool::api::routes(state.clone())
        .oneshot(Request::post("/v1/nodes/reconcile").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
