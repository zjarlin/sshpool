use anyhow::{Context, Result};
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
        owner: None,
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
        owner: None,
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
    let (_summary, token) = sshpool::credentials::issue(
        &state.home,
        "workbench",
        &sshpool::credentials::Scope::ALL,
        3_600,
        now(),
    )?;

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
    let (second, second_token) = sshpool::credentials::issue(
        &state.home,
        "laptop",
        &sshpool::credentials::Scope::ALL,
        3_600,
        now(),
    )?;
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
        owner: None,
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
        owner: None,
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
            owner: None,
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
        owner: None,
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
        owner: None,
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

/// 每个请求都留一条访问记录：主体、身份来源、决定、理由、请求标识与路由模板。
#[tokio::test]
async fn every_request_is_audited_with_subject_decision_and_request_id() -> Result<()> {
    let (_root, state) = state()?;
    let app = sshpool::api::routes(state.clone());
    let (summary, token) = sshpool::credentials::issue(
        &state.home,
        "workbench-ü",
        &sshpool::credentials::Scope::ALL,
        3_600,
        now(),
    )?;

    // 1) 根 token 的只读请求：主体 root、来源 root-token、命中路由模板。
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {}", state.token))
                .header("x-request-id", "cli-run-1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // 2) 短期凭据的请求：主体是签发时的名字，凭据标识单独成列。
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // 3) 无 token：401 也必须留痕，否则「有人在猜 token」永远看不见。
    let response = app
        .clone()
        .oneshot(Request::get("/v1/jobs").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // 4) 伪造凭据：同样拒绝，理由与「没带 token」不同。
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/jobs")
                .header("authorization", "Bearer spt_not-a-real-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // 5) 未命中路由：仍然记录，且路由写成 unmatched（不落原始路径）。
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/does-not-exist")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let entries = sshpool::access::read(&state.home, &sshpool::access::Filter::default())?;
    assert_eq!(entries.len(), 5, "{entries:#?}");

    let root = entries
        .iter()
        .find(|entry| entry.request == "cli-run-1")
        .context("the supplied request id must survive into the audit")?;
    assert_eq!(root.subject, "root");
    assert_eq!(root.kind, "root");
    assert_eq!(root.reason, "root-token");
    assert_eq!(root.decision, "allowed");
    assert_eq!(root.status, 200);
    assert_eq!(root.route, "/v1/status");
    assert_eq!(root.method, "GET");
    assert_eq!(root.credential, None);

    let cred = entries
        .iter()
        .find(|entry| entry.kind == "credential")
        .context("a credential request must be attributed")?;
    assert_eq!(cred.subject, "workbench-ü");
    assert_eq!(
        cred.credential.as_deref(),
        Some(summary.id.to_string().as_str())
    );
    assert_eq!(cred.reason, "credential");
    assert!(
        !cred.request.is_empty(),
        "a server-generated request id is required"
    );

    let missing = entries
        .iter()
        .find(|entry| entry.reason == "missing-token")
        .context("an anonymous probe must be recorded")?;
    assert_eq!(missing.decision, "denied");
    assert_eq!(missing.kind, "anonymous");
    assert_eq!(missing.subject, "");
    assert_eq!(missing.status, 401);

    let forged = entries
        .iter()
        .find(|entry| entry.reason == "unknown-token")
        .context("a forged token must be recorded")?;
    assert_eq!(forged.decision, "denied");

    let unmatched = entries
        .iter()
        .find(|entry| entry.method == "GET" && entry.status == 404)
        .context("unrouted probes must still be audited")?;
    assert_eq!(unmatched.route, "unmatched");

    // 审计文件本身不能含任何 token 明文。
    let raw = fs::read_to_string(sshpool::access::path(&state.home))?;
    assert!(
        !raw.contains(&state.token),
        "the root token must never be logged"
    );
    assert!(
        !raw.contains(&token),
        "a credential secret must never be logged"
    );
    Ok(())
}

/// 拒绝也要计入，且查询接口自身同样受鉴权与审计约束。
#[tokio::test]
async fn the_access_endpoint_filters_and_is_itself_audited() -> Result<()> {
    let (_root, state) = state()?;
    let app = sshpool::api::routes(state.clone());
    let (_summary, token) = sshpool::credentials::issue(
        &state.home,
        "workbench",
        &sshpool::credentials::Scope::ALL,
        3_600,
        now(),
    )?;

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/access?limit=10")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/access?decision=allowed&subject=workbench")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
    assert!(
        !listed.is_empty(),
        "the query itself must have been recorded"
    );
    assert!(listed.iter().all(|entry| entry["subject"] == "workbench"));
    assert!(listed.iter().all(|entry| entry["decision"] == "allowed"));

    // 查询接口也受鉴权：无 token 时 401，并且这条拒绝同样进审计。
    let denied = app
        .clone()
        .oneshot(Request::get("/v1/access").body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let entries = sshpool::access::read(
        &state.home,
        &sshpool::access::Filter {
            decision: Some("denied".into()),
            ..sshpool::access::Filter::default()
        },
    )?;
    assert!(
        entries
            .iter()
            .any(|entry| entry.route == "/v1/access" && entry.decision == "denied"),
        "a denied audit query must itself be audited: {entries:#?}"
    );
    Ok(())
}

/// 审计写不进去时拒绝副作用请求：审计不了的动作不做。
#[tokio::test]
async fn a_non_writable_access_log_blocks_side_effect_requests() -> Result<()> {
    let (_root, state) = state()?;
    // 把 access.jsonl 做成目录：打开追加必然失败，模拟只读/损坏的审计目标。
    fs::create_dir(sshpool::access::path(&state.home))?;
    let app = sshpool::api::routes(state.clone());

    // 只读请求照常：审计失败不该让运维连状态都看不到。
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // 副作用请求被拒：不能出现「执行了但没记录」。
    let response = app
        .oneshot(
            Request::post("/v1/nodes/test-node/disable")
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    // 节点状态未被修改。
    assert!(
        state
            .nodes()
            .await
            .iter()
            .any(|node| node.name == "test-node" && node.enabled)
    );
    Ok(())
}

/// 权限分级：只读凭据能看，不能提交、取消、改节点或读别人的审计。
///
/// 这条测试覆盖的是「同一把 token 在不同路由上得到不同结论」，
/// 所以四类权限两组凭据都走同一个 `routes()`。
#[tokio::test]
async fn a_read_only_credential_is_refused_on_every_write_route() -> Result<()> {
    use sshpool::credentials::{Scope, issue};

    let (_root, state) = state()?;
    let app = sshpool::api::routes(state.clone());
    let (_reader, reader) = issue(&state.home, "reader", &[Scope::Read], 3_600, now())?;
    let (_writer, writer) = issue(
        &state.home,
        "writer",
        &[Scope::Read, Scope::Submit, Scope::Cancel],
        3_600,
        now(),
    )?;

    let send = |method: &str, path: &str, token: String| {
        let app = app.clone();
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .body(Body::empty())
            .expect("request builds");
        async move { app.oneshot(request).await }
    };

    // 读：两种凭据都允许（没有 read 的凭据连列表都看不到，那不是权限，是坏凭据）。
    for token in [&reader, &writer] {
        let response = send("GET", "/v1/status", token.clone()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send("GET", "/v1/jobs", token.clone()).await?;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // 写：只读凭据是 403 而不是 401 —— 身份是成立的，缺的是权限。
    let response = send("POST", "/v1/nodes/test-node/disable", reader.clone()).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4096)
            .await?
            .to_vec(),
    )?;
    assert!(
        body.contains("`admin` scope"),
        "403 should name the missing scope, got {body}"
    );

    let response = send("POST", "/v1/jobs", reader.clone()).await?;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "submit needs its own scope"
    );

    let id = uuid::Uuid::new_v4();
    let response = send("POST", &format!("/v1/jobs/{id}/cancel"), reader.clone()).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 读别人的审计同样要 admin：否则只读凭据能看全公司的访问时间线。
    let response = send("GET", "/v1/access?limit=5", reader.clone()).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send("GET", "/v1/access?limit=5", writer.clone()).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 有 cancel 没 admin：取消未知任务的报错是 400，说明它真的过了授权检查。
    let response = send("POST", &format!("/v1/jobs/{id}/cancel"), writer.clone()).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 越权也进审计，并且是 denied；allowed 的只读请求不能顶替它。
    let entries = sshpool::access::read(&state.home, &sshpool::access::Filter::default())?;
    let forbidden = entries
        .iter()
        .filter(|entry| entry.status == StatusCode::FORBIDDEN.as_u16())
        .count();
    assert!(forbidden >= 4, "every refusal must be audited: {forbidden}");
    assert!(
        entries
            .iter()
            .filter(|entry| entry.status == StatusCode::FORBIDDEN.as_u16())
            .all(|entry| entry.decision == "denied"),
        "403 must be recorded as denied, not allowed"
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.status == 200 && entry.decision == "allowed"),
        "an allowed read is still recorded as allowed"
    );

    // 根 token 不受影响：权限分级只收紧短期凭据。
    let response = send("POST", "/v1/nodes/test-node/disable", state.token.clone()).await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

/// 旧凭据文件（没有 scopes 字段）降级为只读，而不是继续拥有全部权限。
#[tokio::test]
async fn credentials_without_a_scope_field_are_downgraded_to_read_only() -> Result<()> {
    use sshpool::credentials::{Scope, issue};

    let (_root, state) = state()?;
    let (summary, token) = issue(&state.home, "legacy", &Scope::ALL, 3_600, now())?;
    // 模拟上一版签发的记录：删掉 scopes 再写回。
    let path = sshpool::credentials::path(&state.home);
    let mut store: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let entries = store["credentials"].as_array_mut().context("credentials")?;
    for credential in entries.iter_mut() {
        credential
            .as_object_mut()
            .context("object")?
            .remove("scopes");
    }
    fs::write(&path, serde_json::to_vec_pretty(&store)?)?;

    let listed = sshpool::credentials::list(&state.home)?;
    assert_eq!(listed[0].id, summary.id);
    assert_eq!(
        listed[0].scopes,
        vec![Scope::Read],
        "an old record must not keep write access"
    );
    let grant = sshpool::credentials::verify(&state.home, &token, now())?
        .context("the old token still authenticates")?;
    assert!(!grant.allows(Scope::Submit));
    assert!(grant.allows(Scope::Read));

    let app = sshpool::api::routes(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/status")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(
            Request::post("/v1/jobs")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// 提交一个合法的最小任务，返回任务记录；节点先禁用，让它不真的去连 SSH。
async fn submit_job(app: &axum::Router, token: &str) -> Result<Job> {
    let source = tempfile::NamedTempFile::new()?;
    let mut archive = tar::Builder::new(fs::File::create(source.path())?);
    archive.finish()?;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&Build::default())?);
    let digest = sshpool::archive::sha256_file(source.path())?;
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/jobs")
                .header("authorization", format!("Bearer {token}"))
                .header("x-sshpool-build", encoded)
                .header("x-sshpool-source-sha256", digest)
                .body(Body::from(fs::read(source.path())?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// 短期凭据只能看到、操作自己提交的任务；根 token 仍然全权。
///
/// 属主边界与动作权限是两道独立判断：这条测试里 A 与 B 都有
/// `read`/`submit`/`cancel`，差别只在「谁提交的」。
#[tokio::test]
async fn a_credential_sees_and_manages_only_the_jobs_it_submitted() -> Result<()> {
    use sshpool::credentials::{Scope, issue};

    let (root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let app = sshpool::api::routes(state.clone());
    let scopes = [Scope::Read, Scope::Submit, Scope::Cancel];
    let (_, alice) = issue(&state.home, "alice", &scopes, 3_600, now())?;
    let (_, bob) = issue(&state.home, "bob", &scopes, 3_600, now())?;

    let job = submit_job(&app, &alice).await?;
    assert_eq!(
        job.owner.as_deref(),
        Some("alice"),
        "the submitter must be recorded as the owner"
    );

    let send = |method: &str, path: String, token: String| {
        let app = app.clone();
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request builds");
        async move { app.oneshot(request).await }
    };
    let list = |token: String| async move {
        let response = send("GET", "/v1/jobs".into(), token).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        let jobs: Vec<Job> = serde_json::from_slice(&bytes)?;
        Ok::<_, anyhow::Error>(jobs)
    };

    // 属主能看；列表里只有自己的一条。
    let mine = list(alice.clone()).await?;
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id, job.id);
    assert_eq!(
        send("GET", format!("/v1/jobs/{}", job.id), alice.clone())
            .await?
            .status(),
        StatusCode::OK
    );

    // 别人：列表为空，详情/日志/事件/产物/取消一律 403（不是 404，也不是 200）。
    assert!(
        list(bob.clone()).await?.is_empty(),
        "another subject must not see the job in its list"
    );
    for path in [
        format!("/v1/jobs/{}", job.id),
        format!("/v1/jobs/{}/log", job.id),
        format!("/v1/jobs/{}/events", job.id),
        format!("/v1/jobs/{}/artifacts", job.id),
    ] {
        let response = send("GET", path.clone(), bob.clone()).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "GET {path}");
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await?
                .to_vec(),
        )?;
        assert!(
            body.contains("does not own"),
            "403 should name the ownership rule, got {body}"
        );
    }
    assert_eq!(
        send("POST", format!("/v1/jobs/{}/cancel", job.id), bob.clone())
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        !state.jobs.lock().await[&job.id].cancel_requested,
        "a refused cancel must not touch the job"
    );

    // 属主自己取消是允许的；这排除了「403 是因为取消永远失败」。
    assert_eq!(
        send("POST", format!("/v1/jobs/{}/cancel", job.id), alice.clone())
            .await?
            .status(),
        StatusCode::OK
    );

    // 根 token 越过属主边界：它看得到两个主体的全部任务。
    let all = list(state.token.clone()).await?;
    assert_eq!(all.len(), 1);
    assert_eq!(
        send("GET", format!("/v1/jobs/{}", job.id), state.token.clone())
            .await?
            .status(),
        StatusCode::OK
    );

    // 审计里留下这次越权尝试，且是 denied —— 边界不能只在响应体里成立。
    let log = fs::read_to_string(root.path().join("access.jsonl"))?;
    assert!(
        log.lines().any(|line| line.contains("\"subject\":\"bob\"")
            && line.contains("\"status\":403")
            && line.contains("\"decision\":\"denied\"")),
        "the refused access must be audited: {log}"
    );
    Ok(())
}

/// 旧任务没有 `owner` 字段：无法证明归属时只有运维主体能读，不能默认成「大家的」。
#[tokio::test]
async fn a_job_without_an_owner_is_only_visible_to_operators() -> Result<()> {
    use sshpool::credentials::{Scope, issue};

    let (_root, state) = state()?;
    state.set_node_enabled("test-node", false).await?;
    state.set_node_enabled("second-node", false).await?;
    let app = sshpool::api::routes(state.clone());
    let (_, alice) = issue(&state.home, "alice", &[Scope::Read], 3_600, now())?;
    let (_, operator) = issue(
        &state.home,
        "operator",
        &[Scope::Read, Scope::Admin],
        3_600,
        now(),
    )?;

    let mut job = active_job("test-node");
    job.owner = None;
    state.jobs.lock().await.insert(job.id, job.clone());

    let send = |path: String, token: String| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
        }
    };
    assert_eq!(
        send(format!("/v1/jobs/{}", job.id), alice.clone())
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(format!("/v1/jobs/{}", job.id), operator.clone())
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(format!("/v1/jobs/{}", job.id), state.token.clone())
            .await?
            .status(),
        StatusCode::OK
    );
    let response = send("/v1/jobs".into(), alice).await?;
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
    let jobs: Vec<Job> = serde_json::from_slice(&bytes)?;
    assert!(jobs.is_empty(), "an unknown owner must not be listed");
    Ok(())
}
