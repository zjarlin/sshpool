use anyhow::Result;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use sshpool::{
    config::{Build, Config, Node},
    model::{Attempt, Job, Phase},
    state::State,
};
use std::{fs, sync::Arc};
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
        build: Build::default(),
        phase: Phase::Running,
        created_at: 0,
        finished_at: None,
        attempts: vec![Attempt {
            node: node.into(),
            container: "owned".into(),
            started_at: 0,
            outcome: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
    }
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
        let request = Request::post("/v1/jobs")
            .header(
                "authorization",
                "Bearer test-only-token-not-a-production-secret",
            )
            .header("x-sshpool-build", encoded)
            .body(Body::from(bytes))?;
        let response = sshpool::api::routes(state.clone()).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fs::read_dir(root.path().join("jobs"))?.count(), 0);
    }
    assert_eq!(fs::read_to_string(sentinel)?, "untouched");
    Ok(())
}
#[tokio::test]
async fn restart_marks_queued_work_interrupted_without_replaying_it() -> Result<()> {
    let (_root, state) = state()?;
    let job = Job {
        id: uuid::Uuid::new_v4(),
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
    };
    fs::create_dir(state.dir(job.id))?;
    state.persist(&job)?;
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
    };
    state.persist(&job)?;
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
