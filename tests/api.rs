use anyhow::Result;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use sshpool::{
    config::{Build, Config},
    model::{Job, Phase},
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
        ..Config::default()
    };
    let state = State::load(root.path().into(), config)?;
    Ok((root, state))
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
