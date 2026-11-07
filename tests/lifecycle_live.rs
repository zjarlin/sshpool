//! 真实取消与期限：默认忽略，需显式指定可达节点后运行。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=sshpool-anchor cargo test --test lifecycle_live -- --ignored --nocapture
//! ```
//!
//! 走真实的 `POST /v1/jobs` + `POST /v1/jobs/{id}/cancel`，调度到真实 Worker。
//! 断言重点不是「API 返回 200」，而是远端容器确实停了、确实删了、控制面记录
//! 没有把仍在运行的任务报成已取消。容器标签使用一次性 UUID，不触碰业务容器。
use anyhow::{Context, Result, ensure};
use axum::{body::Body, http::Request};
use base64::Engine;
use sshpool::{
    config::{Build, Config, Node},
    model::{Job, Phase},
    state::State,
};
use std::{fs, sync::Arc, time::Duration};
use tower::ServiceExt;

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live".into(),
        ssh,
        images: vec!["alpine:3.22".into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 0,
    })
}

fn state(node: &Node) -> Result<(tempfile::TempDir, Arc<State>)> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let config = Config {
        min_free_disk_mib: 0,
        max_upload_mib: 16,
        max_artifact_mib: 16,
        max_log_mib: 16,
        max_active_jobs: 1,
        nodes: vec![node.clone()],
        ..Config::default()
    };
    fs::write(
        root.path().join("config.toml"),
        toml::to_string_pretty(&config)?,
    )?;
    let state = State::load(root.path().to_path_buf(), config)?;
    Ok((root, state))
}

/// 提交一个真实任务，返回任务记录；`archive` 是空的项目归档。
async fn submit(state: &Arc<State>, build: Build) -> Result<Job> {
    let source = tempfile::NamedTempFile::new()?;
    let mut archive = tar::Builder::new(fs::File::create(source.path())?);
    archive.finish()?;
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
    ensure!(
        response.status() == axum::http::StatusCode::ACCEPTED,
        "submit rejected"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn wait_for(state: &Arc<State>, id: uuid::Uuid, timeout_secs: u64) -> Result<Job> {
    for _ in 0..(timeout_secs * 10) {
        let job = state
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .context("job disappeared")?;
        if job.phase.terminal() {
            return Ok(job);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("job did not reach a terminal phase within {timeout_secs}s")
}

async fn cancel(state: &Arc<State>, id: uuid::Uuid) -> Result<()> {
    let response = sshpool::api::routes(state.clone())
        .oneshot(
            Request::post(format!("/v1/jobs/{id}/cancel"))
                .header("authorization", format!("Bearer {}", state.token))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        response.status() == axum::http::StatusCode::OK,
        "cancel rejected"
    );
    Ok(())
}

/// 取消必须真的停掉远端进程，并且把容器删干净。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn cancel_stops_the_remote_process_and_removes_the_container() -> Result<()> {
    let node = node()?;
    let (_root, state) = state(&node)?;
    let build = Build {
        // 远长于测试窗口：只有主动停止才能让它结束。
        command: vec![
            "sh".into(),
            "-c".into(),
            "sleep 600; echo should-not-finish".into(),
        ],
        ..Build::default()
    };
    let job = submit(&state, build).await?;
    // 等到容器真的在跑，否则取消可能落在创建之前，测不到停止路径。
    let mut running = false;
    for _ in 0..300 {
        if state
            .jobs
            .lock()
            .await
            .get(&job.id)
            .is_some_and(|current| current.phase == Phase::Running)
        {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(running, "job never entered the running phase");
    tokio::time::sleep(Duration::from_secs(2)).await;

    cancel(&state, job.id).await?;
    let finished = wait_for(&state, job.id, 120).await?;
    ensure!(
        finished.phase == Phase::Cancelled,
        "cancel did not produce a cancelled job: {:?} {:?}",
        finished.phase,
        finished.message
    );
    ensure!(
        finished.cleanup_confirmed,
        "container removal was not confirmed"
    );

    let events = fs::read_to_string(state.dir(job.id).join("events.jsonl"))?;
    ensure!(
        events.contains("\"stop_requested\"") && events.contains("remote container stopped"),
        "the stop request must be audited:\n{events}"
    );
    // 远端不能残留这个任务的容器，也不能还有 sleep 进程。
    let node_handle = finished
        .attempts
        .first()
        .map(|attempt| attempt.container.clone())
        .unwrap_or_default();
    ensure!(!node_handle.is_empty(), "attempt container is empty");
    let containers = sshpool::transport::checked(
        &node,
        &format!(
            "docker ps -a --filter {} --format {}",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id)),
            sshpool::transport::quote("{{.Names}}")
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&containers).trim().is_empty(),
        "a container survived cancellation: {}",
        String::from_utf8_lossy(&containers)
    );
    Ok(())
}

/// 执行期限到达时同样要主动停止，而不是把进程留给远端继续跑。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn deadline_stops_the_remote_process_before_reporting_failure() -> Result<()> {
    let node = node()?;
    let (_root, state) = state(&node)?;
    let build = Build {
        command: vec![
            "sh".into(),
            "-c".into(),
            "sleep 600; echo should-not-finish".into(),
        ],
        timeout_secs: 5,
        ..Build::default()
    };
    let job = submit(&state, build).await?;
    let finished = wait_for(&state, job.id, 180).await?;
    ensure!(
        finished.phase == Phase::Failed,
        "a deadline must fail the job: {:?} {:?}",
        finished.phase,
        finished.message
    );
    let message = finished.message.clone().unwrap_or_default();
    ensure!(
        message.contains("job deadline exceeded"),
        "unexpected failure message: {message}"
    );
    ensure!(
        finished.cleanup_confirmed,
        "container removal was not confirmed"
    );
    let events = fs::read_to_string(state.dir(job.id).join("events.jsonl"))?;
    ensure!(
        events.contains("\"stop_requested\"") && events.contains("deadline"),
        "the deadline stop must be audited:\n{events}"
    );
    let containers = sshpool::transport::checked(
        &node,
        &format!(
            "docker ps -a --filter {} --format {}",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id)),
            sshpool::transport::quote("{{.Names}}")
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&containers).trim().is_empty(),
        "a container survived the deadline: {}",
        String::from_utf8_lossy(&containers)
    );
    Ok(())
}
