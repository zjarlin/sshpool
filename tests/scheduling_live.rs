//! 真实节点 + 真实不可达节点：探测不能拖垮派发。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=okm182-lan \
//!   cargo test --test scheduling_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 这台「黑洞」节点用 TEST-NET-1（192.0.2.1，保证不可路由）制造真实的
//! `ConnectTimeout` 等待。它验证的是功能性结论：坏节点只是被排除并报告原因，
//! 不会让任务被挡住，也不会把任务派到它上面。
use anyhow::{Context, Result, ensure};
use sshpool::{
    client::Client,
    config::{Build, Config, Node},
    model::{Health, Job, Phase},
    state::State,
};
use std::{fs, path::Path, sync::Arc, time::Instant};

fn live_node() -> Result<Node> {
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

/// RFC 5737 TEST-NET-1：不会被路由，连接必然等到 ConnectTimeout。
fn blackhole_node() -> Node {
    Node {
        name: "blackhole".into(),
        ssh: "192.0.2.1".into(),
        images: vec!["alpine:3.22".into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 100,
    }
}

async fn harness(nodes: Vec<Node>) -> Result<(tempfile::TempDir, Arc<State>, Client)> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    // 黑洞节点的优先级更高：如果它被当成可用节点，任务会优先派给它。
    let config = Config {
        min_free_disk_mib: 0,
        max_upload_mib: 16,
        max_artifact_mib: 16,
        max_log_mib: 16,
        max_active_jobs: 1,
        nodes,
        ..Config::default()
    };
    fs::write(
        root.path().join("config.toml"),
        toml::to_string_pretty(&config)?,
    )?;
    let state = State::load(root.path().to_path_buf(), config)?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let routes = sshpool::api::routes(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, routes).await;
    });
    let client = Client::new(format!("http://{address}"), &root.path().join("token"))?;
    Ok((root, state, client))
}

fn project(root: &Path) -> Result<std::path::PathBuf> {
    let project = root.join("project");
    fs::create_dir(&project)?;
    fs::write(project.join("build.sh"), "printf 'ok\\n'\n")?;
    Ok(project)
}

async fn platform(node: &Node) -> Result<String> {
    let arch =
        sshpool::transport::verified(node, "docker info --format '{{.Architecture}}'", 20).await?;
    Ok(format!(
        "linux/{}",
        sshpool::probe::platform_arch(String::from_utf8_lossy(&arch).trim())
    ))
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn an_unreachable_node_is_reported_but_never_chosen() -> Result<()> {
    let live = live_node()?;
    let (root, _state, client) = harness(vec![blackhole_node(), live.clone()]).await?;

    // 状态查询是真实探测：坏节点必须带着原因出现，好节点必须可用。
    let started = Instant::now();
    let status: Vec<Health> = serde_json::from_value(client.get("/v1/status").await?)?;
    let status_elapsed = started.elapsed();
    ensure!(
        status.len() == 2,
        "expected two nodes, got {}",
        status.len()
    );
    let blackhole = status
        .iter()
        .find(|health| health.name == "blackhole")
        .context("blackhole node is missing from status")?;
    let error = blackhole
        .error
        .as_deref()
        .context("an unreachable node must report an error")?;
    println!("blackhole error: {error}");
    let healthy = status
        .iter()
        .find(|health| health.name == "live")
        .context("live node is missing from status")?;
    ensure!(
        healthy.error.is_none(),
        "the reachable node must probe cleanly: {:?}",
        healthy.error
    );
    println!("status probe took {status_elapsed:?}");

    // 黑洞节点优先级更高：它只要被误判为可用，任务就会被派过去失败。
    let project = project(root.path())?;
    let build = Build {
        platform: platform(&live).await?,
        command: vec!["sh".into(), "build.sh".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };
    let started = Instant::now();
    let code = client.run(&project, build).await?;
    let run_elapsed = started.elapsed();
    println!("run took {run_elapsed:?}");
    ensure!(code == 0, "the job reported exit code {code}");

    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(jobs.len() == 1, "expected exactly one job");
    let job = &jobs[0];
    ensure!(
        job.phase == Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    let attempt = job.attempts.first().context("the job was never assigned")?;
    ensure!(
        attempt.node == "live",
        "the job was assigned to {} instead of the reachable node",
        attempt.node
    );
    ensure!(
        job.cleanup_confirmed,
        "container removal was not confirmed: {:?}",
        job.message
    );
    Ok(())
}
