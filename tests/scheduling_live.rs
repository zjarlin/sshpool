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
        slo: Default::default(),
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
        slo: Default::default(),
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
    let client = Client::new(
        format!("http://{address}"),
        &root.path().join("token"),
        None,
    )?;
    Ok((root, state, client))
}

fn project(root: &Path) -> Result<std::path::PathBuf> {
    let project = root.join("project");
    fs::create_dir(&project)?;
    fs::write(project.join("build.sh"), "printf 'ok\\n'\n")?;
    Ok(project)
}

/// 同一轮测试里要提交多次时用不同目录：`project()` 在已存在时失败，
/// 这是刻意的（不允许覆盖已有工程），所以这里显式命名。
fn named_project(root: &Path, name: &str) -> Result<std::path::PathBuf> {
    let project = root.join(name);
    fs::create_dir(&project)?;
    fs::write(project.join("build.sh"), "printf 'ok\\n'\n")?;
    Ok(project)
}

/// 只取本次 `run` 新产生的那条记录。
///
/// `created_at` 是秒级时间戳，同一秒内提交的多个任务无法靠排序区分；
/// 用「提交前已有的 ID 集合」做差才是可靠的判据。
async fn new_job(client: &Client, seen: &std::collections::HashSet<uuid::Uuid>) -> Result<Job> {
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    jobs.into_iter()
        .filter(|job| !seen.contains(&job.id))
        .max_by_key(|job| job.created_at)
        .context("the run did not record a new job")
}

async fn job_ids(client: &Client) -> Result<std::collections::HashSet<uuid::Uuid>> {
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    Ok(jobs.into_iter().map(|job| job.id).collect())
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

/// 实测来自真实执行，而不是清单声明：第一次派发没有历史，跑满样本之后
/// 下一次派发必须带上实测上界，且每次尝试都记录了自己的收尾时刻。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn measured_runs_become_the_next_expectation() -> Result<()> {
    let live = live_node()?;
    let (root, _state, client) = harness(vec![live.clone()]).await?;
    let build = Build {
        platform: platform(&live).await?,
        command: vec!["sh".into(), "build.sh".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };
    let project = project(root.path())?;
    let needed = sshpool::scheduler::MIN_SAMPLES;
    for round in 0..=needed {
        let code = client.run(&project, build.clone()).await?;
        ensure!(code == 0, "round {round} reported exit code {code}");
        let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
        let job = jobs
            .iter()
            .max_by_key(|job| job.created_at)
            .context("the job list is empty")?;
        let attempt = job.attempts.first().context("the job was never assigned")?;
        let recorded = attempt
            .schedule
            .as_deref()
            .with_context(|| format!("round {round} did not record why this worker was chosen"))?;
        ensure!(
            recorded.contains("no measured completion time") || recorded.contains("eta "),
            "round {round} recorded an unusable basis: {recorded}"
        );
        let finished = attempt
            .finished_at
            .with_context(|| format!("round {round} has no finish time"))?;
        ensure!(
            finished >= attempt.started_at,
            "round {round} finished before it started: {finished} < {}",
            attempt.started_at
        );
        // 未满 3 条样本时不是预期；满样本之后必须出现实测上界。
        let expected = sshpool::scheduler::expected_seconds(&jobs, "live", &build);
        if round + 1 < needed {
            ensure!(
                expected.is_none(),
                "round {round} claimed an expectation from {} samples",
                round
            );
        } else {
            let expected = expected.context("a full sample set must produce an expectation")?;
            ensure!(
                expected.samples >= needed,
                "expected at least {needed} samples, got {}",
                expected.samples
            );
            ensure!(
                expected.seconds > 0,
                "a real container run cannot take zero seconds"
            );
            println!("round {round}: {expected}");
        }
        // 排序依据必须写进事件链，不能只存在于内存里。
        let events = client.get(&format!("/v1/jobs/{}/events", job.id)).await?;
        let basis = events
            .as_array()
            .context("events must be an array")?
            .iter()
            .filter(|event| event["kind"] == "schedule")
            .filter_map(|event| event["detail"].as_str())
            .next_back()
            .context("the assignment must record how the worker was chosen")?
            .to_string();
        ensure!(
            basis.starts_with("live ("),
            "the basis must name the chosen worker first: {basis}"
        );
        // 派发时样本不足就必须写「没有实测」，满样本之后必须写出上界。
        if round < needed {
            ensure!(
                basis.contains("no measured completion time"),
                "round {round} must not claim a measurement: {basis}"
            );
        } else {
            ensure!(
                basis.contains("eta "),
                "round {round} must state the measured bound: {basis}"
            );
        }
        println!("round {round} basis: {basis}");
    }
    Ok(())
}

/// 业务预算在真实主机上的判据只有一条：**还会不会创建容器**。
///
/// 这里先探测这台机器的真实 swap 用量，再把它自己的读数当作门槛基准：
/// 门槛低于实测 → 必须拒单，且远端不能出现任何容器；门槛等于实测 →
/// 必须真的跑起来。两边都验，才不是「一律拒绝」或「一律放行」的假证据。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn an_over_budget_host_stops_taking_work_before_any_container_exists() -> Result<()> {
    let mut live = live_node()?;
    let health = sshpool::probe::node(&live).await;
    ensure!(
        health.error.is_none(),
        "the worker must probe cleanly before this test means anything: {:?}",
        health.error
    );
    let measured = health
        .swap_used_mib
        .context("this host reported no swap reading, so a swap budget cannot be exercised")?;
    println!(
        "measured swap {} MiB, memory PSI {:?}, io PSI {:?}",
        measured, health.memory_pressure_percent, health.io_pressure_percent
    );

    // 门槛取实测值本身：这是边界，必须放行；低 1 MiB 就必须拒绝。
    live.slo = sshpool::config::Slo {
        max_swap_used_mib: Some(measured.saturating_sub(1)),
        ..Default::default()
    };
    let (root, _state, client) = harness(vec![live.clone()]).await?;
    let build = Build {
        platform: platform(&live).await?,
        command: vec!["sh".into(), "build.sh".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };
    let refused_project = project(root.path())?;
    let code = client.run(&refused_project, build.clone()).await?;
    ensure!(code != 0, "an over-budget host must not succeed: {code}");
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    let job = jobs.last().context("the rejected job was never recorded")?;
    ensure!(
        job.phase == Phase::Failed,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        job.attempts.is_empty(),
        "an over-budget host must be refused before an attempt exists: {:?}",
        job.attempts
    );
    let message = job.message.as_deref().unwrap_or_default();
    ensure!(
        message.contains("business budget") && message.contains("swap used"),
        "the refusal must name the budget and the reading: {message}"
    );
    println!("refused with: {message}");
    // 拒单发生在创建容器之前：远端不能留下任何本次任务的东西。
    let survivors = sshpool::transport::checked(
        &live,
        &format!(
            "docker ps -a --filter {} --format {{.Names}} | wc -l",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id))
        ),
        20,
    )
    .await?;
    let count: usize = String::from_utf8_lossy(&survivors).trim().parse()?;
    ensure!(
        count == 0,
        "a refused job must not create a container, found {count}"
    );
    println!("containers created by the refused job: {count}");

    // 反向对照：门槛抬到实测值，同一台机器必须真的接单并跑完。
    let mut allowed = live.clone();
    allowed.slo = sshpool::config::Slo {
        max_swap_used_mib: Some(measured),
        ..Default::default()
    };
    let (root, _state, client) = harness(vec![allowed.clone()]).await?;
    let accepted_project = project(root.path())?;
    let code = client.run(&accepted_project, build).await?;
    ensure!(code == 0, "a host within its budget must still run: {code}");
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    let job = jobs.last().context("the accepted job was never recorded")?;
    ensure!(
        job.phase == Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        !job.attempts.is_empty() && job.cleanup_confirmed,
        "the accepted job must run and clean up: {:?}",
        job.message
    );
    println!("budget of {measured} MiB accepted the same job");
    Ok(())
}

/// 在线改预算必须免重启生效，而且判据是「还能不能创建容器」。
///
/// 三段对照：无预算 → 跑通；在线设成低于实测 swap → 拒单且 0 容器；
/// 在线取消预算 → 同一台机器又能跑通。全程不重启控制面、不改 config.toml。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn an_online_budget_update_takes_effect_without_a_restart() -> Result<()> {
    let live = live_node()?;
    let health = sshpool::probe::node(&live).await;
    ensure!(
        health.error.is_none(),
        "the worker must probe cleanly: {:?}",
        health.error
    );
    let measured = health
        .swap_used_mib
        .context("this host reported no swap reading, so a swap budget cannot be exercised")?;
    println!("measured swap {measured} MiB");

    let (root, state, client) = harness(vec![live.clone()]).await?;
    let build = Build {
        platform: platform(&live).await?,
        command: vec!["sh".into(), "build.sh".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };

    // 1. 未设预算：必须跑通，证明这台机器本身可用。
    let seen = job_ids(&client).await?;
    let unbudgeted = named_project(root.path(), "unbudgeted")?;
    let code = client.run(&unbudgeted, build.clone()).await?;
    ensure!(code == 0, "an unbudgeted host must run: {code}");
    println!("unbudgeted run succeeded");

    // 2. 在线设成低于实测 1 MiB：不重启，下一次派发就必须拒单。
    let patch = sshpool::config::NodePatch {
        slo: sshpool::config::SloPatch {
            max_swap_used_mib: Some(measured.saturating_sub(1)),
            ..Default::default()
        },
        ..Default::default()
    };
    let applied = client.update_node("live", &patch).await?;
    println!("applied: {}", applied["changes"]);
    ensure!(
        state.nodes().await[0].slo.max_swap_used_mib == Some(measured.saturating_sub(1)),
        "the running controller must see the new budget immediately"
    );

    let refused = named_project(root.path(), "refused")?;
    let code = client.run(&refused, build.clone()).await?;
    ensure!(code != 0, "an over-budget host must be refused: {code}");
    let job = new_job(&client, &seen).await?;
    let job = &job;
    ensure!(
        job.phase == Phase::Failed && job.attempts.is_empty(),
        "an online budget must refuse before an attempt exists: {:?} {:?}",
        job.phase,
        job.message
    );
    let message = job.message.as_deref().unwrap_or_default();
    ensure!(
        message.contains("swap used") && message.contains(&measured.saturating_sub(1).to_string()),
        "the refusal must quote the online budget: {message}"
    );
    let survivors = sshpool::transport::checked(
        &live,
        &format!(
            "docker ps -a --filter {} --format {{.Names}} | wc -l",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id))
        ),
        20,
    )
    .await?;
    let count: usize = String::from_utf8_lossy(&survivors).trim().parse()?;
    ensure!(
        count == 0,
        "an online refusal must create no container, found {count}"
    );
    println!("online budget refused with: {message}");

    // 3. 在线取消预算：必须恢复接单，证明 `clear` 不是只改内存的假动作。
    let patch = sshpool::config::NodePatch {
        slo: sshpool::config::SloPatch {
            clear: vec!["max_swap_used_mib".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    client.update_node("live", &patch).await?;
    ensure!(
        state.nodes().await[0].slo.is_empty(),
        "clearing the budget must leave no threshold behind"
    );
    let stored = sshpool::config::read(root.path())?;
    ensure!(
        stored
            .nodes
            .iter()
            .find(|node| node.name == "live")
            .is_some_and(|node| node.slo.is_empty()),
        "the cleared budget must also be gone from config.toml"
    );
    let seen = job_ids(&client).await?;
    let restored = named_project(root.path(), "restored")?;
    let code = client.run(&restored, build).await?;
    ensure!(
        code == 0,
        "clearing the budget must restore service: {code}"
    );
    let job = new_job(&client, &seen).await?;
    let job = &job;
    ensure!(
        job.phase == Phase::Succeeded && job.cleanup_confirmed,
        "the restored job must run and clean up: {:?}",
        job.message
    );
    println!("cleared budget restored service");
    Ok(())
}
