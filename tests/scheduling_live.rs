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

/// 在线准备镜像必须免重启生效，判据是「任务真的用这张镜像跑起来」。
///
/// 四段：未授权时同一张镜像被拒且 0 容器 → `node prepare` 拉取并授权 → 不重启
/// 就提交、`Succeeded` 且清理确认 → 重复准备不再拉取。再来一段反向对照：
/// 准备一个不存在的镜像必须报错且 `config.toml` 一字未变。
///
/// 默认用 `busybox:1.36`（小镜像、自带 `sh`）。测试开始前它必须尚未存在于
/// Worker 上，否则「拉取」无法与「本来就有」区分；结束时如果这次是它拉下来的，
/// 就删掉，让同一台机器可以重复跑。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker and registry access"]
async fn an_online_image_prepare_takes_effect_without_a_restart() -> Result<()> {
    let live = live_node()?;
    let image =
        std::env::var("SSHPOOL_LIVE_PREPARE_IMAGE").unwrap_or_else(|_| "busybox:1.36".into());
    ensure!(
        !live.images.contains(&image),
        "{image} is already approved in the harness node; pick another tag"
    );
    let present = sshpool::transport::capture(
        &live,
        &format!(
            "docker image inspect {} >/dev/null 2>&1 && echo yes || echo no",
            sshpool::transport::quote(&image)
        ),
        60,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&present.1).trim() == "no",
        "{image} already exists on the worker; it cannot distinguish pull from cache. \
         Set SSHPOOL_LIVE_PREPARE_IMAGE to a tag that is not present"
    );

    let (root, state, client) = harness(vec![live.clone()]).await?;
    let platform = platform(&live).await?;
    let build = Build {
        image: image.clone(),
        platform,
        command: vec!["sh".into(), "-c".into(), "printf 'prepared\\n'".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };

    // 1. 未授权：必须拒单，且不能留下容器。
    let seen = job_ids(&client).await?;
    let refused = named_project(root.path(), "unapproved")?;
    let code = client.run(&refused, build.clone()).await?;
    ensure!(code != 0, "an unapproved image must be refused: {code}");
    let job = new_job(&client, &seen).await?;
    ensure!(
        job.phase == Phase::Failed && job.attempts.is_empty(),
        "an unapproved image must fail before an attempt exists: {:?} {:?}",
        job.phase,
        job.message
    );
    let message = job.message.as_deref().unwrap_or_default();
    ensure!(
        message.contains("image not approved"),
        "the refusal must name the missing approval: {message}"
    );
    let containers = sshpool::transport::checked(
        &live,
        &format!(
            "docker ps -a --filter {} --format {{.Names}} | wc -l",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id))
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&containers).trim() == "0",
        "an unapproved image must create no container"
    );
    println!("unapproved image refused: {message}");

    // 2. 在线准备：控制面真的拉取，并把镜像写进允许清单。
    let applied = client.prepare_node("live", &image).await?;
    ensure!(
        applied["pulled"] == serde_json::json!(true),
        "the first prepare must actually pull: {applied}"
    );
    ensure!(
        state.nodes().await[0]
            .images
            .iter()
            .any(|item| item == &image),
        "the running controller must see the new approval immediately"
    );
    let stored = sshpool::config::read(root.path())?;
    ensure!(
        stored.nodes[0].images.iter().any(|item| item == &image),
        "the approval must also be on disk"
    );
    println!("prepared {image}: {applied}");

    // 3. 不重启就提交：任务必须真的用这张镜像跑起来并清理。
    let seen = job_ids(&client).await?;
    let prepared = named_project(root.path(), "prepared")?;
    let code = client.run(&prepared, build.clone()).await?;
    ensure!(code == 0, "the prepared image must run: {code}");
    let job = new_job(&client, &seen).await?;
    ensure!(
        job.phase == Phase::Succeeded && job.cleanup_confirmed,
        "the prepared job must succeed and clean up: {:?} {:?}",
        job.phase,
        job.message
    );
    let attempt = job.attempts.first().context("the job was never assigned")?;
    ensure!(
        attempt.node == "live",
        "the job ran on {} instead of the prepared worker",
        attempt.node
    );
    println!("prepared image ran: {:?}", job.message);

    // 4. 重复准备：已经是授权状态，不重复拉取。
    let again = client.prepare_node("live", &image).await?;
    ensure!(
        again["pulled"] == serde_json::json!(false),
        "a second prepare must not pull again: {again}"
    );

    // 5. 反向对照：拉不到的镜像不能改配置。
    let before = fs::read_to_string(root.path().join("config.toml"))?;
    let missing = "alpine:0.0.0-sshpool-does-not-exist";
    let error = client
        .prepare_node("live", missing)
        .await
        .expect_err("a nonexistent image must not be approved");
    println!("nonexistent image refused: {error:#}");
    ensure!(
        fs::read_to_string(root.path().join("config.toml"))? == before,
        "a failed pull must not touch config.toml"
    );
    ensure!(
        !state.nodes().await[0]
            .images
            .iter()
            .any(|item| item == missing),
        "a failed pull must not grant the image in memory either"
    );

    // 还原本机镜像列表：只删这次拉下来的那一张。
    sshpool::transport::checked(
        &live,
        &format!(
            "docker rmi {} >/dev/null 2>&1 || true",
            sshpool::transport::quote(&image)
        ),
        60,
    )
    .await?;
    println!("removed {image} from the worker");
    Ok(())
}

/// 在线撤销镜像授权必须免重启生效，判据是「同一张镜像从能跑变成被拒」。
///
/// 五段：`node prepare` 授权后不重启就真的跑起来 → `node revoke` 后内存与磁盘都
/// 不再有这张镜像 → 不重启再提交同一张镜像被拒且 0 容器 → 重复撤销是幂等的
/// `revoked=false` → 撤销一个从未授权的 tag 同样 `revoked=false` 且
/// `config.toml` 一字未变。
///
/// 默认用 `busybox:1.35`（与 prepare 测试的 `busybox:1.36` 错开，避免两条 live
/// 测试互相干扰）。如果 Worker 上本来没有这张镜像，就先 `prepare` 把它拉下来 ——
/// 这一步既是前置条件，也顺带证明授权本身可用；结束时只删这次拉下来的那一张。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker and registry access"]
async fn revoking_an_image_takes_effect_without_a_restart() -> Result<()> {
    let live = live_node()?;
    let image =
        std::env::var("SSHPOOL_LIVE_REVOKE_IMAGE").unwrap_or_else(|_| "busybox:1.35".into());
    ensure!(
        !live.images.contains(&image),
        "{image} is already approved in the harness node; pick another tag"
    );
    let present = sshpool::transport::capture(
        &live,
        &format!(
            "docker image inspect {} >/dev/null 2>&1 && echo yes || echo no",
            sshpool::transport::quote(&image)
        ),
        60,
    )
    .await?;
    let pulled_here = String::from_utf8_lossy(&present.1).trim() == "no";

    let (root, state, client) = harness(vec![live.clone()]).await?;
    let platform = platform(&live).await?;
    let build = Build {
        image: image.clone(),
        platform,
        command: vec!["sh".into(), "-c".into(), "printf 'revoked\\n'".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    };

    // 1. 授权：本来就是拉取，顺带把这张镜像写进允许清单。
    let prepared = client.prepare_node("live", &image).await?;
    ensure!(
        prepared["pulled"] == serde_json::json!(true),
        "the harness has not approved this image, so prepare must report a pull: {prepared}"
    );
    ensure!(
        state.nodes().await[0]
            .images
            .iter()
            .any(|item| item == &image),
        "the running controller must see the new approval immediately"
    );
    println!("prepared {image}: {prepared}");

    // 2. 授权可用：不重启就提交，任务必须真的跑起来并清理。
    let seen = job_ids(&client).await?;
    let approved = named_project(root.path(), "approved")?;
    let code = client.run(&approved, build.clone()).await?;
    ensure!(code == 0, "the approved image must run: {code}");
    let job = new_job(&client, &seen).await?;
    ensure!(
        job.phase == Phase::Succeeded && job.cleanup_confirmed,
        "the approved job must succeed and clean up: {:?} {:?}",
        job.phase,
        job.message
    );
    println!("approved image ran: {:?}", job.message);

    // 3. 撤销：只有允许清单变化，没有远端动作。
    let applied = client.revoke_node_image("live", &image).await?;
    ensure!(
        applied["revoked"] == serde_json::json!(true),
        "the first revoke must remove the approval: {applied}"
    );
    ensure!(
        !state.nodes().await[0]
            .images
            .iter()
            .any(|item| item == &image),
        "the running controller must drop the approval immediately"
    );
    let stored = sshpool::config::read(root.path())?;
    ensure!(
        stored.nodes[0].images.iter().all(|item| item != &image),
        "the approval must also be gone from config.toml"
    );
    println!("revoked {image}: {applied}");

    // 4. 不重启就提交同一张镜像：必须在派发前被拒，且不能留下容器。
    let seen = job_ids(&client).await?;
    let refused = named_project(root.path(), "after-revoke")?;
    let code = client.run(&refused, build.clone()).await?;
    ensure!(code != 0, "a revoked image must be refused: {code}");
    let job = new_job(&client, &seen).await?;
    ensure!(
        job.phase == Phase::Failed && job.attempts.is_empty(),
        "a revoked image must fail before an attempt exists: {:?} {:?}",
        job.phase,
        job.message
    );
    let message = job.message.as_deref().unwrap_or_default();
    ensure!(
        message.contains("image not approved"),
        "the refusal must name the missing approval: {message}"
    );
    let containers = sshpool::transport::checked(
        &live,
        &format!(
            "docker ps -a --filter {} --format {{.Names}} | wc -l",
            sshpool::transport::quote(&format!("label=io.sshpool.job={}", job.id))
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&containers).trim() == "0",
        "a revoked image must create no container"
    );
    println!("revoked image refused: {message}");

    // 5. 幂等与反向对照：没有可删的授权时不写盘。
    let again = client.revoke_node_image("live", &image).await?;
    ensure!(
        again["revoked"] == serde_json::json!(false),
        "a second revoke must report no change: {again}"
    );
    let before = fs::read_to_string(root.path().join("config.toml"))?;
    let never = client.revoke_node_image("live", "alpine:3.21").await?;
    ensure!(
        never["revoked"] == serde_json::json!(false),
        "revoking a tag that was never approved must report no change: {never}"
    );
    ensure!(
        fs::read_to_string(root.path().join("config.toml"))? == before,
        "a no-op revoke must not touch config.toml"
    );

    // 还原本机镜像列表：只删这次拉下来的那一张。
    //
    // 清理失败不能让已经成立的功能结论变成失败：这台 Worker 的 ssh 走 aio 的
    // Node ProxyCommand，机器负载高时偶发握手超过 `ConnectTimeout`。重试几次后
    // 只打印提醒，让镜像列表本身成为唯一需要人工确认的东西。
    if pulled_here {
        let script = format!(
            "docker rmi {} >/dev/null 2>&1 || true",
            sshpool::transport::quote(&image)
        );
        let mut removed = false;
        for attempt in 1..=3 {
            match sshpool::transport::checked(&live, &script, 60).await {
                Ok(_) => {
                    removed = true;
                    break;
                }
                Err(error) => {
                    println!("cleanup attempt {attempt} failed: {error:#}");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
        if removed {
            println!("removed {image} from the worker");
        } else {
            println!("warning: could not reach the worker to remove {image}");
        }
    }
    Ok(())
}
