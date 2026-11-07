//! 节点探测必须发生在调度锁之外。
//!
//! 一台「TCP 可连接但从不发 SSH banner」的节点会让 `ssh` 一直等到
//! `ConnectTimeout`（transport 固定 5s）。若探测在 `state.scheduling` 锁内进行，
//! 这段时间里所有任务派发都会被串行阻塞。本测试用本地静默监听器确定性复现该
//! 阻塞场景，不需要 Docker、不需要真实 Worker。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::{Build, Config, Node},
    model::{Job, Phase, now},
    runner, scheduler,
    state::State,
};
use std::{
    io::Write,
    net::TcpListener,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

/// 接受连接后既不回 banner 也不关闭；真实 `ssh` 会在 banner 交換阶段超时。
fn silent_listener() -> Result<(u16, mpsc::UnboundedReceiver<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let (accepted, receiver) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
            let _ = accepted.send(());
        }
    });
    Ok((port, receiver))
}

fn quiet_ssh_config(path: &Path, port: u16) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    write!(
        file,
        "Host hangtest\n  HostName 127.0.0.1\n  Port {port}\n  User probe\n  \
         IdentitiesOnly yes\n  IdentityFile /dev/null\n  StrictHostKeyChecking yes\n"
    )?;
    Ok(())
}

fn hanging_node(config: &Path) -> Node {
    Node {
        name: "hangtest".into(),
        ssh: "hangtest".into(),
        images: vec!["alpine:3.22".into()],
        ssh_config: Some(config.to_path_buf()),
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
    }
}

fn queued_job() -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: Build::default(),
        phase: Phase::Queued,
        created_at: now(),
        finished_at: None,
        attempts: Vec::new(),
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
    }
}

#[tokio::test]
async fn an_unreachable_worker_does_not_hold_the_scheduling_lock() -> Result<()> {
    // 没有 OpenSSH 客户端的环境无法复现「banner 超时」，明确跳过而不是假装通过。
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("skipped: ssh client is unavailable");
        return Ok(());
    }

    let (port, mut accepted) = silent_listener()?;
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let ssh_config = root.path().join("ssh_config");
    quiet_ssh_config(&ssh_config, port)?;
    let config = Config {
        min_free_disk_mib: 0,
        nodes: vec![hanging_node(&ssh_config)],
        ..Config::default()
    };
    let state = State::load(root.path().to_path_buf(), config)?;
    let job = queued_job();
    std::fs::create_dir_all(state.dir(job.id))?;
    state.jobs.lock().await.insert(job.id, job.clone());

    let runner_state = Arc::clone(&state);
    let mut running = tokio::spawn(async move { runner::run(runner_state, job.id).await });

    // 等到探测真的连上了监听器：此刻 runner 正在锁外等待 `ssh` 超时。
    let reached = tokio::time::timeout(Duration::from_secs(15), accepted.recv())
        .await
        .context("the probe never reached the silent listener")?;
    ensure!(
        reached.is_some(),
        "the silent listener closed before accepting the probe"
    );

    let started = Instant::now();
    let guard = tokio::time::timeout(Duration::from_secs(1), state.scheduling.lock())
        .await
        .context("scheduling lock is held while a worker probe is still running")?;
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(1),
        "scheduling lock acquire waited {waited:?} behind an unreachable worker"
    );
    assert!(
        !running.is_finished(),
        "the probe finished too early to prove anything"
    );
    drop(guard);

    // 探测器应继续走完 ConnectTimeout，然后任务因「无可用节点」失败而不是卡住。
    tokio::time::timeout(Duration::from_secs(30), &mut running)
        .await
        .context("the job never left the probe phase")???;
    let settled = state
        .jobs
        .lock()
        .await
        .get(&job.id)
        .cloned()
        .context("job disappeared")?;
    assert_eq!(settled.phase, Phase::Failed);
    let message = settled.message.unwrap_or_default();
    ensure!(
        message.contains("no eligible worker") && message.contains("hangtest"),
        "unexpected failure message: {message}"
    );
    // 探测本身确实消耗了 ConnectTimeout，否则这个测试没有复现目标场景。
    assert!(
        started.elapsed() > Duration::from_secs(2),
        "the silent listener did not stall the probe: {:?}",
        started.elapsed()
    );
    Ok(())
}

/// 没有探测快照的节点必须被拒绝，而不是当成「资源充足」。
#[tokio::test]
async fn a_worker_without_a_health_snapshot_is_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let config = Config {
        min_free_disk_mib: 0,
        nodes: vec![hanging_node(&root.path().join("unused-ssh-config"))],
        ..Config::default()
    };
    let state = State::load(root.path().to_path_buf(), config)?;
    let nodes = state.nodes().await;
    assert!(
        state.health_is_stale(&nodes).await,
        "缓存必须从「没有快照」开始"
    );
    let health = state.health_snapshot(&nodes).await;
    assert_eq!(health.len(), nodes.len(), "快照必须与节点一一对应");
    let reason = scheduler::score(&nodes[0], &health[0], &Build::default(), &[])
        .expect_err("未探测节点不得参与调度");
    assert!(
        reason.contains("not probed"),
        "原因必须说明尚未探测: {reason}"
    );
    Ok(())
}

/// 并发探测只能产生一轮 SSH：等待者复用前一个调用者的新鲜快照。
#[tokio::test]
async fn concurrent_probes_share_one_round_trip() -> Result<()> {
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("skipped: ssh client is unavailable");
        return Ok(());
    }

    let (port, mut accepted) = silent_listener()?;
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let ssh_config = root.path().join("ssh_config");
    quiet_ssh_config(&ssh_config, port)?;
    let config = Config {
        min_free_disk_mib: 0,
        nodes: vec![hanging_node(&ssh_config)],
        ..Config::default()
    };
    let state = State::load(root.path().to_path_buf(), config)?;
    let nodes = state.nodes().await;

    let first = {
        let state = Arc::clone(&state);
        let nodes = nodes.clone();
        tokio::spawn(async move { state.ensure_health(&nodes).await })
    };
    let reached = tokio::time::timeout(Duration::from_secs(15), accepted.recv())
        .await
        .context("the first probe never reached the silent listener")?;
    ensure!(reached.is_some(), "the silent listener closed early");

    // 第二个调用者在探测锁上排队；第一个探测结束后它必须直接复用快照。
    let second = {
        let state = Arc::clone(&state);
        let nodes = nodes.clone();
        tokio::spawn(async move { state.ensure_health(&nodes).await })
    };
    let first_health = tokio::time::timeout(Duration::from_secs(30), first)
        .await
        .context("the first probe never finished")??;
    let second_health = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .context("the second probe waited for a fresh snapshot instead of reusing it")??;
    assert_eq!(
        serde_json::to_value(&first_health)?,
        serde_json::to_value(&second_health)?,
        "两个调用者必须看到同一份快照"
    );
    assert!(
        !state.health_is_stale(&nodes).await,
        "探测完成后快照必须是新鲜的"
    );
    assert!(
        accepted.try_recv().is_err(),
        "第二个调用者不应再发起一轮 SSH"
    );
    Ok(())
}

/// 管理员在「读节点 → 探测」期间禁用节点时，任务不得被派给刚停用的 Worker。
///
/// 节点开关由 `set_node_enabled` 在 `scheduling` 锁内修改；调度在拿到锁后必须重新
/// 读取节点列表，而不是复用在探测前拍下的旧快照。
#[tokio::test]
async fn a_node_disabled_during_the_probe_is_not_assigned() -> Result<()> {
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("skipped: ssh client is unavailable");
        return Ok(());
    }

    let (port, mut accepted) = silent_listener()?;
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let ssh_config = root.path().join("ssh_config");
    quiet_ssh_config(&ssh_config, port)?;
    let config = Config {
        min_free_disk_mib: 0,
        nodes: vec![hanging_node(&ssh_config)],
        ..Config::default()
    };
    std::fs::write(
        root.path().join("config.toml"),
        toml::to_string_pretty(&config)?,
    )?;
    let state = State::load(root.path().to_path_buf(), config)?;
    let job = queued_job();
    std::fs::create_dir_all(state.dir(job.id))?;
    state.jobs.lock().await.insert(job.id, job.clone());

    let runner_state = Arc::clone(&state);
    let running = tokio::spawn(async move { runner::run(runner_state, job.id).await });
    let reached = tokio::time::timeout(Duration::from_secs(15), accepted.recv())
        .await
        .context("the probe never reached the silent listener")?;
    ensure!(
        reached.is_some(),
        "the silent listener closed before accepting the probe"
    );

    // 探测仍在进行（尚未超过 ConnectTimeout）时停用节点。
    state.set_node_enabled("hangtest", false).await?;

    tokio::time::timeout(Duration::from_secs(30), running)
        .await
        .context("the job never finished after the node was disabled")???;
    let settled = state
        .jobs
        .lock()
        .await
        .get(&job.id)
        .cloned()
        .context("job disappeared")?;
    assert_eq!(settled.phase, Phase::Failed);
    assert!(
        settled.attempts.is_empty(),
        "the job must not be assigned to a node disabled during the probe: {:?}",
        settled.attempts
    );
    let message = settled.message.unwrap_or_default();
    assert!(
        message.contains("disabled"),
        "the failure must state the node is disabled: {message}"
    );
    Ok(())
}
