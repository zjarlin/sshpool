//! 真实远端核对：默认忽略，需显式指定可达节点后运行。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=okm182-lan cargo test --test watchdog_live -- --ignored --nocapture
//! ```
//!
//! 它只在临时目录创建状态，容器标签使用一次性 UUID；不触碰既有任务与业务容器。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::{Config, Node},
    model::{Attempt, Job, Phase},
    state::State,
    watchdog::{self, Proof, RemoteState},
};
use std::{fs, sync::Arc, time::Duration};

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
        slo: Default::default(),
    })
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn stopped_remote_container_is_proven_and_removed() -> Result<()> {
    let node = node()?;
    let id = uuid::Uuid::new_v4();
    let container = format!("sshpool-live-{id}");
    let create = format!(
        "docker create --name {} --label io.sshpool.job={id} --restart=no --network=none --read-only --entrypoint=/bin/sh alpine:3.22 -c 'sleep 1' && docker start {}",
        sshpool::transport::quote(&container),
        sshpool::transport::quote(&container)
    );
    sshpool::transport::checked(&node, &create, 60).await?;
    tokio::time::sleep(Duration::from_secs(4)).await;

    let state = sshpool::transport::checked(
        &node,
        &format!(
            "docker inspect --format {} {}",
            sshpool::transport::quote("{{.State.Running}}"),
            sshpool::transport::quote(&container)
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&state).trim() == "false",
        "lease did not stop the container"
    );
    ensure!(
        watchdog::inspect(&node, id, &container).await? == RemoteState::Stopped,
        "a stopped container must not be reported as running or absent"
    );
    // 标签不匹配时绝不把容器当成本任务。
    let other = uuid::Uuid::new_v4();
    assert!(watchdog::inspect(&node, other, &container).await.is_err());

    watchdog::remove_after_proof(&node, id, &container).await?;
    ensure!(
        watchdog::inspect(&node, id, &container).await? == RemoteState::Absent,
        "proof-backed removal must leave no container behind"
    );

    // 在线 reconcile：状态里有一条未确认清理时，凭远端状态直接解除隔离。
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let config = Config {
        nodes: vec![node.clone()],
        ..Config::default()
    };
    let state = State::load(root.path().to_path_buf(), config)?;
    let id = uuid::Uuid::new_v4();
    let container = format!("sshpool-live-{id}");
    sshpool::transport::checked(&node, &create_with(&container, id), 60).await?;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let job = Job {
        id,
        revision: 1,
        build: Default::default(),
        phase: Phase::Interrupted,
        created_at: 0,
        finished_at: Some(1),
        attempts: vec![Attempt {
            node: node.name.clone(),
            container: container.clone(),
            started_at: 0,
            outcome: Some("SSH connection interrupted".into()),
            cleanup_confirmed: Some(false),
            watchdog_deadline: None,
            cleanup_proof: None,
            finished_at: None,
            schedule: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    };
    state.jobs.lock().await.insert(id, job);
    let report = sshpool::reconcile::reconcile(&state, Some("live")).await?;
    assert_eq!(report.proven, 1, "{report:?}");
    assert_eq!(
        report.attempts[0].proof,
        Some(Proof::RemoteStopped.as_str().into())
    );
    let stored = state.jobs.lock().await.get(&id).cloned().unwrap();
    ensure!(stored.cleanup_confirmed, "proof must clear the quarantine");
    ensure!(
        watchdog::inspect(&node, id, &container).await? == RemoteState::Absent,
        "reconcile must remove the proven container"
    );
    let _ = Arc::strong_count(&state);
    Ok(())
}

fn create_with(container: &str, id: uuid::Uuid) -> String {
    format!(
        "docker create --name {} --label io.sshpool.job={id} --restart=no --network=none --read-only --entrypoint=/bin/sh alpine:3.22 -c 'sleep 1' && docker start {}",
        sshpool::transport::quote(container),
        sshpool::transport::quote(container)
    )
}

/// 仍在运行的容器必须拒绝放行，即使控制面记录里写着租约已过期。
/// 时间只是 SSH 不可达时的兜底，不能覆盖「实际还在跑」这个更强的反证。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn running_container_is_never_waved_through() -> Result<()> {
    let node = node()?;
    let id = uuid::Uuid::new_v4();
    let container = format!("sshpool-live-{id}");
    let create = format!(
        "docker create --name {} --label io.sshpool.job={id} --restart=no --network=none --read-only --entrypoint=/bin/sh alpine:3.22 -c 'sleep 120' && docker start {}",
        sshpool::transport::quote(&container),
        sshpool::transport::quote(&container)
    );
    sshpool::transport::checked(&node, &create, 60).await?;
    let cleanup = async {
        ensure!(
            watchdog::inspect(&node, id, &container).await? == RemoteState::Running,
            "a live container must be reported as running"
        );
        // 租约早已过期，但实际运行状态优先级更高。
        let attempt = Attempt {
            node: node.name.clone(),
            container: container.clone(),
            started_at: 0,
            outcome: Some("SSH connection interrupted".into()),
            cleanup_confirmed: Some(false),
            watchdog_deadline: Some(1),
            cleanup_proof: None,
            finished_at: None,
            schedule: None,
        };
        let decision = watchdog::decide(
            &attempt,
            Ok(RemoteState::Running),
            10_000,
            sshpool::reconcile::LEASE_CLOCK_SKEW_SECS,
        );
        ensure!(
            !decision.proven,
            "running container must not be proven terminated"
        );
        ensure!(
            watchdog::remove_after_proof(&node, id, &container)
                .await
                .is_err(),
            "removal must refuse a running container"
        );
        Ok(())
    }
    .await;
    let policy = async {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("token"),
            "test-only-token-not-a-production-secret",
        )?;
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let state = State::load(root.path().to_path_buf(), config)?;
        let job = Job {
            id,
            revision: 1,
            build: Default::default(),
            phase: Phase::Interrupted,
            created_at: 0,
            finished_at: Some(1),
            attempts: vec![Attempt {
                node: node.name.clone(),
                container: container.clone(),
                started_at: 0,
                outcome: Some("SSH connection interrupted".into()),
                cleanup_confirmed: Some(false),
                watchdog_deadline: Some(1),
                cleanup_proof: None,
                finished_at: None,
                schedule: None,
            }],
            exit_code: None,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: false,
            queue_deadline: None,
            source_sha256: None,
            owner: None,
        };
        state.jobs.lock().await.insert(id, job);
        let report = sshpool::reconcile::reconcile(&state, Some("live")).await?;
        ensure!(report.proven == 0, "{report:?}");
        ensure!(report.resumed.is_empty(), "{report:?}");
        let stored = state.jobs.lock().await.get(&id).cloned().unwrap();
        ensure!(!stored.cleanup_confirmed);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let removed = sshpool::transport::checked(
        &node,
        &format!(
            "docker rm -f {} >/dev/null",
            sshpool::transport::quote(&container)
        ),
        60,
    )
    .await;
    cleanup.and(policy).and(removed.map(|_| ()))
}
