//! 真实跨物理故障域恢复：默认忽略，需显式指定两台独立副本后运行。
//!
//! ```sh
//! SSHPOOL_LIVE_REPLICAS=okm182-lan,macmini-lan \
//!   cargo test --test control_state_live -- --ignored --nocapture
//! ```
//!
//! 这是「控制面主机丢失后从远端故障域恢复」的故障注入：控制面状态目录整体不可用
//! （用一个只有 config 与 token 的空目录模拟换机），只剩远端副本里已提交的归档。
//! 每台副本使用一次性 namespace，结束时删除，不触碰既有生产副本集合。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::{Build, Config, Replica},
    mirror,
    model::{Job, Phase},
    state::State,
};
use std::fs;

fn replica_targets() -> Result<Vec<String>> {
    let value =
        std::env::var("SSHPOOL_LIVE_REPLICAS").context("SSHPOOL_LIVE_REPLICAS is not set")?;
    let targets = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    ensure!(
        targets.len() == 2,
        "exactly two independent replicas are required, got {}",
        targets.len()
    );
    Ok(targets)
}

/// 每个副本登记一次，拿到不可逆主机身份摘要；失败域用目标别名区分。
async fn replica(name: &str, ssh: &str, namespace: &str) -> Result<Replica> {
    let host_id = mirror::prepare(ssh, None, namespace).await?;
    let replica = Replica {
        name: name.into(),
        ssh: ssh.into(),
        namespace: namespace.into(),
        failure_domain: format!("live-{name}"),
        expected_host_id_sha256: host_id,
        ssh_config: None,
        enabled: true,
    };
    sshpool::config::validate_replica(&replica)?;
    Ok(replica)
}

fn config(replicas: Vec<Replica>) -> Result<Config> {
    let config = Config {
        replica_min_ack: 2,
        replicas,
        ..Config::default()
    };
    sshpool::config::validate(&config)?;
    Ok(config)
}

/// 控制器主机只剩配置与 token：任务状态、回执和归档都不在本地。
fn fresh_home(root: &std::path::Path, name: &str, config: &Config) -> Result<std::path::PathBuf> {
    let home = root.join(name);
    fs::create_dir_all(&home)?;
    fs::write(
        home.join("token"),
        "live-control-state-token-placeholder-32+",
    )?;
    sshpool::config::save(&home, config)?;
    Ok(home)
}

/// 一个带显式产物的小归档，用来证明恢复的不只是 job.json。
fn artifacts_archive(path: &std::path::Path) -> Result<()> {
    let mut archive = tar::Builder::new(fs::File::create(path)?);
    let mut header = tar::Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, "out.txt", &b"result\n"[..])?;
    archive.finish()?;
    Ok(())
}

fn source_archive(path: &std::path::Path) -> Result<String> {
    let mut archive = tar::Builder::new(fs::File::create(path)?);
    let mut header = tar::Header::new_gnu();
    header.set_size(6);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, "main.txt", &b"probe\n"[..])?;
    archive.finish()?;
    sshpool::archive::sha256_file(path)
}

/// 在原控制面目录里完成一个任务；只有这里能写出 events.jsonl 与本地回执。
async fn publish_job(home: &std::path::Path, config: Config) -> Result<Job> {
    let id = uuid::Uuid::new_v4();
    let directory = home.join("jobs").join(id.to_string());
    fs::create_dir_all(&directory)?;
    let source = directory.join("source.tar");
    let source_sha256 = source_archive(&source)?;
    artifacts_archive(&directory.join("artifacts.tar"))?;
    fs::write(directory.join("log.txt"), "line one\nline two\n")?;
    let job = Job {
        id,
        revision: 0,
        build: Build {
            network: false,
            idempotent: true,
            ..Build::default()
        },
        phase: Phase::Queued,
        created_at: 1,
        finished_at: None,
        attempts: Vec::new(),
        exit_code: None,
        message: None,
        artifacts: true,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: Some(source_sha256),
        owner: None,
    };
    fs::write(directory.join("job.json"), serde_json::to_vec(&job)?)?;
    let state = State::load(home.to_path_buf(), config)?;
    state
        .finish(
            id,
            Phase::Succeeded,
            Some(0),
            "live control-state publication".into(),
            true,
        )
        .await?;
    state
        .jobs
        .lock()
        .await
        .get(&id)
        .cloned()
        .context("job disappeared after publication")
}

/// 在只有配置与 token 的新主机上重放控制面启动阶段。
async fn restore_on(
    name: &str,
    config: &Config,
    root: &std::path::Path,
) -> Result<Vec<uuid::Uuid>> {
    let home = fresh_home(root, name, config)?;
    mirror::restore_missing(config, &home).await
}

/// 删除一次性副本 namespace；路径必须落在专用根目录内且属于当前用户。
async fn wipe(target: &str, namespace: &str) -> Result<()> {
    let node = sshpool::config::Node {
        name: "cleanup".into(),
        ssh: target.into(),
        images: Vec::new(),
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
    };
    let source = format!(
        r#"import os,shutil
namespace={namespace:?}
root=os.path.expanduser('~/.sshpool-replica')
target=os.path.join(root,namespace)
if os.path.islink(target):
    raise SystemExit('refusing to follow a symlink')
if not target.startswith(root+os.sep):
    raise SystemExit('refusing to escape the replica root')
if os.path.isdir(target):
    if os.stat(target).st_uid!=os.getuid():
        raise SystemExit('replica namespace is owned by another user')
    shutil.rmtree(target)
print('removed')
"#
    );
    let script = format!("python3 -c {}", sshpool::transport::quote(&source));
    sshpool::transport::checked(&node, &script, 60).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires two reachable SSH replicas in distinct failure domains"]
async fn controller_state_is_recovered_from_remote_failure_domains() -> Result<()> {
    let targets = replica_targets()?;
    let root = tempfile::tempdir()?;
    let namespace = format!("live-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let first = replica("first", &targets[0], &namespace).await?;
    let second = replica("second", &targets[1], &namespace).await?;
    ensure!(
        first.expected_host_id_sha256 != second.expected_host_id_sha256,
        "the two replicas must be different physical hosts"
    );
    let config = config(vec![first.clone(), second.clone()])?;
    let result = run(&targets, &root, &config, &first, &second).await;
    for target in &targets {
        wipe(target, &namespace)
            .await
            .with_context(|| format!("cleaning up {target}"))?;
    }
    result
}

async fn run(
    targets: &[String],
    root: &tempfile::TempDir,
    config: &Config,
    first: &Replica,
    second: &Replica,
) -> Result<()> {
    // 1. 原控制面：提交到两个独立故障域，本地保留终态事件与提交回执。
    let origin = fresh_home(root.path(), "controller-a", config)?;
    let published = publish_job(&origin, config.clone()).await?;
    for target in [first, second] {
        let ids = mirror::list(target).await?;
        ensure!(
            ids.contains(&published.id),
            "replica {} did not receive the job",
            target.name
        );
    }

    // 2. 控制面主机整体丢失：新主机只有 config 与 token，任务目录为空。
    let restored = restore_on("controller-b", config, root.path()).await?;
    ensure!(
        restored == vec![published.id],
        "restore returned {restored:?}, expected the published job"
    );
    let recovered = root
        .path()
        .join("controller-b")
        .join("jobs")
        .join(published.id.to_string());
    let record: Job = serde_json::from_slice(&fs::read(recovered.join("job.json"))?)?;
    ensure!(record.phase == Phase::Succeeded, "recovered phase changed");
    ensure!(record.exit_code == Some(0), "recovered exit code changed");
    ensure!(
        record.source_sha256 == published.source_sha256,
        "recovered source digest changed"
    );
    ensure!(
        record.revision >= published.revision,
        "recovered revision regressed: {} < {}",
        record.revision,
        published.revision
    );
    // 终态事件必须随归档一起恢复，否则恢复出来的任务缺少「何时结束」的证据。
    // 日志与已声明产物也属于确认状态，不能只恢复元数据。
    ensure!(
        record.artifacts,
        "the recovered record lost its artifact flag"
    );
    ensure!(
        fs::read_to_string(recovered.join("log.txt"))? == "line one\nline two\n",
        "the recovered log differs from the published one"
    );
    ensure!(
        recovered.join("artifacts.tar").is_file(),
        "the recovered record lost its artifacts archive"
    );
    sshpool::archive::validate(
        &recovered.join("artifacts.tar"),
        1048576,
        Some(&["out.txt".to_string()]),
    )?;
    let events = fs::read_to_string(recovered.join("events.jsonl"))?;
    ensure!(
        events.contains("\"finished\""),
        "the recovered record is missing its terminal event:\n{events}"
    );
    let restored_state = State::load(root.path().join("controller-b"), config.clone())?;
    ensure!(
        restored_state.jobs.lock().await.contains_key(&published.id),
        "the recovered controller cannot load the restored job"
    );

    // 3. 一个故障域也失去：quorum 2 仍由「新主机 + 一台远端」满足。
    let only_second = config_with(vec![second.clone()])?;
    let after_one_loss = restore_on("controller-c", &only_second, root.path()).await?;
    ensure!(
        after_one_loss == vec![published.id],
        "a single surviving fault domain did not recover the job: {after_one_loss:?}"
    );

    // 4. 恢复只覆盖任务状态：换机后 token 与配置仍须由运维独立提供。
    let secretless = root.path().join("controller-e");
    fs::create_dir_all(&secretless)?;
    sshpool::config::save(&secretless, config)?;
    ensure!(
        State::load(secretless, config.clone()).is_err(),
        "a recovered directory without the token must not load"
    );

    // 5. 两台副本都丢失：既拒绝启动，也不能把空状态当成「没有任务」。
    for target in targets {
        wipe(target, &first.namespace)
            .await
            .with_context(|| format!("removing {target} before the quorum check"))?;
    }
    let refusal = restore_on("controller-d", config, root.path())
        .await
        .expect_err("a controller without any live fault domain must not start");
    ensure!(
        format!("{refusal:#}").contains("quorum not met at startup"),
        "unexpected refusal: {refusal:#}"
    );
    ensure!(
        !root
            .path()
            .join("controller-d")
            .join("jobs")
            .join(published.id.to_string())
            .exists(),
        "a failed startup must not resurrect the job from a wiped fault domain"
    );
    Ok(())
}

fn config_with(replicas: Vec<Replica>) -> Result<Config> {
    let config = Config {
        replica_min_ack: 2,
        replicas,
        ..Config::default()
    };
    sshpool::config::validate(&config)?;
    Ok(config)
}
