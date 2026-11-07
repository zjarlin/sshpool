//! 真实交付闭环：默认忽略，需显式指定可达节点后运行。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=okm182-lan \
//!   cargo test --test delivery_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 走的是真正的统一入口：进程内启动 `axum::serve`，用 `sshpool::client::Client`
//! 提交项目、跟随日志、按任务 ID 回取产物——不直接调用 `runner` 内部函数，
//! 也不读写控制面文件绕过 API。容器标签使用一次性 UUID，结束时按标签复核残留。
use anyhow::{Context, Result, ensure};
use sshpool::{
    client::Client,
    config::{Build, Config, Node},
    model::Job,
    state::State,
};
use std::{fs, path::Path, sync::Arc, time::Duration};

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live-delivery".into(),
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

/// 平台必须与 Worker 真实架构一致：本项目明确拒绝自动模拟。
async fn platform(node: &Node) -> Result<String> {
    let arch =
        sshpool::transport::verified(node, "docker info --format '{{.Architecture}}'", 20).await?;
    Ok(format!(
        "linux/{}",
        sshpool::probe::platform_arch(String::from_utf8_lossy(&arch).trim())
    ))
}

/// 隔离的控制面目录 + 进程内 HTTP 服务；返回临时根、状态与已就绪的客户端。
async fn harness(node: &Node) -> Result<(tempfile::TempDir, Arc<State>, Client, String)> {
    let root = tempfile::tempdir()?;
    let token = "test-only-token-not-a-production-secret";
    fs::write(root.path().join("token"), token)?;
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
    // 端口取 0 由内核分配：不占用本机既有控制面端口，也不会与并行测试冲突。
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let routes = sshpool::api::routes(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, routes).await;
    });
    let endpoint = format!("http://{address}");
    let client = Client::new(endpoint.clone(), &root.path().join("token"), None)?;
    Ok((root, state, client, endpoint))
}

/// 一个只含公开演示内容的最小项目。
fn project(root: &Path, body: &str) -> Result<std::path::PathBuf> {
    let project = root.join("project");
    fs::create_dir(&project)?;
    fs::write(project.join("build.sh"), body)?;
    Ok(project)
}

fn build(platform: String) -> Build {
    Build {
        platform,
        command: vec!["sh".into(), "build.sh".into()],
        outputs: vec!["out".into()],
        memory_mib: 256,
        scratch_mib: 64,
        cpus: 0.5,
        timeout_secs: 120,
        ..Build::default()
    }
}

/// 经 API 列出任务，取唯一的那一条（响应是 Job 的 JSON 数组）。
async fn only_job(client: &Client) -> Result<Job> {
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(
        jobs.len() == 1,
        "expected exactly one job, got {}",
        jobs.len()
    );
    jobs.into_iter().next().context("missing job")
}

/// 任务结束后远端不能残留这个任务的容器（按标签查询，不看名字）。
async fn assert_no_container(node: &Node, id: uuid::Uuid) -> Result<()> {
    // 先等一次短暂的收敛，避免只看容器删除瞬间之前的快照。
    tokio::time::sleep(Duration::from_secs(1)).await;
    let containers = sshpool::transport::verified(
        node,
        &format!(
            "docker ps -a --filter {} --format {}",
            sshpool::transport::quote(&format!("label=io.sshpool.job={id}")),
            sshpool::transport::quote("{{.Names}}")
        ),
        20,
    )
    .await?;
    ensure!(
        String::from_utf8_lossy(&containers).trim().is_empty(),
        "a container survived the job: {}",
        String::from_utf8_lossy(&containers)
    );
    Ok(())
}

/// 提交 → 执行 → 日志/退出码 → 产物回传 → 清理，全部走统一入口。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn unified_entry_delivers_logs_exit_code_and_artifacts() -> Result<()> {
    let node = node()?;
    let (root, _state, client, endpoint) = harness(&node).await?;
    let project = project(
        root.path(),
        "mkdir -p out\n\
         uname -m > out/arch.txt\n\
         awk 'BEGIN {s=0; for (i=1; i<=200000; i++) s=(s+i)%1000003; print s}' > out/sum.txt\n\
         printf 'line-one\\n' && printf 'line-two\\n' >&2\n\
         cat out/arch.txt out/sum.txt\n",
    )?;
    let mut build = build(platform(&node).await?);
    build.command = vec!["sh".into(), "build.sh".into()];

    let code = client.run(&project, build).await?;
    ensure!(code == 0, "the unified entry reported exit code {code}");

    let job = only_job(&client).await?;
    ensure!(
        job.phase == sshpool::model::Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        job.exit_code == Some(0),
        "unexpected exit code {:?}",
        job.exit_code
    );
    ensure!(job.artifacts, "the job must publish artifacts");
    ensure!(
        job.cleanup_confirmed,
        "container removal was not confirmed: {:?}",
        job.message
    );
    ensure!(
        job.message
            .as_deref()
            .unwrap_or_default()
            .contains("exit 0"),
        "the terminal message must keep the exit code: {:?}",
        job.message
    );
    ensure!(
        job.source_sha256
            .as_deref()
            .is_some_and(|digest| digest.len() == 64),
        "the job record must keep the source digest"
    );

    // 日志必须真的带着远端 stdout 与 stderr 回到工作台。
    let log_text = String::from_utf8_lossy(&client.log(job.id, 0).await?).to_string();
    ensure!(
        log_text.contains("line-one"),
        "stdout was not delivered to the log: {log_text}"
    );
    ensure!(
        log_text.contains("line-two"),
        "stderr was not delivered to the log: {log_text}"
    );

    // 事件链必须覆盖提交、分配、创建、导入、执行、导出、清理与终态。
    let events = client.get(&format!("/v1/jobs/{}/events", job.id)).await?;
    let kinds = events
        .as_array()
        .context("events must be an array")?
        .iter()
        .filter_map(|event| event["kind"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "submitted",
        "assigned",
        "image_check",
        "container_create",
        "source_import",
        "execution",
        "artifact_export",
        "cleanup",
        "finished",
    ] {
        ensure!(
            kinds.contains(&expected),
            "missing event {expected}: {kinds:?}"
        );
    }
    ensure!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "cleanup" && event["detail"] == "confirmed"),
        "cleanup must be recorded as confirmed: {events}"
    );

    // 审计还要能被 CLI 按任务 ID 查到：走真实二进制 + 真实 HTTP 入口，
    // 不用 API 直接读文件，否则「CLI 可以按任务 ID 查询事件」这一步没有被证明。
    //
    // 必须用 spawn_blocking：本测试是 current-thread 运行时，同步等待子进程会把
    // 进程内 axum 服务一起阻塞，请求永远等不到响应（实测 150s 超时）。
    let cli = {
        let home = root.path().to_path_buf();
        let endpoint = endpoint.clone();
        let id = job.id.to_string();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
                .arg("--home")
                .arg(&home)
                .arg("--endpoint")
                .arg(&endpoint)
                .args(["events", &id])
                .output()
        })
        .await??
    };
    ensure!(
        cli.status.success(),
        "sshpool events failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_events: Vec<serde_json::Value> = serde_json::from_slice(&cli.stdout)?;
    ensure!(
        cli_events.len() == kinds.len(),
        "the CLI must return the same event count as the API: {} vs {}",
        cli_events.len(),
        kinds.len()
    );
    ensure!(
        !String::from_utf8_lossy(&cli.stdout).contains("test-only-token"),
        "the CLI must not print the controller token"
    );

    // 产物：解到全新目录，内容必须与容器里算出来的完全一致。
    let output = root.path().join("results");
    let unpacked = client.fetch(job.id, &output).await?;
    ensure!(unpacked == output, "fetch returned an unexpected path");
    let arch = fs::read_to_string(output.join("out/arch.txt"))?;
    // `uname -m` 报 x86_64 / aarch64，镜像平台写 amd64 / arm64：用同一映射比较，
    // 否则只是两个词表不同，断言本身就会误报。
    ensure!(
        sshpool::probe::platform_arch(arch.trim())
            == job.build.platform.trim_start_matches("linux/"),
        "artifact arch {} does not match the requested platform {}",
        arch.trim(),
        job.build.platform
    );
    let sum = fs::read_to_string(output.join("out/sum.txt"))?;
    // 独立算式复核：等差数列 1..=200000 的和模 1000003。
    let expected = (200000_u64 * 200001 / 2) % 1000003;
    ensure!(
        sum.trim() == expected.to_string(),
        "artifact sum {} != expected {}",
        sum.trim(),
        expected
    );

    // 同一目录再回取一次必须失败：产物交付不覆盖任何已存在的文件。
    ensure!(
        client.fetch(job.id, &output).await.is_err(),
        "fetch must refuse an existing output directory"
    );

    assert_no_container(&node, job.id).await?;
    Ok(())
}

/// 非零退出码必须原样带回工作台，并且不发布任何产物。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn nonzero_exit_is_reported_without_publishing_artifacts() -> Result<()> {
    let node = node()?;
    let (root, _state, client, _endpoint) = harness(&node).await?;
    let project = project(
        root.path(),
        "mkdir -p out\n\
         echo 'partial' > out/partial.txt\n\
         echo 'deliberate failure' >&2\n\
         exit 7\n",
    )?;
    let code = client.run(&project, build(platform(&node).await?)).await?;
    ensure!(code == 7, "the unified entry must return 7, got {code}");

    let job = only_job(&client).await?;
    ensure!(
        job.phase == sshpool::model::Phase::Failed,
        "unexpected phase {:?}",
        job.phase
    );
    ensure!(
        job.exit_code == Some(7),
        "unexpected exit code {:?}",
        job.exit_code
    );
    ensure!(!job.artifacts, "a failed job must not publish artifacts");
    ensure!(
        job.cleanup_confirmed,
        "a failed job still has to clean up: {:?}",
        job.message
    );
    // 产物接口必须明确拒绝，而不是回一个空归档。
    ensure!(
        client
            .get(&format!("/v1/jobs/{}/artifacts", job.id))
            .await
            .is_err(),
        "artifacts must not be downloadable for a failed job"
    );
    assert_no_container(&node, job.id).await?;
    Ok(())
}

/// 命令成功但声明的产物缺失时必须失败：不能把不完整的归档当成交付物。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn missing_declared_output_fails_closed() -> Result<()> {
    let node = node()?;
    let (root, _state, client, _endpoint) = harness(&node).await?;
    // 声明 out，却只写了别处：导出的 tar 会因为没有匹配路径而失败。
    let project = project(
        root.path(),
        "mkdir -p elsewhere\n echo ok > elsewhere/f.txt\nexit 0\n",
    )?;
    let code = client.run(&project, build(platform(&node).await?)).await?;
    ensure!(
        code != 0,
        "a missing declared output must not be reported as success"
    );

    let job = only_job(&client).await?;
    ensure!(
        job.phase == sshpool::model::Phase::Failed,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(!job.artifacts, "no artifacts may be published");
    ensure!(
        job.message
            .as_deref()
            .unwrap_or_default()
            .contains("artifact export failed"),
        "the failure must name the real reason: {:?}",
        job.message
    );
    assert_no_container(&node, job.id).await?;
    Ok(())
}
