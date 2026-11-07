//! 工作台之外的真实硬件：ARM64 工作台经统一入口提交 linux/amd64 任务。
//!
//! ```sh
//! # 先在工作台构建当前源码的客户端（测试用二进制，不安装）
//! scripts/prepare-live-workbench.sh sshpool-anchor
//! SSHPOOL_LIVE_WORKBENCH=sshpool-anchor \
//! SSHPOOL_LIVE_WORKER=okm182-lan \
//! SSHPOOL_LIVE_WORKBENCH_BIN=/tmp/sshpool-src/target/release/sshpool \
//!   cargo test --test hardware_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 控制面在**本测试进程内**启动，只绑回环；工作台通过 `host.lima.internal`
//! （可覆盖）访问它，因此这条链路是「工作台 → 控制面 → Worker」的真实三段，
//! 不是在同一台机器上自问自答。工作台侧执行的是真实 CLI 二进制：
//! 提交、跟随、回取都发生在工作台上，测试只读结果。
//!
//! 断言重点：
//! - 工作台是 ARM64、Worker 是 x86_64（选错机器直接失败，不猜）
//! - 任务确实在 Worker 的 Docker 里以该任务标签运行，工作台没有这个容器
//! - 产物回到工作台，架构与数值经独立算式复核
//! - `uname`/`nproc` 报工作台，`status` 分节点报资源，任务记录标明实际 Worker
use anyhow::{Context, Result, ensure};
use sshpool::{
    client::Client,
    config::{Config, Node},
    model::{Job, Phase},
    state::State,
    transport,
};
use std::{
    fs,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

const IMAGE: &str = "alpine:3.22";

fn env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is not set"))?;
    ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(value.trim().to_string())
}

/// 登记用的节点：工作台优先级更高，用来证明「平台不匹配优先于优先级」。
fn node(name: &str, ssh: String, priority: i32) -> Node {
    Node {
        name: name.into(),
        ssh,
        images: vec![IMAGE.into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority,
    }
}

struct Live {
    workbench: Node,
    worker: Node,
    /// 工作台上由当前源码构建出的 CLI；不走历史安装版。
    bin: String,
    /// 工作台侧看到控制面宿主的名字；Lima 默认 host.lima.internal。
    host: String,
}

fn live() -> Result<Live> {
    let workbench = env("SSHPOOL_LIVE_WORKBENCH")?;
    let worker = env("SSHPOOL_LIVE_WORKER")?;
    ensure!(
        workbench != worker,
        "workbench and worker must be different hosts, both are {workbench}"
    );
    let bin = env("SSHPOOL_LIVE_WORKBENCH_BIN")?;
    let host = std::env::var("SSHPOOL_LIVE_WORKBENCH_HOST")
        .unwrap_or_else(|_| "host.lima.internal".into());
    Ok(Live {
        workbench: node("workbench", workbench, 100),
        worker: node("worker", worker, 10),
        bin,
        host,
    })
}

async fn capture(node: &Node, script: &str, seconds: u64) -> Result<(i32, String, String)> {
    let (code, stdout, stderr) = transport::capture(node, script, seconds).await?;
    Ok((
        code,
        String::from_utf8_lossy(&stdout).to_string(),
        String::from_utf8_lossy(&stderr).to_string(),
    ))
}

async fn text(node: &Node, script: &str, seconds: u64) -> Result<String> {
    Ok(capture(node, script, seconds).await?.1.trim().to_string())
}

/// `docker info` 报告的架构；容器平台必须与它一致，本项目拒绝自动模拟。
async fn runtime_arch(node: &Node) -> Result<String> {
    Ok(sshpool::probe::platform_arch(
        &text(node, "docker info --format '{{.Architecture}}'", 20).await?,
    )
    .to_string())
}

/// 带 stdin 的单次命令：用于把 token 与项目文件写进工作台，避免出现在 argv 里。
async fn upload(node: &Node, script: &str, bytes: &[u8]) -> Result<()> {
    let mut command = transport::command(node, script);
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().context("missing stdin")?;
        stdin.write_all(bytes).await?;
    }
    let output = child.wait_with_output().await?;
    ensure!(
        output.status.success(),
        "upload to {} failed: {}",
        node.name,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// 隔离的控制面：临时目录 + 回环随机端口，不碰 `~/.sshpool` 与生产控制面。
async fn harness(nodes: Vec<Node>) -> Result<(tempfile::TempDir, Arc<State>, Client, String)> {
    let root = tempfile::tempdir()?;
    let token = "test-only-token-not-a-production-secret";
    fs::write(root.path().join("token"), token)?;
    let config = Config {
        min_free_disk_mib: 0,
        max_upload_mib: 16,
        max_artifact_mib: 16,
        max_log_mib: 16,
        max_active_jobs: 1,
        nodes,
        ..Config::default()
    };
    sshpool::config::validate(&config)?;
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
    Ok((root, state, client, format!("http://{address}")))
}

/// 工作台侧的一次性目录：token、项目与 `sshpool.toml` 都写在这里。
struct Remote {
    root: String,
}

impl Remote {
    async fn create(workbench: &Node, id: &str) -> Result<Self> {
        let root = format!("/tmp/sshpool-live-{id}");
        let (code, _, stderr) = capture(
            workbench,
            &format!(
                "set -eu; umask 077; mkdir -p {} {}/project",
                transport::quote(&root),
                transport::quote(&root),
            ),
            20,
        )
        .await?;
        ensure!(code == 0, "creating the workbench dir failed: {stderr}");
        Ok(Self { root })
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.root)
    }

    /// 未加引号的远端脚本：`transport::command` 负责整段转义。
    fn token_script(&self) -> String {
        format!(
            "set -eu; umask 077; cat > {}",
            transport::quote(&self.path("token"))
        )
    }

    async fn remove(&self, workbench: &Node) {
        // 只删本次创建的目录；名字带一次性 UUID，不会命中其他路径。
        let _ = capture(
            workbench,
            &format!("rm -rf {}", transport::quote(&self.root)),
            20,
        )
        .await;
    }
}

fn project_toml(platform: &str) -> String {
    format!(
        r#"image = "{IMAGE}"
platform = "{platform}"
command = ["sh", "build.sh"]
outputs = ["out"]
memory_mib = 256
scratch_mib = 64
cpus = 1.0
timeout_secs = 120
"#
    )
}

/// 工作台上执行的 CLI 前缀：显式 home、endpoint 与 token 文件。
///
/// 三项都必须显式传：工作台的登录环境里有 `SSHPOOL_ENDPOINT` / `SSHPOOL_TOKEN_FILE`
/// 指向生产控制面，clap 的 env 回退会在只给 `--home` 时用上那个 token——
/// 结果是拿着生产 token 去打临时控制面，得到 401。这不是测试洁癖，是真实误连。
fn cli_prefix(live: &Live, remote: &Remote, endpoint: &str) -> String {
    format!(
        "{} --home {} --endpoint {} --token-file {}",
        transport::quote(&live.bin),
        transport::quote(&remote.root),
        transport::quote(endpoint),
        transport::quote(&remote.path("token"))
    )
}

/// 只列本任务标签的容器名；不看名字前缀，避免与残留容器混淆。
async fn job_containers(node: &Node, id: uuid::Uuid) -> Result<Vec<String>> {
    let output = text(
        node,
        &format!(
            "docker ps -a --filter {} --format {}",
            transport::quote(&format!("label=io.sshpool.job={id}")),
            transport::quote("{{.Names}}")
        ),
        20,
    )
    .await?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

async fn all_job_containers(node: &Node) -> Result<usize> {
    let output = text(
        node,
        "docker ps -aq --filter label=io.sshpool.job | wc -l",
        20,
    )
    .await?;
    Ok(output.trim().parse()?)
}

async fn only_job(client: &Client) -> Result<Job> {
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(jobs.len() == 1, "expected one job, got {}", jobs.len());
    jobs.into_iter().next().context("missing job")
}

/// ARM64 工作台提交 linux/amd64：计算发生在独立 x86_64 Worker 上，产物回到工作台。
#[tokio::test]
#[ignore = "requires an ARM64 SSH workbench and an independent x86_64 Docker worker"]
async fn an_arm64_workbench_offloads_an_amd64_build_to_an_independent_worker() -> Result<()> {
    let live = live()?;
    // 机器角色必须先对得上：拿错主机就没有「异构卸载」可言。
    ensure!(
        runtime_arch(&live.workbench).await? == "arm64",
        "the workbench must be ARM64 to prove a cross-architecture submission"
    );
    ensure!(
        runtime_arch(&live.worker).await? == "amd64",
        "the worker must be x86_64 to prove the task did not stay on the workbench"
    );

    let (root, _state, client, endpoint) =
        harness(vec![live.workbench.clone(), live.worker.clone()]).await?;
    let remote_endpoint = format!(
        "http://{}:{}",
        live.host,
        endpoint.rsplit(':').next().unwrap()
    );
    let remote = Remote::create(&live.workbench, &uuid::Uuid::new_v4().to_string()).await?;
    let before = all_job_containers(&live.workbench).await?;

    // 工作台侧项目只含公开演示内容。
    upload(
        &live.workbench,
        &remote.token_script(),
        b"test-only-token-not-a-production-secret",
    )
    .await?;
    let build = br#"set -eu
mkdir -p out
uname -m > out/arch.txt
nproc > out/cpus.txt
sleep 10
awk 'BEGIN {s=0; for (i=1; i<=200000; i++) s=(s+i)%1000003; print s}' > out/sum.txt
cat out/arch.txt out/sum.txt
"#;
    upload(
        &live.workbench,
        &format!(
            "set -eu; umask 066; cat > {}",
            transport::quote(&format!("{}/project/build.sh", remote.root))
        ),
        build,
    )
    .await?;
    upload(
        &live.workbench,
        &format!(
            "set -eu; umask 066; cat > {}",
            transport::quote(&format!("{}/project/sshpool.toml", remote.root))
        ),
        project_toml("linux/amd64").as_bytes(),
    )
    .await?;

    let prefix = cli_prefix(&live, &remote, &remote_endpoint);
    let command = format!(
        "cd {} && {prefix} run 2>&1",
        transport::quote(&format!("{}/project", remote.root))
    );
    let workbench = live.workbench.clone();
    let mut submit = tokio::spawn(async move { capture(&workbench, &command, 300).await });

    // 任务一旦被领取，就在 Worker 上等容器出现；sleep 10 给观测留出窗口。
    // 提交本身失败时必须立刻报出来，而不是等到超时后说「没提交任务」。
    let mut job = None;
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if submit.is_finished() {
            let (code, stdout, stderr) = (&mut submit).await??;
            anyhow::bail!(
                "the workbench CLI exited before any job appeared: code={code}\nstdout={stdout}\nstderr={stderr}"
            );
        }
        if let Ok(jobs) = client.get("/v1/jobs").await
            && let Ok(list) = serde_json::from_value::<Vec<Job>>(jobs)
            && list.len() == 1
        {
            job = list.into_iter().next();
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let job = job.context("the workbench never submitted a job")?;
    ensure!(
        job.build.platform == "linux/amd64",
        "the build must request linux/amd64, got {}",
        job.build.platform
    );

    // Worker 上必须出现带该任务标签的运行容器，且执行的是项目脚本。
    let mut container = None;
    let mut top = String::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(names) = job_containers(&live.worker, job.id).await
            && let Some(name) = names.first()
        {
            container = Some(name.clone());
            if let Ok((code, stdout, _)) = capture(
                &live.worker,
                &format!("docker top {}", transport::quote(name)),
                20,
            )
            .await
                && code == 0
            {
                top = stdout;
                if top.contains("build.sh") {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let container = container.context("the worker never created a container for this job")?;
    ensure!(
        top.contains("build.sh"),
        "the worker container never ran the project script: {top}"
    );
    // 观测值打印出来供 `docs/evidence` 引用；断言本身不依赖这些文字。
    println!(
        "hardware: job={} workbench=aarch64 worker=x86_64 container={container}",
        job.id
    );
    println!(
        "hardware: worker docker top matched build.sh ({} lines)",
        top.lines().count()
    );

    // 同一时刻工作台上不能有该任务的容器：任务没有在工作台上执行。
    ensure!(
        job_containers(&live.workbench, job.id).await?.is_empty(),
        "the workbench must not execute the task locally"
    );

    let (code, stdout, stderr) = submit.await??;
    ensure!(
        code == 0,
        "the workbench CLI failed: code={code}\nstdout={stdout}\nstderr={stderr}"
    );
    ensure!(
        stdout.contains("x86_64"),
        "the delivered log must come from the x86_64 worker: {stdout}"
    );

    let job = only_job(&client).await?;
    ensure!(
        job.phase == Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        job.attempts.last().map(|a| a.node.as_str()) == Some("worker"),
        "the task must be assigned to the x86_64 worker: {:?}",
        job.attempts
    );
    ensure!(
        !job.attempts.iter().any(|a| a.node == "workbench"),
        "the workbench must never receive the amd64 attempt"
    );
    ensure!(
        job.cleanup_confirmed,
        "cleanup was not confirmed: {:?}",
        job.message
    );

    // 产物回取发生在工作台上，测试只读工作台里的文件。
    let results = format!("{}/results", remote.root);
    let (code, out, err) = capture(
        &live.workbench,
        &format!(
            "{prefix} fetch {} --output {}",
            job.id,
            transport::quote(&results)
        ),
        120,
    )
    .await?;
    ensure!(code == 0, "fetch on the workbench failed: {err}");
    ensure!(
        out.contains(&results),
        "fetch must report the real path: {out}"
    );
    let arch = text(
        &live.workbench,
        &format!(
            "cat {}",
            transport::quote(&format!("{results}/out/arch.txt"))
        ),
        20,
    )
    .await?;
    ensure!(
        sshpool::probe::platform_arch(&arch) == "amd64",
        "the artifact must be built on x86_64, got {arch}"
    );
    let sum = text(
        &live.workbench,
        &format!(
            "cat {}",
            transport::quote(&format!("{results}/out/sum.txt"))
        ),
        20,
    )
    .await?;
    let expected = (200_000_u64 * 200_001 / 2) % 1_000_003;
    ensure!(
        sum == expected.to_string(),
        "artifact sum {sum} != independently computed {expected}"
    );
    println!("hardware: artifact arch={arch} sum={sum} expected={expected}");

    // 远端清理与工作台无残留都用标签核对，不看容器名。
    ensure!(
        job_containers(&live.worker, job.id).await?.is_empty(),
        "the worker still has container {container} for the finished job"
    );
    ensure!(
        job_containers(&live.workbench, job.id).await?.is_empty(),
        "the workbench still has a container for this job"
    );
    ensure!(
        all_job_containers(&live.workbench).await? == before,
        "the workbench container count changed"
    );

    remote.remove(&live.workbench).await;
    // 临时控制面目录随 TempDir 一起删除，不触碰本机 `~/.sshpool`。
    drop(root);
    Ok(())
}

/// 工作台指标与计算池能力必须分开报告，任务记录指明实际 Worker。
#[tokio::test]
#[ignore = "requires an ARM64 SSH workbench and an independent x86_64 Docker worker"]
async fn workbench_and_pool_capabilities_are_reported_separately() -> Result<()> {
    let live = live()?;
    ensure!(
        runtime_arch(&live.workbench).await? == "arm64",
        "the workbench must be ARM64"
    );
    ensure!(
        runtime_arch(&live.worker).await? == "amd64",
        "the worker must be x86_64"
    );
    let (root, _state, client, endpoint) =
        harness(vec![live.workbench.clone(), live.worker.clone()]).await?;
    let remote_endpoint = format!(
        "http://{}:{}",
        live.host,
        endpoint.rsplit(':').next().unwrap()
    );
    let remote = Remote::create(&live.workbench, &uuid::Uuid::new_v4().to_string()).await?;
    upload(
        &live.workbench,
        &remote.token_script(),
        b"test-only-token-not-a-production-secret",
    )
    .await?;
    upload(
        &live.workbench,
        &format!(
            "set -eu; umask 066; cat > {}",
            transport::quote(&format!("{}/project/build.sh", remote.root))
        ),
        b"set -eu\nmkdir -p out\nuname -m > out/arch.txt\n",
    )
    .await?;
    upload(
        &live.workbench,
        &format!(
            "set -eu; umask 066; cat > {}",
            transport::quote(&format!("{}/project/sshpool.toml", remote.root))
        ),
        project_toml("linux/amd64").as_bytes(),
    )
    .await?;

    // 工作台自己的 uname / nproc：这就是用户在统一入口里看到的机器。
    let uname = text(&live.workbench, "uname -sm", 20).await?;
    ensure!(
        uname == "Linux aarch64",
        "the unified entry must report the workbench kernel, got {uname}"
    );
    let workbench_cpus: u32 = text(&live.workbench, "nproc", 20).await?.parse()?;
    let workbench_memory: u64 = text(
        &live.workbench,
        "awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo",
        20,
    )
    .await?
    .parse()?;

    let prefix = cli_prefix(&live, &remote, &remote_endpoint);
    let command = format!(
        "cd {} && {prefix} run 2>&1",
        transport::quote(&format!("{}/project", remote.root))
    );
    let (code, stdout, stderr) = capture(&live.workbench, &command, 300).await?;
    ensure!(
        code == 0,
        "the workbench CLI failed: code={code}\nstdout={stdout}\nstderr={stderr}"
    );
    // 工作台侧打印的 Worker 行必须与实际派发一致，而不是打印「工作台」。
    // 命令带 `2>&1`，因此进度行落在 stdout 里；stderr 只剩 SSH 的 locale 告警。
    let progress = format!("{stdout}{stderr}");
    ensure!(
        progress.contains("worker=worker") && progress.contains("platform=linux/amd64"),
        "the client must name the real worker: {progress}"
    );

    // `status` 走控制面：两个节点各自一份快照，不是相加后的总内存/总 CPU。
    let (code, status, err) = capture(&live.workbench, &format!("{prefix} status"), 120).await?;
    ensure!(code == 0, "status on the workbench failed: {err}");
    let reports: Vec<sshpool::model::Health> = serde_json::from_str(&status)?;
    ensure!(
        reports.len() == 2,
        "status must report one entry per node, got {}",
        reports.len()
    );
    let entry = |name: &str| {
        reports
            .iter()
            .find(|entry| entry.name == name)
            .with_context(|| format!("{name} is missing from status"))
    };
    let bench = entry("workbench")?;
    let pool = entry("worker")?;
    ensure!(
        bench.arch == "aarch64" && bench.cpus == workbench_cpus,
        "the workbench snapshot must match its own kernel: {:?} vs {workbench_cpus} cpus",
        bench
    );
    ensure!(
        pool.arch == "x86_64" && pool.cpus > bench.cpus,
        "the pool snapshot must describe the x86_64 worker: {:?}",
        pool
    );
    ensure!(
        bench.memory_available_mib <= workbench_memory
            && pool.memory_available_mib > bench.memory_available_mib,
        "each node keeps its own memory figure; no merged total"
    );
    ensure!(
        reports.iter().all(|entry| entry.error.is_none()
            && entry.runtime_arch != bench.runtime_arch
            || entry.name == "workbench"),
        "per-node runtime architectures must stay distinct: {reports:?}"
    );

    // 任务记录必须标明实际 Worker，而不是把工作台当成执行者。
    let job = only_job(&client).await?;
    ensure!(
        job.phase == Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        job.attempts.last().map(|attempt| attempt.node.as_str()) == Some("worker"),
        "the job record must name the real worker: {:?}",
        job.attempts
    );
    ensure!(
        job.build.platform == "linux/amd64" && job.attempts.len() == 1,
        "one attempt on the amd64 worker: {:?}",
        job.attempts
    );
    println!(
        "capabilities: job={} attempt={} workbench={{arch=aarch64,cpus={workbench_cpus},mem_total_mib={workbench_memory}}} pool={{arch=x86_64,cpus={},mem_available_mib={}}}",
        job.id, job.attempts[0].node, pool.cpus, pool.memory_available_mib
    );

    remote.remove(&live.workbench).await;
    drop(root);
    Ok(())
}
