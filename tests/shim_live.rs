//! 真实 shim 链路：`cargo build` 经包装命令落到隔离容器。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=sshpool-anchor \
//!   cargo test --test shim_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 走的是真实二进制（`CARGO_BIN_EXE_sshpool shim cargo -- ...`）与真实 HTTP 入口，
//! 不直接调用 `runner`。项目本身零依赖，因此 `--offline` 在只有工具链的镜像里可跑。
use anyhow::{Context, Result, ensure};
use sshpool::{
    client::Client,
    config::{Config, Node},
    model::{Job, Phase},
    state::State,
};
use std::{fs, path::Path, sync::Arc};

/// 与镜像能力匹配的工具链镜像；必须在节点允许清单里显式登记。
const IMAGE: &str = "rust:1.93-alpine";

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live-shim".into(),
        ssh,
        images: vec![IMAGE.into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 0,
    })
}

async fn harness(node: &Node) -> Result<(tempfile::TempDir, Arc<State>, Client, String)> {
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

async fn platform(node: &Node) -> Result<String> {
    let arch =
        sshpool::transport::verified(node, "docker info --format '{{.Architecture}}'", 20).await?;
    Ok(format!(
        "linux/{}",
        sshpool::probe::platform_arch(String::from_utf8_lossy(&arch).trim())
    ))
}

/// 零依赖项目；`build.rs` 在容器内记录真实 UID 与架构，证明构建不是 root 也不是工作台。
fn project(root: &Path, platform: &str) -> Result<std::path::PathBuf> {
    let project = root.join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"demo\"\npath = \"src/main.rs\"\n\n[workspace]\n",
    )?;
    fs::write(
        project.join("src/main.rs"),
        "fn main() { println!(\"sshpool-demo\"); }\n",
    )?;
    fs::write(
        project.join("build.rs"),
        "use std::{fs, process::Command};\n\
         fn main() {\n\
             let uid = Command::new(\"id\").arg(\"-u\").output().expect(\"id\");\n\
             let arch = Command::new(\"uname\").arg(\"-m\").output().expect(\"uname\");\n\
             fs::create_dir_all(\"out\").expect(\"out\");\n\
             fs::write(\"out/uid.txt\", &uid.stdout).expect(\"uid\");\n\
             fs::write(\"out/arch.txt\", &arch.stdout).expect(\"arch\");\n\
         }\n",
    )?;
    fs::write(
        project.join("sshpool.toml"),
        format!(
            "image = \"{IMAGE}\"\nplatform = \"{platform}\"\noutputs = [\"out\", \"target/release/demo\"]\n\
             memory_mib = 1024\nscratch_mib = 512\ncpus = 1.0\ntimeout_secs = 600\n"
        ),
    )?;
    Ok(project)
}

/// ELF 头里的 `e_machine`：这是「产物真的是该架构二进制」的结构性证据。
fn elf_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    Some(u16::from_le_bytes([bytes[18], bytes[19]]))
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with the Rust image"]
async fn the_cargo_shim_runs_an_isolated_build_and_returns_real_artifacts() -> Result<()> {
    let node = node()?;
    // 镜像必须由管理员显式准备；缺失时明确跳过，不把「没装工具链」冒充成 shim 缺陷。
    let present = sshpool::transport::verified(
        &node,
        &format!(
            "docker image inspect {} >/dev/null 2>&1 && echo yes || echo no",
            sshpool::transport::quote(IMAGE)
        ),
        20,
    )
    .await?;
    if String::from_utf8_lossy(&present).trim() != "yes" {
        eprintln!("skipped: {IMAGE} is not prepared on this worker");
        return Ok(());
    }
    let platform = platform(&node).await?;
    let (root, _state, client, endpoint) = harness(&node).await?;
    let project = project(root.path(), &platform)?;

    // 真实二进制 + 真实包装路径；同步等待子进程必须放到阻塞线程池，
    // 否则会卡住同进程内的 axum 服务。
    let shim = {
        let home = root.path().to_path_buf();
        let endpoint = endpoint.clone();
        let cwd = project.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
                .arg("--home")
                .arg(&home)
                .arg("--endpoint")
                .arg(&endpoint)
                .args(["shim", "cargo", "--", "build", "--release", "--offline"])
                .current_dir(&cwd)
                .output()
        })
        .await??
    };
    ensure!(
        shim.status.success(),
        "the shim failed: {}",
        String::from_utf8_lossy(&shim.stderr)
    );
    println!("{}", String::from_utf8_lossy(&shim.stdout));

    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(
        jobs.len() == 1,
        "expected exactly one job, got {}",
        jobs.len()
    );
    let job = &jobs[0];
    ensure!(
        job.phase == Phase::Succeeded,
        "unexpected phase {:?}: {:?}",
        job.phase,
        job.message
    );
    ensure!(
        job.exit_code == Some(0),
        "unexpected exit code {:?}",
        job.exit_code
    );
    ensure!(job.artifacts, "a shim build must publish artifacts");
    ensure!(
        job.cleanup_confirmed,
        "container removal was not confirmed: {:?}",
        job.message
    );
    // 原始命令必须逐字下发，不被重写成别的东西。
    ensure!(
        job.build.command == ["cargo", "build", "--release", "--offline"],
        "the shim must forward the original command: {:?}",
        job.build.command
    );

    let output = root.path().join("results");
    client.fetch(job.id, &output).await?;
    let uid = fs::read_to_string(output.join("out/uid.txt"))?;
    ensure!(
        uid.trim() == "65534",
        "the build ran as uid {} instead of the unprivileged 65534",
        uid.trim()
    );
    let arch = fs::read_to_string(output.join("out/arch.txt"))?;
    ensure!(
        sshpool::probe::platform_arch(arch.trim())
            == job.build.platform.trim_start_matches("linux/"),
        "artifact arch {} does not match the requested platform {}",
        arch.trim(),
        job.build.platform
    );
    let binary = fs::read(output.join("target/release/demo"))?;
    let expected = if job.build.platform.ends_with("amd64") {
        0x3e
    } else {
        0xb7
    };
    ensure!(
        elf_machine(&binary) == Some(expected),
        "the artifact is not an ELF binary for {:?}: {:?}",
        job.build.platform,
        elf_machine(&binary)
    );
    ensure!(!binary.is_empty(), "the fetched binary is empty");

    // 「产物可被回取并**执行**」：把回取的二进制送到 Worker 上真跑一次。
    // 镜像用 musl 静态链接，因此不依赖容器里的动态库。
    let remote = format!("/tmp/{}-demo", job.id);
    let local = output.join("target/release/demo");
    sshpool::transport::upload(
        &node,
        &format!("cat > {}", sshpool::transport::quote(&remote)),
        &local,
    )
    .await?;
    let run = format!(
        "chmod 700 {} && {} ; printf 'exit:%s' $? ; rm -f {}",
        sshpool::transport::quote(&remote),
        sshpool::transport::quote(&remote),
        sshpool::transport::quote(&remote)
    );
    let observed = sshpool::transport::verified(&node, &run, 30).await?;
    let observed = String::from_utf8_lossy(&observed).to_string();
    ensure!(
        observed.contains("sshpool-demo") && observed.contains("exit:0"),
        "the fetched artifact did not run on the worker: {observed}"
    );

    // 同一条命令离开项目目录时必须留在本机：包装器不能劫持普通 shell。
    let outside = {
        let home = root.path().to_path_buf();
        let endpoint = endpoint.clone();
        let cwd = root.path().join("plain");
        fs::create_dir_all(&cwd)?;
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
                .arg("--home")
                .arg(&home)
                .arg("--endpoint")
                .arg(&endpoint)
                .args(["shim", "cargo", "--", "--version"])
                .current_dir(&cwd)
                .output()
        })
        .await??
    };
    ensure!(
        outside.status.success(),
        "a local cargo query must not fail: {}",
        String::from_utf8_lossy(&outside.stderr)
    );
    let after: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(
        after.len() == 1,
        "a --version query must not create a job, got {}",
        after.len()
    );
    Ok(())
}
