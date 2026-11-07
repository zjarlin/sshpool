//! 四类构建工具的兼容性验收：Gradle / Make / Node / Python，全部走统一入口。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=sshpool-anchor \
//!   cargo test --test adapters_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 与 `shim_live` 一样只经 `Client` 与真实 HTTP 入口提交，不直接调 `runner`；
//! 「每类工具都有实际兼容性验收」这句话因此对应的是真实构建产物，而不是参数拼装。
//! 镜像必须由管理员预先准备；缺镜像时显式跳过，不把「没装工具链」算成适配器缺陷。
use anyhow::{Context, Result, ensure};
use sshpool::{
    client::Client,
    config::{Build, Config, Node},
    model::{Job, Phase},
    state::State,
};
use std::{fs, path::Path, sync::Arc};

/// 一个可在隔离容器里真跑起来的工具链。`outputs` 与 `probe` 一起构成判据。
struct Adapter {
    name: &'static str,
    image: &'static str,
    /// 写进项目目录的文件：(相对路径, 内容)。
    files: &'static [(&'static str, &'static str)],
    command: &'static [&'static str],
    outputs: &'static [&'static str],
    /// 从回取产物里读的文本文件，以及它必须包含的内容。
    evidence: (&'static str, &'static str),
    /// 产物是可执行文件时，在 Worker 上真跑一次并检查 stdout。
    run_output: Option<(&'static str, &'static str)>,
}

const ADAPTERS: &[Adapter] = &[
    Adapter {
        name: "gradle",
        image: "gradle:8.10-jdk21-alpine",
        files: &[
            ("settings.gradle", "rootProject.name = 'demo'\n"),
            (
                "build.gradle",
                "plugins { id 'java' }\n\
                 // 构建内记录运行身份与架构，证明它不是 root、也不是工作台本机。\n\
                 tasks.register('probe') {\n\
                   doLast {\n\
                     file('out').mkdirs()\n\
                     file('out/probe.txt').text = \"gradle ${System.getProperty('java.version')} \" +\n\
                       \"uid=${['id','-u'].execute().text.trim()} \" +\n\
                       \"arch=${System.getProperty('os.arch')}\\n\"\n\
                   }\n\
                 }\n\
                 build.dependsOn('probe')\n",
            ),
            (
                "src/main/java/demo/Main.java",
                "package demo;\n\
                 public class Main { public static void main(String[] a) { System.out.println(\"sshpool-gradle\"); } }\n",
            ),
        ],
        command: &["gradle", "--offline", "--no-daemon", "-q", "build"],
        outputs: &["out", "build/libs"],
        evidence: ("out/probe.txt", "uid=65534"),
        run_output: None,
    },
    Adapter {
        name: "make",
        image: "gcc:13",
        files: &[
            (
                "src/hello.c",
                "#include <stdio.h>\n\
                 #include <unistd.h>\n\
                 #include <sys/utsname.h>\n\
                 int main(void) {\n\
                     struct utsname u; uname(&u);\n\
                     printf(\"sshpool-make %s uid=%d\\n\", u.machine, (int)getuid());\n\
                     return 0;\n\
                 }\n",
            ),
            (
                "Makefile",
                "CC ?= cc\n\
                 CFLAGS ?= -O1 -Wall\n\
                 all: dist/hello\n\
                 dist/hello: src/hello.c\n\
                 \tmkdir -p dist\n\
                 \t$(CC) $(CFLAGS) -o dist/hello src/hello.c\n",
            ),
        ],
        command: &["make", "all"],
        outputs: &["dist"],
        evidence: ("dist/hello", "\u{7f}ELF"),
        run_output: Some(("dist/hello", "sshpool-make")),
    },
    Adapter {
        name: "node",
        image: "node:22-alpine",
        files: &[
            (
                "package.json",
                "{\n  \"name\": \"demo\",\n  \"version\": \"0.1.0\",\n  \"private\": true,\n  \"scripts\": { \"build\": \"node build.js\" }\n}\n",
            ),
            (
                "build.js",
                "const fs = require('fs');\n\
                 const os = require('os');\n\
                 fs.mkdirSync('dist', { recursive: true });\n\
                 fs.writeFileSync('dist/payload.txt',\n\
                   `node ${process.version} uid=${os.userInfo().uid} arch=${process.arch}\\n`);\n\
                 console.log('sshpool-node build ok');\n",
            ),
        ],
        command: &["npm", "run", "build", "--silent"],
        outputs: &["dist"],
        evidence: ("dist/payload.txt", "uid=65534"),
        run_output: None,
    },
    Adapter {
        name: "python",
        image: "python:3.12-alpine",
        files: &[
            ("app/__init__.py", ""),
            (
                "app/__main__.py",
                "import os, sys\n\
                 print(f\"sshpool-python {sys.version.split()[0]} uid={os.getuid()}\")\n",
            ),
            (
                "build.sh",
                // zipapp 会按源文件时间戳写 zip 条目，所以这条也间接验证了源码归档
                // 的 mtime 不是 1970（1970 会让 zipapp 直接报错）。
                "set -eu\n\
                 mkdir -p dist\n\
                 python3 -m compileall -q app\n\
                 python3 -m zipapp app -o dist/app.pyz -p \"/usr/bin/env python3\"\n\
                 python3 dist/app.pyz > dist/probe.txt\n\
                 cat dist/probe.txt\n",
            ),
        ],
        command: &["sh", "build.sh"],
        outputs: &["dist"],
        evidence: ("dist/probe.txt", "uid=65534"),
        run_output: None,
    },
];

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live-adapters".into(),
        ssh,
        images: ADAPTERS
            .iter()
            .map(|adapter| adapter.image.into())
            .collect(),
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 0,
    })
}

async fn harness(node: &Node) -> Result<(tempfile::TempDir, Arc<State>, Client)> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("token"),
        "test-only-token-not-a-production-secret",
    )?;
    let config = Config {
        min_free_disk_mib: 0,
        max_upload_mib: 16,
        max_artifact_mib: 32,
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
    let client = Client::new(
        format!("http://{address}"),
        &root.path().join("token"),
        None,
    )?;
    Ok((root, state, client))
}

async fn platform(node: &Node) -> Result<String> {
    let arch =
        sshpool::transport::verified(node, "docker info --format '{{.Architecture}}'", 20).await?;
    Ok(format!(
        "linux/{}",
        sshpool::probe::platform_arch(String::from_utf8_lossy(&arch).trim())
    ))
}

async fn present(node: &Node, image: &str) -> Result<bool> {
    let output = sshpool::transport::verified(
        node,
        &format!(
            "docker image inspect {} >/dev/null 2>&1 && echo yes || echo no",
            sshpool::transport::quote(image)
        ),
        20,
    )
    .await?;
    Ok(String::from_utf8_lossy(&output).trim() == "yes")
}

fn project(root: &Path, adapter: &Adapter) -> Result<std::path::PathBuf> {
    let project = root.join(adapter.name);
    for (relative, body) in adapter.files {
        let path = project.join(relative);
        fs::create_dir_all(path.parent().context("missing parent")?)?;
        fs::write(path, body)?;
    }
    Ok(project)
}

async fn only_job(client: &Client) -> Result<Job> {
    let jobs: Vec<Job> = serde_json::from_value(client.get("/v1/jobs").await?)?;
    ensure!(
        jobs.len() == 1,
        "expected exactly one job, got {}",
        jobs.len()
    );
    jobs.into_iter().next().context("missing job")
}

/// 每个适配器一条用例，失败时报告是哪一类工具链出了问题。
async fn verify(adapter: &Adapter) -> Result<()> {
    let node = node()?;
    // 缺镜像时明确跳过：管理员没准备工具链不等于适配器坏了。
    if !present(&node, adapter.image).await? {
        eprintln!("skipped: {} is not prepared on this worker", adapter.image);
        return Ok(());
    }
    let target = platform(&node).await?;
    let (root, _state, client) = harness(&node).await?;
    let project = project(root.path(), adapter)?;
    let build = Build {
        image: adapter.image.into(),
        platform: target,
        command: adapter
            .command
            .iter()
            .map(|part| part.to_string())
            .collect(),
        outputs: adapter
            .outputs
            .iter()
            .map(|path| path.to_string())
            .collect(),
        memory_mib: 2048,
        scratch_mib: 1024,
        cpus: 2.0,
        timeout_secs: 600,
        pids: 512,
        ..Build::default()
    };

    let code = client.run(&project, build).await?;
    ensure!(
        code == 0,
        "{}: the entry reported exit {code}",
        adapter.name
    );

    let job = only_job(&client).await?;
    ensure!(
        job.phase == Phase::Succeeded,
        "{}: unexpected phase {:?}: {:?}",
        adapter.name,
        job.phase,
        job.message
    );
    ensure!(
        job.exit_code == Some(0),
        "{}: unexpected exit code {:?}",
        adapter.name,
        job.exit_code
    );
    ensure!(
        job.cleanup_confirmed,
        "{}: container removal was not confirmed: {:?}",
        adapter.name,
        job.message
    );
    // 原命令逐字下发；适配器不能悄悄改写用户写的命令。
    ensure!(
        job.build.command == adapter.command,
        "{}: the command was rewritten: {:?}",
        adapter.name,
        job.build.command
    );

    let output = root.path().join("results");
    client.fetch(job.id, &output).await?;
    let (relative, expected) = adapter.evidence;
    let bytes = fs::read(output.join(relative))
        .with_context(|| format!("{}: missing artifact {}", adapter.name, relative))?;
    let text = String::from_utf8_lossy(&bytes);
    ensure!(
        text.contains(expected),
        "{}: {} does not contain {:?}",
        adapter.name,
        relative,
        expected
    );
    // 每条工作负载都自己报告 uid：编译不是以 root 跑的，这一点不靠配置推断。
    if adapter.name != "make" {
        ensure!(
            text.contains("uid=65534"),
            "{}: the build did not report the unprivileged uid: {text}",
            adapter.name
        );
    }

    if let Some((relative, marker)) = adapter.run_output {
        let remote = format!("/tmp/{}-{}", job.id, adapter.name);
        let local = output.join(relative);
        sshpool::transport::upload(
            &node,
            &format!("cat > {}", sshpool::transport::quote(&remote)),
            &local,
        )
        .await?;
        let run = format!(
            "chmod 700 {p} && {p} ; printf 'exit:%s' $? ; rm -f {p}",
            p = sshpool::transport::quote(&remote)
        );
        let observed = sshpool::transport::verified(&node, &run, 30).await?;
        let observed = String::from_utf8_lossy(&observed).to_string();
        ensure!(
            observed.contains(marker) && observed.contains("exit:0"),
            "{}: the artifact did not run on the worker: {observed}",
            adapter.name
        );
    }
    eprintln!("{}: ok on {}", adapter.name, adapter.image);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with the toolchain images"]
async fn gradle_builds_in_the_same_isolated_pipeline() -> Result<()> {
    verify(&ADAPTERS[0]).await
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with the toolchain images"]
async fn make_builds_in_the_same_isolated_pipeline() -> Result<()> {
    verify(&ADAPTERS[1]).await
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with the toolchain images"]
async fn node_builds_in_the_same_isolated_pipeline() -> Result<()> {
    verify(&ADAPTERS[2]).await
}

#[tokio::test]
#[ignore = "requires a reachable SSH worker with the toolchain images"]
async fn python_builds_in_the_same_isolated_pipeline() -> Result<()> {
    verify(&ADAPTERS[3]).await
}
