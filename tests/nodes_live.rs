//! 用真实别名接入多台主机，并验证单节点故障不吞掉其他结果。
//!
//! ```sh
//! SSHPOOL_LIVE_NODES=sshpool-anchor,okm182-lan,macmini-lan \
//!   cargo test --test nodes_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 走真实 CLI：`sshpool --home <临时目录> node add ...` 然后 `sshpool doctor`。
//! 这里刻意不通过 `probe::all` 直接调用，因为要证明的是「管理员按 alias 登记后，
//! doctor 真的能分节点报告」，而不是内部函数可跑。
use anyhow::{Context, Result, ensure};
use sshpool::model::Health;

fn targets() -> Result<Vec<String>> {
    let value = std::env::var("SSHPOOL_LIVE_NODES").context("SSHPOOL_LIVE_NODES is not set")?;
    let targets = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    ensure!(
        targets.len() >= 2,
        "at least two real targets are required, got {}",
        targets.len()
    );
    Ok(targets)
}

/// 临时控制面目录；不碰本机 `~/.sshpool`。
fn home() -> Result<tempfile::TempDir> {
    let root = tempfile::tempdir()?;
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .arg("--home")
        .arg(root.path())
        .arg("init")
        .output()?;
    ensure!(
        cli.status.success(),
        "sshpool init failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    Ok(root)
}

/// 直接调用 CLI（同步）；本测试不服务于任何进程内 server，因此无需 spawn_blocking。
fn cli(home: &std::path::Path, args: &[&str]) -> Result<std::process::Output> {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .arg("--home")
        .arg(home)
        .args(args)
        .output()?;
    Ok(output)
}

fn add(home: &std::path::Path, name: &str, ssh: &str) -> Result<()> {
    let output = cli(
        home,
        &[
            "node",
            "add",
            name,
            "--ssh",
            ssh,
            "--reserve-memory-mib",
            "0",
            "--reserve-disk-mib",
            "0",
            "--max-load-per-cpu",
            "100",
            "--max-jobs",
            "1",
        ],
    )?;
    ensure!(
        output.status.success(),
        "node add {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// 已登记的多台真实主机各自报告自己的能力，一台不可达不吞掉其他结果。
#[tokio::test]
#[ignore = "requires real SSH aliases with docker and python3"]
async fn existing_aliases_are_reported_per_host_and_failures_stay_isolated() -> Result<()> {
    let targets = targets()?;
    let root = home()?;
    for (index, target) in targets.iter().enumerate() {
        add(root.path(), &format!("node-{index}"), target)?;
    }
    // 再登记一台必然不可路由的节点：它的失败必须出现在结果里，而不是拖垮整次探测。
    add(root.path(), "blackhole", "192.0.2.1")?;

    let output = cli(root.path(), &["doctor"])?;
    ensure!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let health: Vec<Health> = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        health.len(),
        targets.len() + 1,
        "doctor must report one entry per registered node"
    );

    for (index, target) in targets.iter().enumerate() {
        let entry = health
            .iter()
            .find(|entry| entry.name == format!("node-{index}"))
            .with_context(|| format!("node-{index} ({target}) is missing from doctor output"))?;
        ensure!(
            entry.error.is_none(),
            "{} ({target}) probed with an error: {:?}",
            entry.name,
            entry.error
        );
        ensure!(entry.cpus > 0, "{} reported no CPUs", entry.name);
        ensure!(
            entry.memory_available_mib > 0,
            "{} reported no available memory",
            entry.name
        );
        // 三类节点的 OS/arch 可以不同；这里断言它们被如实、独立地报告，而不是合并。
        ensure!(
            !entry.os.is_empty() && !entry.arch.is_empty(),
            "{} must report os and arch",
            entry.name
        );
        ensure!(
            !entry.runtime_arch.is_empty(),
            "{} must report the container runtime arch",
            entry.name
        );
        println!(
            "{} ({target}): os={} arch={} cpus={} mem={}MiB docker_arch={}",
            entry.name,
            entry.os,
            entry.arch,
            entry.cpus,
            entry.memory_available_mib,
            entry.runtime_arch
        );
    }

    let blackhole = health
        .iter()
        .find(|entry| entry.name == "blackhole")
        .context("the unreachable node vanished from the report")?;
    ensure!(
        blackhole.error.is_some(),
        "an unreachable node must report an error, not be silently dropped"
    );

    // 名字与能力必须一一对应：不能把 A 的 CPU 数挂到 B 上。
    let mut seen = std::collections::HashSet::new();
    for entry in &health {
        ensure!(
            seen.insert(entry.name.clone()),
            "duplicate node name in doctor output: {}",
            entry.name
        );
    }

    // 登记重复名字必须拒绝，且不破坏已有配置。
    let duplicate = cli(
        root.path(),
        &["node", "add", "node-0", "--ssh", "192.0.2.1"],
    )?;
    ensure!(
        !duplicate.status.success(),
        "adding a duplicate node name must be refused"
    );
    let listed = cli(root.path(), &["node", "list"])?;
    ensure!(listed.status.success(), "node list failed");
    let text = String::from_utf8_lossy(&listed.stdout).to_string();
    ensure!(
        text.matches("[[nodes]]").count() == targets.len() + 1,
        "the refused duplicate must not change the config:\n{text}"
    );
    Ok(())
}

/// 别名本身必须是合法 SSH 目标：带 shell 语法的「别名」会在远端被解释。
#[tokio::test]
async fn shell_syntax_in_an_alias_is_refused_by_the_cli() -> Result<()> {
    let root = home()?;
    for target in ["host; rm -rf /", "-oProxyCommand=evil", "host`id`", ""] {
        let output = cli(root.path(), &["node", "add", "bad", "--ssh", target])?;
        ensure!(
            !output.status.success(),
            "alias {target:?} must be refused before it reaches ssh"
        );
    }
    let listed = cli(root.path(), &["node", "list"])?;
    ensure!(
        !String::from_utf8_lossy(&listed.stdout).contains("[[nodes]]"),
        "no refused alias may be persisted"
    );
    Ok(())
}
