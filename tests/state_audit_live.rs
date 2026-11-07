//! 真实主机上的只读状态审核：清单说的每一项都要在 182 上对得上。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=okm182 \
//!   cargo test --test state_audit_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 两条测试都以 `examples/state-audit/sub2api.json` 为输入：
//!
//! - 第一条按**现状**审核，期望被拒：Redis 宣称可丢弃缓存却握着 4000 多个无 TTL 键，
//!   三份数据在同一块盘上，PostgreSQL 没有 WAL 归档也没有定时备份，所以 RPO 没有上界。
//!   「被拒」是正确结果，不是失败。
//! - 第二条是阳性对照：把备份节奏、RPO 与缓存允许量改成与事实相符的值后，
//!   工具必须给出通过。否则这个工具只会永远说「不行」，那它证明不了任何东西。
//!
//! 探针只跑 `docker inspect/exec` 与 `stat/du`，不创建容器、卷、网络，不改任何配置。
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sshpool::state_audit::{self, Disposition, Inventory, Probe, Report};
use std::path::Path;

/// 清单里声明的关键表：会话、计费、后台任务各两张。
const KEY_TABLES: [&str; 6] = [
    "pending_auth_sessions",
    "auth_cache_invalidation_outbox",
    "usage_billing_dedup",
    "billing_usage_entries",
    "scheduler_outbox",
    "batch_image_jobs",
];

fn node() -> Result<String> {
    std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")
}

fn inventory() -> Result<Inventory> {
    state_audit::read_inventory(Path::new("examples/state-audit/sub2api.json"))
}

fn codes(findings: &[state_audit::Finding]) -> Vec<&str> {
    findings.iter().map(|item| item.code.as_str()).collect()
}

#[tokio::test]
#[ignore = "requires a reachable worker running the real sub2api stack"]
async fn the_declared_contract_is_checked_against_the_host() -> Result<()> {
    let ssh = node()?;
    let declared = inventory()?;
    let facts: Probe = state_audit::probe(&declared, &ssh, None).await?;

    ensure!(
        facts.errors.is_empty(),
        "probe reported errors: {:?}",
        facts.errors
    );

    // 1. 声明的库确实存在，关键表与唯一索引都对得上。
    let postgres = facts
        .postgres
        .iter()
        .find(|item| item.container == "postgres" && item.database == "sub2api")
        .context("postgres::sub2api was not observed")?;
    for table in KEY_TABLES {
        ensure!(
            postgres.tables.iter().any(|name| name == table),
            "declared table `{table}` is missing"
        );
    }
    let dedup = postgres
        .unique_indexes
        .iter()
        .find(|index| index.table == "usage_billing_dedup" && !index.primary)
        .context("usage_billing_dedup has no unique index")?;
    let mut columns = dedup.columns.clone();
    columns.sort();
    ensure!(
        columns == vec!["api_key_id".to_string(), "request_id".to_string()],
        "the unique index no longer covers (request_id, api_key_id): {columns:?}"
    );
    eprintln!(
        "postgres::sub2api archive_mode={} wal_level={} tables={} sequences={} size={:.1} MiB",
        postgres.archive_mode,
        postgres.wal_level,
        postgres.tables.len(),
        postgres.sequences,
        postgres.size_bytes as f64 / 1048576.0
    );
    ensure!(
        postgres.archive_mode != "on",
        "archive_mode turned on: the checklist below assumes point-in-time recovery is still absent"
    );

    // 2. Redis 的「可丢弃缓存」不成立：存在大量无 TTL 键。
    let redis = facts
        .redis
        .iter()
        .find(|item| item.container == "redis")
        .context("redis was not observed")?;
    let persistent: u64 = redis
        .databases
        .iter()
        .map(|db| db.keys.saturating_sub(db.expires))
        .sum();
    ensure!(
        persistent > 0,
        "redis now holds only expiring keys; the audit's premise is stale and must be revisited"
    );
    eprintln!(
        "redis v{} appendonly={} appendfsync={} persistent_keys={persistent} databases={}",
        redis.version,
        redis.appendonly,
        redis.appendfsync,
        redis.databases.len()
    );

    // 3. 三份数据目录落在同一块盘上：不能宣称独立故障域。
    let devices = facts
        .mounts
        .iter()
        .map(|mount| mount.device.clone().unwrap_or_default())
        .collect::<Vec<_>>();
    ensure!(
        devices.len() >= 3,
        "expected the application volume plus both engine data directories, saw {}",
        devices.len()
    );
    ensure!(
        devices.iter().all(|device| !device.is_empty()),
        "a mount could not be resolved to a device: {devices:?}"
    );
    ensure!(
        devices.windows(2).all(|pair| pair[0] == pair[1]),
        "data directories now sit on different devices: {devices:?}"
    );
    eprintln!("mount devices: {devices:?}");

    // 4. 结论必须是被拒，而且要把原因说清楚。
    let report = state_audit::assess(&declared, &facts);
    eprintln!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(report.read_only, "the audit must stay read-only");
    ensure!(
        report.blockers.is_empty(),
        "the audit itself is invalid: {:?}",
        report.blockers
    );
    ensure!(
        !report.migration_plan_approved,
        "the current sub2api contract must not be approved while backups are manual only"
    );
    ensure!(
        codes(&report.violations).contains(&"redis_cache_claim_refused"),
        "a cache claim with persistent keys must be refused: {:?}",
        report.violations
    );
    ensure!(
        codes(&report.violations).contains(&"rpo_claim_unachievable"),
        "a declared RPO without a bounded surface must be refuted: {:?}",
        report.violations
    );
    ensure!(
        report.achievable_rpo_seconds.is_none(),
        "manual backups cannot yield a finite RPO, got {:?}",
        report.achievable_rpo_seconds
    );
    let redis_surface = report
        .surfaces
        .iter()
        .find(|surface| surface.kind == "redis")
        .context("the redis surface is missing from the report")?;
    ensure!(
        redis_surface.effective_disposition == Disposition::Authoritative,
        "a refused cache claim must be counted as authoritative state"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable worker running the real sub2api stack"]
async fn a_contract_that_matches_the_facts_is_approved() -> Result<()> {
    let ssh = node()?;
    let mut declared = inventory()?;
    let mut facts = state_audit::probe(&declared, &ssh, None).await?;
    ensure!(
        facts.errors.is_empty(),
        "probe reported errors: {:?}",
        facts.errors
    );

    // 阳性对照：把清单改成与现场相符的承诺，其余声明一律不动。
    let persistent: u64 = facts
        .redis
        .iter()
        .find(|item| item.container == "redis")
        .map(|item| {
            item.databases
                .iter()
                .map(|db| db.keys.saturating_sub(db.expires))
                .sum()
        })
        .unwrap_or(0);
    declared.redis[0].cache_persistent_allowance = persistent;

    // 现场没有定时备份，而审核不接受「清单说自己有备份」。
    // 阳性对照因此必须同时造出**探针事实**，否则它验证的只是自我保证。
    // 用 `来源#摘要` 指向这一条：即使 root 的 crontab 里还有别的任务，也不会被误认。
    let evidence = "crontab:root#00000000feedface";
    facts.backup_schedules.push(state_audit::BackupSchedule {
        source: "crontab:root".into(),
        command_digest: "00000000feedface".into(),
        interval_seconds: Some(3600),
    });
    let schedule = state_audit::Backup::Scheduled {
        interval_seconds: 3600,
        evidence: evidence.into(),
    };
    declared.postgres[0].backup = schedule.clone();
    declared.volumes[0].backup = schedule;
    declared.rpo_seconds = Some(3600);

    let report: Report = state_audit::assess(&declared, &facts);
    eprintln!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(
        report.violations.is_empty(),
        "a matched contract was still refused: {:?}",
        report.violations
    );
    ensure!(
        report.blockers.is_empty(),
        "a matched contract still has blockers: {:?}",
        report.blockers
    );
    ensure!(
        report.migration_plan_approved,
        "a matched contract must be approved"
    );
    ensure!(
        report.achievable_rpo_seconds == Some(3600),
        "the hourly backup interval bounds RPO at 3600s, got {:?}",
        report.achievable_rpo_seconds
    );
    Ok(())
}

/// 脚本看到的契约：真实二进制作一次端到端审核，退出码是 2，标准输出只有一份 JSON。
#[tokio::test]
#[ignore = "requires a reachable worker running the real sub2api stack"]
async fn the_binary_exits_two_and_prints_one_report() -> Result<()> {
    let ssh = node()?;
    let root = tempfile::tempdir()?;
    let output = root.path().join("report.json");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .args([
            "state-audit",
            "--inventory",
            "examples/state-audit/sub2api.json",
        ])
        .args(["--ssh", &ssh, "--output"])
        .arg(&output)
        .output()?;
    let stderr = String::from_utf8_lossy(&result.stderr).to_string();
    ensure!(
        result.status.code() == Some(2),
        "exit code was {:?}: {stderr}",
        result.status.code()
    );
    let report: Value = serde_json::from_slice(&std::fs::read(&output)?)
        .context("the report file is not one JSON document")?;
    ensure!(report["read_only"] == true, "{stderr}");
    ensure!(report["migration_plan_approved"] == false, "{stderr}");
    ensure!(report["achievable_rpo_seconds"].is_null(), "{stderr}");
    ensure!(
        report["scope"] == "read-only-application-state-audit",
        "unexpected scope: {}",
        report["scope"]
    );
    Ok(())
}
