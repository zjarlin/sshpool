//! `sshpool state-audit` 的真实二进制契约：退出码、标准输出、拒绝时不给结论。
//!
//! 这里不调库函数，因为要证明的正是脚本看到的契约。输入是离线探针结果，
//! 所以这条测试在 CI 上就能跑；真实主机探测在 `tests/state_audit_live.rs`。
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{fs, path::Path};

fn run(arguments: &[&std::ffi::OsStr]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .args(arguments)
        .output()?)
}

/// 一次调用：退出码加解析后的报告；不是单份 JSON 就当场失败。
fn audit(inventory: &Path, probe: &Path) -> Result<(i32, Value, String)> {
    let output = run(&[
        "state-audit".as_ref(),
        "--inventory".as_ref(),
        inventory.as_os_str(),
        "--probe".as_ref(),
        probe.as_os_str(),
    ])?;
    let code = output.status.code().context("state-audit was killed")?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    if code == 0 || code == 2 {
        let value: Value = serde_json::from_str(&stdout)
            .with_context(|| format!("stdout is not one JSON document: {stdout}"))?;
        Ok((code, value, stderr))
    } else {
        Ok((code, Value::Null, stderr))
    }
}

fn write(root: &Path, name: &str, value: &Value) -> Result<std::path::PathBuf> {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)?;
    Ok(path)
}

/// 一份自洽的清单：三个状态面都声明了，RPO/RTO 与事实一致。
fn inventory() -> Value {
    json!({
        "schema": 1,
        "application": "demo",
        "version": "demo@sha256:1111",
        "images": ["demo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        "rpo_seconds": 3600,
        "rto_seconds": 1800,
        "rto_rehearsal": "data-layer",
        "postgres": [{
            "container": "pg",
            "database": "app",
            "user": "app",
            "backup": { "kind": "scheduled", "interval_seconds": 600, "evidence": "crontab:root" },
            "groups": { "billing": ["charge"] },
            "dedup": [{ "purpose": "重试不得重复计费", "table": "charge",
                        "columns": ["request_id", "api_key_id"] }]
        }],
        "redis": [{
            "container": "cache",
            "disposition": "derived",
            "backup": { "kind": "scheduled", "interval_seconds": 600, "evidence": "crontab:root" },
            "required_prefixes": ["sched:"],
            "cache_persistent_allowance": 0
        }],
        "volumes": [{
            "container": "app",
            "destination": "/app/data",
            "disposition": "authoritative",
            "backup": { "kind": "scheduled", "interval_seconds": 600, "evidence": "crontab:root" }
        }],
        "failure_domains": { "claim_independent": false }
    })
}

/// 与上面清单相符的探针事实：Redis 全带 TTL，唯一索引覆盖去重列。
fn facts() -> Value {
    json!({
        "schema": 1,
        "collected_at_unix": 1_800_000_000,
        "discovered": [
            { "name": "pg", "image": "postgres:16-alpine", "image_id": "sha256:1",
              "engine": "postgres", "writable_binds": [] },
            { "name": "app", "image": "demo/app:latest",
              "image_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "engine": "",
              "writable_binds": [{ "destination": "/app/data", "source_digest": "0123456789abcdef" }] }
        ],
        "postgres": [{
            "container": "pg", "database": "app", "server_version": "16.4",
            "archive_mode": "off", "wal_level": "replica", "archive_timeout_seconds": 0,
            "replicas": 0, "size_bytes": 4096, "sequences": 1,
            "tables": ["charge"], "unlogged": [], "without_primary_key": [],
            "extensions": ["plpgsql"],
            "unique_indexes": [{ "table": "charge", "name": "charge_request",
                                 "columns": ["api_key_id", "request_id"], "primary": false }]
        }],
        "redis": [{
            "container": "cache", "version": "8.0", "appendonly": true,
            "appendfsync": "everysec", "save_rules": "3600 1", "replicas": 0,
            "databases": [{ "index": 0, "keys": 10, "expires": 10 }],
            "prefix_counts": { "sched:": 4 }
        }],
        "mounts": [
            { "container": "app", "role": "volume", "destination": "/app/data",
              "read_only": false, "bytes": 2048, "device": "2049" },
            { "container": "pg", "role": "engine-data",
              "destination": "/var/lib/postgresql/data", "read_only": false,
              "bytes": 8192, "device": "2049" }
        ],
        "backup_schedules": [{ "source": "crontab:root",
                               "command_digest": "0123456789abcdef",
                               "interval_seconds": 600 }],
        "errors": []
    })
}

fn codes(report: &Value, field: &str) -> Vec<String> {
    report[field]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item["code"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_consistent_inventory_exits_zero_and_reports_read_only() -> Result<()> {
    let root = tempfile::tempdir()?;
    let inventory = write(root.path(), "inventory.json", &inventory())?;
    let probe = write(root.path(), "probe.json", &facts())?;
    let (code, report, stderr) = audit(&inventory, &probe)?;
    assert_eq!(code, 0, "{report}\n{stderr}");
    assert_eq!(report["scope"], "read-only-application-state-audit");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["migration_plan_approved"], true);
    assert_eq!(report["achievable_rpo_seconds"], 600);
    assert_eq!(report["rpo_claim_supported"], true);
    assert_eq!(report["surfaces"].as_array().map(Vec::len), Some(3));
    assert!(codes(&report, "blockers").is_empty());
    assert!(codes(&report, "violations").is_empty());
    Ok(())
}

#[test]
fn a_declared_backup_without_a_host_schedule_exits_two() -> Result<()> {
    let root = tempfile::tempdir()?;
    let inventory = write(root.path(), "inventory.json", &inventory())?;
    let mut bare = facts();
    bare["backup_schedules"] = json!([]);
    let probe = write(root.path(), "probe.json", &bare)?;
    let (code, report, _) = audit(&inventory, &probe)?;

    // 「每 600 秒备份一次」是清单自己的说法，主机上找不到对应任务就不能兑现。
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["migration_plan_approved"], false);
    assert_eq!(report["achievable_rpo_seconds"], Value::Null);
    assert!(
        codes(&report, "violations").contains(&"backup_schedule_unverified".to_string()),
        "{report}"
    );

    // 同一来源下出现多条任务时没有指向性，同样不算证据。
    let mut crowded = facts();
    crowded["backup_schedules"] = json!([
        { "source": "crontab:root", "command_digest": "0123456789abcdef",
          "interval_seconds": 600 },
        { "source": "crontab:root", "command_digest": "fedcba9876543210",
          "interval_seconds": 86400 }
    ]);
    let probe = write(root.path(), "crowded.json", &crowded)?;
    let (code, report, _) = audit(&inventory, &probe)?;
    assert_eq!(code, 2, "{report}");
    assert!(
        codes(&report, "violations").contains(&"backup_schedule_ambiguous".to_string()),
        "{report}"
    );

    // 补上摘要指向唯一一条后，同一个宿主事实就能支持这个声明。
    let mut declared: Value = serde_json::from_slice(&fs::read(&inventory)?)?;
    for surface in ["postgres", "redis", "volumes"] {
        declared[surface][0]["backup"]["evidence"] = json!("crontab:root#0123456789abcdef");
    }
    let pinned = write(root.path(), "pinned.json", &declared)?;
    let (code, report, _) = audit(&pinned, &probe)?;
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["achievable_rpo_seconds"], 600);
    Ok(())
}

#[test]
fn redis_declared_as_cache_but_holding_state_exits_two() -> Result<()> {
    let root = tempfile::tempdir()?;
    let inventory = write(root.path(), "inventory.json", &inventory())?;
    let mut unpaged = facts();
    unpaged["redis"][0]["databases"] = json!([{ "index": 7, "keys": 28, "expires": 1 }]);
    let probe = write(root.path(), "probe.json", &unpaged)?;
    let (code, report, _) = audit(&inventory, &probe)?;
    assert_eq!(code, 2);
    assert_eq!(report["migration_plan_approved"], false);
    assert!(codes(&report, "violations").contains(&"redis_cache_claim_refused".to_string()));
    // 被拒的声明不能再按 0 RPO 计入：Redis 这一面必须按权威状态报 RPO。
    let redis = report["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|surface| surface["kind"] == "redis")
        .unwrap();
    assert_eq!(redis["effective_disposition"], "authoritative");
    assert_eq!(redis["achievable_rpo_seconds"], 1);
    Ok(())
}

#[test]
fn a_missing_key_table_or_unique_index_invalidates_the_audit() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut declared = inventory();
    declared["postgres"][0]["groups"]["sessions"] = json!(["pending_auth_sessions"]);
    declared["postgres"][0]["dedup"][0]["columns"] = json!(["request_id"]);
    let inventory = write(root.path(), "inventory.json", &declared)?;
    let probe = write(root.path(), "probe.json", &facts())?;
    let (code, report, _) = audit(&inventory, &probe)?;
    assert_eq!(code, 2);
    let blockers = codes(&report, "blockers");
    assert!(
        blockers.contains(&"declared_table_missing".to_string()),
        "{blockers:?}"
    );
    assert!(
        blockers.contains(&"dedup_index_missing".to_string()),
        "{blockers:?}"
    );
    Ok(())
}

#[test]
fn a_probe_failure_or_unpinned_image_never_yields_approval() -> Result<()> {
    let root = tempfile::tempdir()?;
    let inventory = write(root.path(), "inventory.json", &inventory())?;
    let mut broken = facts();
    broken["errors"] = json!(["postgres pg: permission denied for database app"]);
    let probe = write(root.path(), "probe.json", &broken)?;
    let (code, report, _) = audit(&inventory, &probe)?;
    assert_eq!(code, 2);
    assert!(codes(&report, "blockers").contains(&"probe_failed".to_string()));

    let declared: Value = serde_json::from_slice(&fs::read(&inventory)?)?;
    let mut mutable = declared.clone();
    mutable["images"] = json!(["demo/app:latest"]);
    let path = write(root.path(), "mutable.json", &mutable)?;
    let ok = write(root.path(), "ok.json", &facts())?;
    let (code, report, _) = audit(&path, &ok)?;
    assert_eq!(code, 2);
    assert!(codes(&report, "blockers").contains(&"image_not_pinned".to_string()));
    Ok(())
}

#[test]
fn malformed_input_and_ambiguous_sources_exit_one_without_a_report() -> Result<()> {
    let root = tempfile::tempdir()?;
    let probe = write(root.path(), "probe.json", &facts())?;
    let mut broken = inventory();
    broken["surprise"] = json!(true);
    let path = write(root.path(), "unknown-field.json", &broken)?;
    let (code, report, stderr) = audit(&path, &probe)?;
    assert_eq!(code, 1);
    assert!(report.is_null());
    assert!(
        stderr.contains("unknown field") || stderr.contains("unknown"),
        "{stderr}"
    );

    let not_json = root.path().join("not-json.json");
    fs::write(&not_json, b"{")?;
    let (code, _, _) = audit(&not_json, &probe)?;
    assert_eq!(code, 1);

    let declared = inventory();
    let inventory_path = write(root.path(), "inventory.json", &declared)?;
    let both = run(&[
        "state-audit".as_ref(),
        "--inventory".as_ref(),
        inventory_path.as_os_str(),
        "--probe".as_ref(),
        probe.as_os_str(),
        "--ssh".as_ref(),
        "example.invalid".as_ref(),
    ])?;
    assert_eq!(both.status.code(), Some(1));
    let neither = run(&[
        "state-audit".as_ref(),
        "--inventory".as_ref(),
        inventory_path.as_os_str(),
    ])?;
    assert_eq!(neither.status.code(), Some(1));
    Ok(())
}

#[test]
fn an_output_file_is_never_overwritten() -> Result<()> {
    let root = tempfile::tempdir()?;
    let inventory = write(root.path(), "inventory.json", &inventory())?;
    let probe = write(root.path(), "probe.json", &facts())?;
    let output = root.path().join("report.json");
    fs::write(&output, b"keep me")?;
    let result = run(&[
        "state-audit".as_ref(),
        "--inventory".as_ref(),
        inventory.as_os_str(),
        "--probe".as_ref(),
        probe.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ])?;
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(&output)?, b"keep me");
    Ok(())
}
