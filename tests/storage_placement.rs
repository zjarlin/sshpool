//! 无 RAID 存储放置核算：通过真实二进制跑「可承诺」与「不可承诺」两份拓扑。
//!
//! 这里不复用库函数，因为要证明的正是脚本看到的契约：
//! 标准输出是一份可解析的 JSON、退出码区分可承诺/拒绝、且拒绝时绝不给出可用容量。
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{fs, path::Path};

fn run(arguments: &[&std::ffi::OsStr]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .args(arguments)
        .output()?)
}

fn plan(topology: &Path) -> Result<(i32, Value)> {
    let output = run(&[
        "storage-plan".as_ref(),
        "--topology".as_ref(),
        topology.as_os_str(),
    ])?;
    let code = output.status.code().context("storage-plan was killed")?;
    let text = String::from_utf8(output.stdout)?;
    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("stdout is not one JSON document: {text}"))?;
    Ok((code, value))
}

fn write(root: &Path, name: &str, value: &Value) -> Result<std::path::PathBuf> {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)?;
    Ok(path)
}

fn disk(name: &str, size: u64) -> Value {
    serde_json::json!({ "name": name, "size_bytes": size })
}

#[test]
fn three_real_domains_are_allowed_and_two_are_refused_without_usable_bytes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let allowed_topology = serde_json::json!({
        "schema": 1,
        "replica_count": 3,
        "min_size": 2,
        "recovery_reserve_permille": 200,
        "monitor_count": 3,
        "hosts": [
            { "name": "store-a", "failure_domain": "rack-a",
              "devices": [disk("sda", 4_000_000_000_000)] },
            { "name": "store-b", "failure_domain": "rack-b",
              "devices": [disk("sdb", 6_000_000_000_000)] },
            { "name": "store-c", "failure_domain": "rack-c",
              "devices": [disk("sdc", 8_000_000_000_000)] },
        ],
    });
    let path = write(root.path(), "three.json", &allowed_topology)?;
    let (code, report) = plan(&path)?;
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["scope"], "read-only-storage-placement");
    assert_eq!(report["fault_tolerance_claim_allowed"], true);
    assert_eq!(report["distinct_failure_domains"], 3);
    assert_eq!(report["data_failure_domains"], 3);
    assert_eq!(report["raw_capacity_bytes"], 18_000_000_000_000u64);
    // 每域扣 20% 恢复预留：3200/4800/6400 GiB 级；三副本受最小域约束。
    assert_eq!(report["recovery_reserve_bytes"], 3_600_000_000_000u64);
    let usable = report["usable_after_recovery_reserve_bytes"]
        .as_u64()
        .context("usable bytes")?;
    assert!(usable > 0 && usable <= 4_800_000_000_000, "{usable}");
    assert_eq!(
        report["tolerated_domain_failures"],
        Value::from(3usize - 2),
        "min_size=2 意味着还能少一个域"
    );
    assert_eq!(report["monitor_quorum"], 2);
    assert_eq!(report["tolerated_monitor_failures"], 1);
    assert_eq!(report["blockers"], Value::Array(Vec::new()));
    assert_eq!(report["domains"].as_array().map(Vec::len), Some(3));

    // 三个 VM 但只有两台物理机：第三个「域」是假的。
    let refused_topology = serde_json::json!({
        "schema": 1,
        "replica_count": 3,
        "min_size": 2,
        "recovery_reserve_permille": 200,
        "hosts": [
            { "name": "physical-a", "failure_domain": "site-a",
              "devices": [disk("sda", 4_000_000_000_000)] },
            { "name": "vm-a1", "failure_domain": "site-a", "vm_of": "physical-a",
              "devices": [] },
            { "name": "physical-b", "failure_domain": "site-b",
              "devices": [disk("sdb", 4_000_000_000_000)] },
            { "name": "vm-b1", "failure_domain": "site-b", "vm_of": "physical-b",
              "devices": [] },
        ],
    });
    let path = write(root.path(), "two.json", &refused_topology)?;
    let (code, report) = plan(&path)?;
    assert_eq!(code, 2, "拒绝承诺必须是非零退出码: {report}");
    assert_eq!(report["fault_tolerance_claim_allowed"], false);
    assert_eq!(report["distinct_failure_domains"], 2);
    assert_eq!(report["usable_after_recovery_reserve_bytes"], 0);
    assert_eq!(report["tolerated_domain_failures"], Value::Null);
    ensure!(
        report["blockers"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item.to_string().contains("2 个故障域"))),
        "blockers 必须说明域数不足: {report}"
    );
    Ok(())
}

#[test]
fn a_misspelled_field_is_rejected_before_any_capacity_is_reported() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut topology = serde_json::json!({
        "schema": 1,
        "replica_count": 2,
        "min_size": 1,
        "recovery_reserve_permille": 0,
        "hosts": [
            { "name": "store-a", "failure_domain": "rack-a",
              "devices": [disk("sda", 1000)] },
            { "name": "store-b", "failure_domain": "rack-b",
              "devices": [disk("sdb", 1000)] },
        ],
    });
    // 拼错的键不能被当成默认值静默忽略。
    topology["hosts"][0]["failure_domian"] = Value::from("rack-b");
    let path = write(root.path(), "misspelled.json", &topology)?;
    let output = run(&[
        "storage-plan".as_ref(),
        "--topology".as_ref(),
        path.as_os_str(),
    ])?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "解析错误应是普通失败而不是拒绝承诺"
    );
    assert!(output.stdout.is_empty(), "不能输出半份报告");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field") || stderr.contains("未知字段"),
        "stderr 应指出未知字段: {stderr}"
    );
    Ok(())
}

#[test]
fn a_topology_that_grows_beyond_the_capacity_limit_is_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    let huge = vec![b' '; 4 * 1024 * 1024 + 1];
    let path = root.path().join("huge.json");
    fs::write(&path, huge)?;
    let output = run(&[
        "storage-plan".as_ref(),
        "--topology".as_ref(),
        path.as_os_str(),
    ])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}
