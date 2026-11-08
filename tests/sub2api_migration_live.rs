//! 真实 sub2api 演示实例的入口迁移与切回；只使用一次性 Docker 资源。
//!
//! `SSHPOOL_LIVE_NODE=okm182-lan cargo test --test sub2api_migration_live -- --ignored --nocapture`
//! 原始演练包保留在 `target/live-evidence/sub2api-migration/<uuid>`，包含合成凭据，不能提交。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::Node,
    migration::{Journal, POSTGRES_FINGERPRINT_SQL, REDIS_FINGERPRINT_LUA, fingerprint},
    transport,
};
use std::{fs, path::Path};

#[tokio::test]
#[ignore = "requires an SSH Docker worker with the pinned sub2api, postgres, redis and caddy images"]
async fn application_state_moves_through_one_endpoint_and_returns_with_new_writes() -> Result<()> {
    let node = Node {
        name: "migration-demo".into(),
        ssh: std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?,
        images: Vec::new(),
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
        slo: Default::default(),
    };
    let id = uuid::Uuid::new_v4();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/live-evidence/sub2api-migration")
        .join(id.to_string());
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(root.join("fingerprint.sql"), POSTGRES_FINGERPRINT_SQL)?;
    fs::write(root.join("fingerprint.lua"), REDIS_FINGERPRINT_LUA)?;
    let remote = format!("/tmp/sshpool-app-migration-{id}");
    transport::checked(
        &node,
        &format!("mkdir -m 700 {}", transport::quote(&remote)),
        30,
    )
    .await?;
    for (source, target) in [
        (
            Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/sub2api-migration/rehearse.py"),
            "rehearse.py",
        ),
        (root.join("fingerprint.sql"), "fingerprint.sql"),
        (root.join("fingerprint.lua"), "fingerprint.lua"),
    ] {
        transport::upload(
            &node,
            &format!("cat > {}", transport::quote(&format!("{remote}/{target}"))),
            &source,
        )
        .await?;
    }
    let command = format!(
        "python3 {base}/rehearse.py --output {base}/output --postgres-fingerprint {base}/fingerprint.sql --redis-fingerprint {base}/fingerprint.lua",
        base = transport::quote(&remote),
    );
    // 不重试演练：一次断连不能授权重新执行已有副作用的流程。
    let outcome = transport::capture(&node, &command, 1200).await;
    let archive = root.join("rehearsal.tar");
    transport::download(
        &node,
        &format!("tar -C {} -cf - output", transport::quote(&remote)),
        &archive,
        120,
    )
    .await?;
    tar::Archive::new(fs::File::open(&archive)?).unpack(&root)?;
    let cleanup = format!(
        "python3 -c {}",
        transport::quote(&format!("import shutil; shutil.rmtree({remote:?})"))
    );
    transport::checked(&node, &cleanup, 30).await?;
    eprintln!("rehearsal artifacts: {}", root.display());
    let (code, stdout, stderr) = outcome?;
    eprintln!("{}", String::from_utf8_lossy(&stdout));
    ensure!(
        code == 0,
        "rehearsal failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("output/report.json"))?)?;
    let checks = report["checks"].as_object().context("checks missing")?;
    for name in [
        "initial_credit_applied",
        "a_app_stopped_cleanly",
        "a_sql_write_rejected",
        "a_redis_write_rejected",
        "a_queue_pending",
        "b_configuration_files_restored",
        "forward_fingerprints_equal",
        "b_old_access_token_valid",
        "b_refresh_session_survived",
        "b_fresh_login",
        "forward_credit_not_duplicated",
        "b_new_credit_and_sequence",
        "b_queue_consumed",
        "b_stale_cache_invalidated",
        "a_stayed_frozen",
        "b_app_stopped_cleanly",
        "b_sql_write_rejected",
        "b_redis_write_rejected",
        "b_queue_pending",
        "return_configuration_files_restored",
        "reverse_fingerprints_equal",
        "return_old_access_token_valid",
        "return_refresh_session_survived",
        "return_fresh_login",
        "b_credit_survived_switchback",
        "return_credit_and_sequence",
        "return_queue_consumed",
        "return_stale_cache_invalidated",
        "b_stayed_frozen",
        "both_backups_retained",
        "resources_removed",
        "redis_unordered_values_and_stream_stable",
        "redis_binary_boundaries_distinguished",
    ] {
        ensure!(
            checks.get(name) == Some(&serde_json::Value::Bool(true)),
            "required check missing or failed: {name}"
        );
    }
    for (name, value) in checks {
        ensure!(value == true, "check did not pass: {name}");
    }
    let transfers = report["transfers"]
        .as_array()
        .context("transfers missing")?;
    ensure!(transfers.len() == 2, "both directions must be verified");
    let frozen = report["frozen_observations"]
        .as_array()
        .context("frozen observations missing")?;
    ensure!(frozen.len() == 2, "both old writers must stay frozen");
    for transfer in transfers.iter().chain(frozen) {
        let parse = |side: &str| -> Result<_> {
            fingerprint(
                transfer[side]["postgres"]
                    .as_str()
                    .context("PostgreSQL print missing")?,
                transfer[side]["redis"]
                    .as_str()
                    .context("Redis print missing")?,
            )
        };
        let at = transfer["compared_at_ms"]
            .as_i64()
            .context("comparison time missing")?;
        let (before, _) = parse("before")?;
        let (after, _) = parse("after")?;
        let before = before.at_time(at)?;
        let after = after.at_time(at)?;
        ensure!(
            before.differences(&after).is_empty() && before.digest()? == after.digest()?,
            "restored contents differ: {:?}",
            before.differences(&after)
        );
        eprintln!(
            "{} -> {}: {} tables, {} sequences, {} Redis keys verified",
            transfer["from"],
            transfer["to"],
            before.postgres.tables.len(),
            before.postgres.sequences.len(),
            before.redis.keys.len()
        );
    }
    let mut journal = Journal::new();
    for entry in report["steps"].as_array().context("steps missing")? {
        journal.append(
            entry["step"].as_str().context("step missing")?,
            format!("observed at {}", entry["at"]),
        )?;
    }
    journal.save(&root.join("migration-journal.jsonl"))?;
    Journal::load(&root.join("migration-journal.jsonl"))?.verify()?;
    eprintln!(
        "{} checks passed; {} journal entries verified",
        checks.len(),
        journal.entries().len()
    );
    Ok(())
}
