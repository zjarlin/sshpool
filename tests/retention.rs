//! 任务归档保留策略：失败关闭核对、可恢复归档与移动式清理。
//!
//! 这些测试不需要 Docker 或 SSH：全部在临时 home 里构造任务目录，
//! 走与真实命令行相同的库接口。
use anyhow::Result;
use sshpool::{
    config::{Build, Config},
    model::{Attempt, Job, Phase},
    retention,
};
use std::{fs, path::Path};

fn job(phase: Phase, finished_at: Option<u64>, cleanup: Option<bool>) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        revision: 3,
        build: Build::default(),
        phase,
        created_at: 1000,
        finished_at,
        attempts: vec![Attempt {
            node: "worker".into(),
            container: "sshpool-test-1".into(),
            started_at: 1000,
            outcome: Some("ok".into()),
            cleanup_confirmed: cleanup,
            watchdog_deadline: None,
            cleanup_proof: None,
        }],
        exit_code: Some(0),
        message: Some("test".into()),
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: cleanup == Some(true),
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    }
}

/// 在 home 下写一个形状正确的任务目录：记录 + 源码归档 + 版本预留。
fn write_job(home: &Path, job: &mut Job) -> Result<()> {
    let directory = home.join("jobs").join(job.id.to_string());
    fs::create_dir_all(&directory)?;
    let source = directory.join("source.tar");
    {
        let file = fs::File::create(&source)?;
        let mut builder = tar::Builder::new(file);
        let payload = b"fn main() {}\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, "src/main.rs", &payload[..])?;
        builder.finish()?;
    }
    job.source_sha256 = Some(sshpool::archive::sha256_file(&source)?);
    fs::write(directory.join("job.json"), serde_json::to_vec_pretty(job)?)?;
    fs::write(directory.join(".revision"), job.revision.to_string())?;
    Ok(())
}

fn home() -> Result<tempfile::TempDir> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("jobs"))?;
    Ok(root)
}

#[test]
fn inspection_rejects_unexplained_directories_instead_of_skipping_them() -> Result<()> {
    let root = home()?;
    let mut good = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut good)?;
    // 控制面启动时会静默跳过这种目录；清理必须把它当成 blocker。
    fs::create_dir(root.path().join("jobs").join("archive-old"))?;
    let missing = uuid::Uuid::new_v4();
    fs::create_dir(root.path().join("jobs").join(missing.to_string()))?;

    let report = retention::inspect(root.path(), &Config::default())?;
    assert_eq!(report.jobs, 3);
    assert_eq!(report.blockers.len(), 2);
    assert!(
        report
            .blockers
            .iter()
            .any(|line| line.contains("archive-old"))
    );
    assert!(
        report
            .blockers
            .iter()
            .any(|line| line.contains(&missing.to_string()))
    );
    assert_eq!(
        report
            .entries
            .iter()
            .filter(|entry| entry.bundle_ready)
            .count(),
        1
    );
    assert!(retention::plan(root.path(), &Config::default(), 60, 0, 10_000).is_err());
    Ok(())
}

#[test]
fn inspection_rejects_record_digest_and_revision_disagreement() -> Result<()> {
    let root = home()?;
    let mut changed = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut changed)?;
    let directory = root.path().join("jobs").join(changed.id.to_string());
    // 源码被替换而记录未更新。
    let mut other = tempfile::NamedTempFile::new()?;
    {
        use std::io::Write;
        other.write_all(b"not a tar archive")?;
    }
    fs::copy(other.path(), directory.join("source.tar"))?;
    // 版本预留领先于已发布记录，说明有失败写入或外部改动。
    fs::write(
        directory.join(".revision"),
        (changed.revision + 5).to_string(),
    )?;

    let report = retention::inspect(root.path(), &Config::default())?;
    let problem = report.entries[0]
        .problem
        .as_deref()
        .expect("必须在报告里给出原因");
    assert!(problem.contains("source archive"), "{problem}");
    assert!(problem.contains("revision reservation"), "{problem}");
    assert!(!report.entries[0].bundle_ready);
    Ok(())
}

#[test]
fn terminal_states_with_unconfirmed_cleanup_are_never_pruned() -> Result<()> {
    let root = home()?;
    let mut confirmed = job(Phase::Succeeded, Some(1000), Some(true));
    let mut unconfirmed = job(Phase::Failed, Some(1000), Some(false));
    let mut unknown = job(Phase::Cancelled, Some(1000), None);
    let mut interrupted = job(Phase::Interrupted, Some(1000), Some(true));
    let mut running = job(Phase::Running, None, Some(true));
    for job in [
        &mut confirmed,
        &mut unconfirmed,
        &mut unknown,
        &mut interrupted,
        &mut running,
    ] {
        write_job(root.path(), job)?;
    }
    let plan = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].id, confirmed.id);
    let reasons = plan
        .skipped
        .iter()
        .map(|skip| skip.reason.as_str())
        .collect::<Vec<_>>();
    assert!(reasons.iter().any(|reason| reason.contains("cleanup")));
    assert!(reasons.iter().any(|reason| reason.contains("interrupted")));
    assert!(reasons.iter().any(|reason| reason.contains("still active")));
    Ok(())
}

#[test]
fn legacy_records_without_per_attempt_cleanup_follow_the_top_level_flag() -> Result<()> {
    let root = home()?;
    // 旧记录：attempt 没有 cleanup_confirmed，顶层为 true —— 与调度器一致，视为已确认。
    let mut legacy = job(Phase::Succeeded, Some(1000), None);
    legacy.cleanup_confirmed = true;
    write_job(root.path(), &mut legacy)?;
    // 同一形状但顶层为 false：不能清理。
    let mut unproven = job(Phase::Failed, Some(1000), None);
    unproven.cleanup_confirmed = false;
    write_job(root.path(), &mut unproven)?;
    // 显式 Some(false) 不能被顶层 true 覆盖。
    let mut explicit = job(Phase::Failed, Some(1000), Some(false));
    explicit.cleanup_confirmed = true;
    write_job(root.path(), &mut explicit)?;

    let plan = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].id, legacy.id);
    Ok(())
}

#[test]
fn keep_last_and_age_are_both_required_before_a_job_qualifies() -> Result<()> {
    let root = home()?;
    let mut ids = Vec::new();
    for finished in [100, 200, 300, 400] {
        let mut record = job(Phase::Succeeded, Some(finished), Some(true));
        record.created_at = finished;
        write_job(root.path(), &mut record)?;
        ids.push((finished, record.id));
    }
    // now=1000：除 400 外都已超过 300 秒；keep_last=2 保留最新的两条（300、400）。
    let plan = retention::plan(root.path(), &Config::default(), 300, 2, 1000)?;
    assert_eq!(plan.candidates.len(), 2);
    let candidate_ids = plan
        .candidates
        .iter()
        .map(|candidate| candidate.id)
        .collect::<Vec<_>>();
    assert!(candidate_ids.contains(&ids[0].1));
    assert!(candidate_ids.contains(&ids[1].1));
    assert_eq!(plan.older_than_secs, 300);
    assert_eq!(plan.keep_last, 2);
    // 保留的是最新两条，不是最早两条。
    assert!(!candidate_ids.contains(&ids[2].1));
    assert!(!candidate_ids.contains(&ids[3].1));
    Ok(())
}

#[test]
fn apply_writes_a_restorable_bundle_and_moves_instead_of_deleting() -> Result<()> {
    let root = home()?;
    let mut record = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut record)?;
    let plan = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    assert_eq!(plan.candidates.len(), 1);
    let report = retention::apply(root.path(), &Config::default(), &plan, false)?;
    assert_eq!(report.pruned.len(), 1);
    let pruned = &report.pruned[0];
    assert!(!pruned.purged);
    assert!(pruned.bundle.is_file());
    // 任务目录已移出 jobs/，但仍在 staged 目录里可找回。
    assert!(
        !root
            .path()
            .join("jobs")
            .join(record.id.to_string())
            .exists()
    );
    assert!(pruned.staged.as_ref().expect("staged dir").is_dir());
    assert_eq!(report.remaining_jobs, 0);
    // 归档能被 mirror 重新安装，且内容与清理前一致。
    let verify = tempfile::tempdir()?;
    fs::create_dir(verify.path().join("jobs"))?;
    let restored =
        sshpool::mirror::install_bundle(verify.path(), record.id, &pruned.bundle, u64::MAX)?;
    let stored: Job = serde_json::from_slice(&fs::read(restored.join("job.json"))?)?;
    assert_eq!(stored.id, record.id);
    assert_eq!(stored.phase, Phase::Succeeded);
    assert!(restored.join("source.tar").is_file());
    Ok(())
}

#[test]
fn purge_reclaims_the_moved_directory_keeps_the_bundle() -> Result<()> {
    let root = home()?;
    let mut record = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut record)?;
    let plan = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    let report = retention::apply(root.path(), &Config::default(), &plan, true)?;
    assert!(report.purged);
    let pruned = &report.pruned[0];
    assert!(pruned.purged);
    assert!(pruned.staged.as_ref().is_none_or(|staged| !staged.exists()));
    assert!(pruned.bundle.is_file());
    assert!(report.staged_root.is_none());
    Ok(())
}

#[test]
fn apply_is_idempotent_after_a_clean_run_and_rejects_a_stale_plan() -> Result<()> {
    let root = home()?;
    let mut record = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut record)?;
    let plan = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    retention::apply(root.path(), &Config::default(), &plan, false)?;
    // 同一计划再执行一次：候选集合已变化，必须拒绝而不是重复归档。
    let error = retention::apply(root.path(), &Config::default(), &plan, false)
        .expect_err("stale plan must be rejected");
    assert!(
        format!("{error:#}").contains("changed since the plan"),
        "{error:#}"
    );
    let again = retention::plan(root.path(), &Config::default(), 60, 0, 10_000)?;
    assert!(again.candidates.is_empty());
    let report = retention::apply(root.path(), &Config::default(), &again, false)?;
    assert!(report.pruned.is_empty());
    Ok(())
}

#[test]
fn a_failed_bundle_rolls_back_the_batch() -> Result<()> {
    let root = home()?;
    let mut first = job(Phase::Succeeded, Some(1000), Some(true));
    let mut second = job(Phase::Succeeded, Some(1001), Some(true));
    write_job(root.path(), &mut first)?;
    write_job(root.path(), &mut second)?;
    let plan = retention::plan(root.path(), &Config::default(), 1, 0, 10_000)?;
    assert_eq!(plan.candidates.len(), 2);
    // 让第二条在归档阶段失败：源码在计划之后被破坏。
    let broken = root.path().join("jobs").join(second.id.to_string());
    fs::write(broken.join("source.tar"), b"corrupted")?;
    // 计划复核会先发现变化并拒绝，因此任务库保持原状。
    let error = retention::apply(root.path(), &Config::default(), &plan, false)
        .expect_err("changed store must be rejected");
    assert!(
        format!("{error:#}").contains("changed since the plan")
            || format!("{error:#}").contains("source archive")
    );
    assert!(root.path().join("jobs").join(first.id.to_string()).is_dir());
    assert!(
        root.path()
            .join("jobs")
            .join(second.id.to_string())
            .is_dir()
    );
    Ok(())
}

#[test]
fn legacy_records_without_a_source_digest_block_pruning() -> Result<()> {
    let root = home()?;
    let mut record = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut record)?;
    // 旧记录缺摘要：清理前必须先 adopt 补齐，否则归档无法核对来源。
    record.source_sha256 = None;
    fs::write(
        root.path()
            .join("jobs")
            .join(record.id.to_string())
            .join("job.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    let report = retention::inspect(root.path(), &Config::default())?;
    let problem = report.entries[0].problem.as_deref().unwrap_or_default();
    assert!(problem.contains("source digest is missing"), "{problem}");
    assert!(retention::plan(root.path(), &Config::default(), 1, 0, 10_000).is_err());
    Ok(())
}

#[tokio::test]
async fn adopting_a_legacy_record_unblocks_pruning() -> Result<()> {
    let root = home()?;
    let mut record = job(Phase::Succeeded, Some(1000), Some(true));
    write_job(root.path(), &mut record)?;
    // 模拟升级前的旧记录：没有源码摘要，其它字段齐备。
    record.source_sha256 = None;
    fs::write(
        root.path()
            .join("jobs")
            .join(record.id.to_string())
            .join("job.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    let config = Config::default();
    let blocked = retention::plan(root.path(), &config, 1, 0, 10_000)
        .expect_err("legacy record without digest must block pruning");
    assert!(format!("{blocked:#}").contains("source digest is missing"));

    // 升级路径：先补摘要并发布新 revision，再做保留清理。
    let adopted = sshpool::mirror::adopt_legacy_job(&config, root.path(), record.id).await?;
    assert_eq!(adopted.id, record.id);
    assert!(adopted.source_sha256.is_some());
    assert_eq!(adopted.revision, record.revision + 1);
    // adopt 会先留一份旧 job.json 的备份。
    let backups = fs::read_dir(root.path().join("backups").join("jobs"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(backups.len(), 1);
    assert!(
        backups[0]
            .file_name()
            .to_string_lossy()
            .contains("-legacy-")
    );

    let plan = retention::plan(root.path(), &config, 1, 0, 10_000)?;
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].id, record.id);
    Ok(())
}
