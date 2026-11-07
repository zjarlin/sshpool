//! 任务归档的保留策略：只读核对、可恢复备份与到期清理。
//!
//! 失败关闭规则：
//! - 任何无法解释的任务目录都是 blocker，阻塞整批清理，而不是被静默跳过；
//! - 只有 `succeeded` / `failed` / `cancelled`、结束时间已知且清理逐个确认的终态才是候选；
//! - `interrupted` 可能被 reconciler 自动重跑，永不作为候选；
//! - 清理前必须先写出「能再安装一次」的恢复归档，而不只是写成功；
//! - 任务目录是移动而不是就地删除；只有显式 purge 才回收空间；
//! - `controller.lock` 必须可独占获取，避免对着运行中控制面的内存状态做离线清理。
use crate::{
    archive,
    config::{self, Config},
    mirror,
    model::{Job, Phase, now},
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::Serialize;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// 报告格式版本；字段只增不改，便于脚本消费。
pub const SCHEMA: u32 = 1;

/// 任务目录只允许这些文件；未知文件不会进归档，因此必须阻塞清理而不是被静默丢弃。
const ALLOWED_FILES: &[&str] = &[
    "job.json",
    ".revision",
    "source.tar",
    "log.txt",
    "events.jsonl",
    "artifacts.tar",
];

/// 与副本打包使用同一上限，避免清理阶段生成超规归档。
fn bundle_limit(config: &Config) -> u64 {
    (config.max_upload_mib + config.max_artifact_mib + config.max_log_mib + 16) * 1048576
}

/// 只有确定不会再有执行者的终态才可能被清理。
///
/// `interrupted` 被排除：reconciler 可能在证明旧容器终止后自动重跑它。
pub fn prunable(phase: &Phase) -> bool {
    matches!(phase, Phase::Succeeded | Phase::Failed | Phase::Cancelled)
}

/// 清理确认与调度器的隔离判定必须用同一套语义。
///
/// 旧记录没有逐 attempt 的 `cleanup_confirmed` 字段（`None`），此时顶层标志就是
/// 该任务全部尝试的结论；`Some(false)` 永远不能被顶层标志覆盖，否则一个仍可能
/// 在运行的容器会被当成已清理。
pub fn cleanup_proven(job: &Job) -> bool {
    job.attempts
        .iter()
        .all(|attempt| match attempt.cleanup_confirmed {
            Some(confirmed) => confirmed,
            None => job.cleanup_confirmed,
        })
}

/// 单个任务目录的核对结果。
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub id: Option<Uuid>,
    pub directory: String,
    pub phase: Option<Phase>,
    pub revision: Option<u64>,
    pub finished_at: Option<u64>,
    pub bytes: u64,
    pub files: usize,
    /// 该目录是否具备生成并验证恢复归档的全部前提。
    pub bundle_ready: bool,
    pub problem: Option<String>,
}

/// 整个任务库的只读核对。
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub schema: u32,
    pub home: PathBuf,
    pub jobs: usize,
    pub total_bytes: u64,
    pub entries: Vec<Entry>,
    /// 非空即拒绝清理；这是失败关闭的主要出口。
    pub blockers: Vec<String>,
}

/// 进入清理计划的单个任务。
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub id: Uuid,
    pub phase: Phase,
    pub finished_at: u64,
    pub age_secs: u64,
    pub bytes: u64,
}

/// 被保留的任务及原因；运维据此判断策略是否符合预期。
#[derive(Clone, Debug, Serialize)]
pub struct Skip {
    pub id: Option<Uuid>,
    pub directory: String,
    pub reason: String,
}

/// 清理计划；`apply` 之前不改动任何文件。
#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub schema: u32,
    pub home: PathBuf,
    pub now: u64,
    pub older_than_secs: u64,
    pub keep_last: usize,
    pub jobs: usize,
    pub total_bytes: u64,
    pub candidates: Vec<Candidate>,
    pub candidate_bytes: u64,
    pub skipped: Vec<Skip>,
    /// 每个候选生成归档时允许的字节上限。
    pub bundle_limit: u64,
}

/// 已生成归档并移出任务库的单条记录。
#[derive(Clone, Debug, Serialize)]
pub struct Pruned {
    pub id: Uuid,
    pub phase: Phase,
    pub finished_at: u64,
    pub bytes: u64,
    pub bundle: PathBuf,
    pub bundle_bytes: u64,
    pub bundle_sha256: String,
    pub staged: Option<PathBuf>,
    pub purged: bool,
}

/// 一次实际清理的结果；失败时已移动的目录会回滚。
#[derive(Clone, Debug, Serialize)]
pub struct PruneReport {
    pub schema: u32,
    pub home: PathBuf,
    pub purged: bool,
    pub staged_root: Option<PathBuf>,
    pub pruned: Vec<Pruned>,
    pub skipped: Vec<Skip>,
    pub job_bytes_moved: u64,
    pub bundle_bytes: u64,
    pub remaining_jobs: usize,
    pub remaining_bytes: u64,
}

fn read_reserved_revision(directory: &Path) -> Result<Option<u64>> {
    match fs::read_to_string(directory.join(".revision")) {
        Ok(value) => Ok(Some(value.trim().parse::<u64>().with_context(|| {
            format!("invalid revision reservation in {directory:?}")
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// 统计目录里的常规文件字节数，并把非文件条目标记为问题。
fn measure(path: &Path) -> Result<(u64, usize, Vec<String>)> {
    let mut bytes: u64 = 0;
    let mut files = 0;
    let mut problems = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            problems.push(format!("symbolic link in job directory: {name}"));
            continue;
        }
        if !metadata.is_file() {
            problems.push(format!("non-file entry in job directory: {name}"));
            continue;
        }
        bytes = bytes.saturating_add(metadata.len());
        files += 1;
        if !ALLOWED_FILES.contains(&name.as_str()) {
            problems.push(format!("unknown file in job directory: {name}"));
        }
    }
    Ok((bytes, files, problems))
}

fn inspect_job(path: &Path, name: &str, limit: u64) -> Entry {
    let mut entry = Entry {
        id: None,
        directory: name.to_string(),
        phase: None,
        revision: None,
        finished_at: None,
        bytes: 0,
        files: 0,
        bundle_ready: false,
        problem: None,
    };
    let mut problems = Vec::new();
    let Ok(metadata) = fs::symlink_metadata(path) else {
        entry.problem = Some("cannot read entry metadata".into());
        return entry;
    };
    if metadata.file_type().is_symlink() {
        problems.push("task entry is a symbolic link".into());
    } else if !metadata.is_dir() {
        problems.push("task entry is not a directory".into());
    }
    if !problems.is_empty() {
        entry.problem = Some(problems.join("; "));
        return entry;
    }
    match measure(path) {
        Ok((bytes, files, found)) => {
            entry.bytes = bytes;
            entry.files = files;
            problems.extend(found);
        }
        Err(error) => problems.push(format!("cannot read job directory: {error}")),
    }
    // 目录名必须是规范 UUID 文本；否则可能在移动时与另一个任务混淆。
    match Uuid::parse_str(name) {
        Ok(id) if id.to_string() == name => entry.id = Some(id),
        Ok(_) => problems.push("directory name is not the canonical UUID form".into()),
        Err(_) => problems.push("directory name is not a job UUID".into()),
    }
    let job = match fs::read(path.join("job.json")) {
        Ok(bytes) => match serde_json::from_slice::<Job>(&bytes) {
            Ok(job) => Some(job),
            Err(error) => {
                problems.push(format!("job.json is not a valid task record: {error}"));
                None
            }
        },
        Err(error) => {
            problems.push(format!("job.json is unreadable: {error}"));
            None
        }
    };
    if let Some(job) = &job {
        entry.phase = Some(job.phase.clone());
        entry.revision = Some(job.revision);
        entry.finished_at = job.finished_at;
        if entry.id != Some(job.id) {
            problems.push(format!(
                "job.json identity {} does not match the directory",
                job.id
            ));
        }
        if job.phase.terminal() && job.finished_at.is_none() {
            problems.push("terminal record has no finish time".into());
        }
        match read_reserved_revision(path) {
            Ok(Some(reserved)) if reserved > job.revision => problems.push(format!(
                "revision reservation {reserved} is ahead of stored revision {}",
                job.revision
            )),
            Ok(_) => {}
            Err(error) => problems.push(format!(".revision is invalid: {error}")),
        }
        let source = path.join("source.tar");
        match archive::validate(&source, limit, None) {
            Ok(()) => match job.source_sha256.as_deref() {
                None => problems.push(
                    "source digest is missing; adopt the legacy record before pruning".into(),
                ),
                Some(digest) => match archive::sha256_file(&source) {
                    Ok(actual) if actual == digest => {}
                    Ok(_) => {
                        problems.push("source archive digest does not match the record".into())
                    }
                    Err(error) => problems.push(format!("source digest is unavailable: {error}")),
                },
            },
            Err(error) => problems.push(format!("source archive is invalid: {error}")),
        }
        if job.artifacts {
            let artifacts = path.join("artifacts.tar");
            if let Err(error) = archive::validate(&artifacts, limit, None) {
                problems.push(format!("declared artifacts archive is invalid: {error}"));
            }
        }
    }
    entry.bundle_ready = problems.is_empty() && job.is_some();
    if !problems.is_empty() {
        entry.problem = Some(problems.join("; "));
    }
    entry
}

/// 只读核对整个任务库：目录归属、记录格式、归档摘要与版本预留。
///
/// 控制面启动时的 `State::load` 会静默跳过无法解释的目录；清理不能沿用这种语义，
/// 否则一个命名错误的历史任务会永远留在磁盘上或被误当成过期数据。
pub fn inspect(home: &Path, config: &Config) -> Result<Inspection> {
    config::validate(config)?;
    let jobs = home.join("jobs");
    ensure!(jobs.is_dir(), "task store is missing: {}", jobs.display());
    let limit = bundle_limit(config);
    let mut entries = Vec::new();
    let mut blockers = Vec::new();
    let mut total_bytes = 0_u64;
    let mut raw = fs::read_dir(&jobs)?.collect::<std::io::Result<Vec<_>>>()?;
    raw.sort_by_key(|entry| entry.file_name());
    for entry in raw {
        let name = entry.file_name().to_string_lossy().to_string();
        let inspected = inspect_job(&entry.path(), &name, limit);
        total_bytes = total_bytes.saturating_add(inspected.bytes);
        if let Some(problem) = &inspected.problem {
            blockers.push(format!("{name}: {problem}"));
        }
        entries.push(inspected);
    }
    Ok(Inspection {
        schema: SCHEMA,
        home: home.to_path_buf(),
        jobs: entries.len(),
        total_bytes,
        entries,
        blockers,
    })
}

fn read_job(directory: &Path) -> Result<Job> {
    Ok(serde_json::from_slice(&fs::read(
        directory.join("job.json"),
    )?)?)
}

/// 按显式策略生成清理计划；任何格式问题都先失败。
pub fn plan(
    home: &Path,
    config: &Config,
    older_than_secs: u64,
    keep_last: usize,
    now: u64,
) -> Result<Plan> {
    ensure!(older_than_secs > 0, "retention age must be positive");
    let inspection = inspect(home, config)?;
    ensure!(
        inspection.blockers.is_empty(),
        "{} task directories failed validation; inspect them before pruning:\n{}",
        inspection.blockers.len(),
        inspection.blockers.join("\n")
    );
    let mut terminal = Vec::new();
    let mut skipped = Vec::new();
    for entry in &inspection.entries {
        let id = entry.id.context("validated task entry has no identity")?;
        let job = read_job(&home.join("jobs").join(&entry.directory))?;
        if !prunable(&job.phase) {
            let reason = if job.phase == Phase::Interrupted {
                "interrupted task may still be resumed by reconcile"
            } else {
                "task is still active"
            };
            skipped.push(Skip {
                id: Some(id),
                directory: entry.directory.clone(),
                reason: reason.into(),
            });
            continue;
        }
        let Some(finished_at) = job.finished_at else {
            skipped.push(Skip {
                id: Some(id),
                directory: entry.directory.clone(),
                reason: "finish time is unknown".into(),
            });
            continue;
        };
        if !cleanup_proven(&job) {
            skipped.push(Skip {
                id: Some(id),
                directory: entry.directory.clone(),
                reason: "cleanup is not confirmed for every attempt".into(),
            });
            continue;
        }
        terminal.push((
            finished_at,
            job.created_at,
            id,
            job.phase.clone(),
            entry.bytes,
        ));
    }
    // 最近完成的若干条无论多旧都保留，避免一次策略失误清空整个历史。
    terminal.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then(right.1.cmp(&left.1))
            .then(right.2.cmp(&left.2))
    });
    let mut candidates = Vec::new();
    for (index, (finished_at, _created_at, id, phase, bytes)) in terminal.into_iter().enumerate() {
        if index < keep_last {
            skipped.push(Skip {
                id: Some(id),
                directory: id.to_string(),
                reason: format!("kept by keep_last={keep_last}"),
            });
            continue;
        }
        if finished_at.saturating_add(older_than_secs) > now {
            skipped.push(Skip {
                id: Some(id),
                directory: id.to_string(),
                reason: "finished too recently for this retention age".into(),
            });
            continue;
        }
        candidates.push(Candidate {
            id,
            phase,
            finished_at,
            age_secs: now.saturating_sub(finished_at),
            bytes,
        });
    }
    candidates.sort_by_key(|candidate| (candidate.finished_at, candidate.id));
    let candidate_bytes = candidates
        .iter()
        .fold(0_u64, |sum, candidate| sum.saturating_add(candidate.bytes));
    Ok(Plan {
        schema: SCHEMA,
        home: home.to_path_buf(),
        now,
        older_than_secs,
        keep_last,
        jobs: inspection.jobs,
        total_bytes: inspection.total_bytes,
        candidates,
        candidate_bytes,
        skipped,
        bundle_limit: bundle_limit(config),
    })
}

/// 独占控制面锁；返回的句柄必须活到清理结束。
fn offline_guard(home: &Path) -> Result<File> {
    let path = home.join("controller.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    file.try_lock_exclusive().context(
        "controller is running on this home; stop it before pruning so in-memory task state cannot go stale",
    )?;
    Ok(file)
}

/// 回收已移出 `jobs/` 的目录；第一个失败即停止，并把实际删到哪一条报告给调用方。
///
/// 这里只做删除，不影响已经生成并验证过的归档。
fn purge_staged(pruned: &mut [Pruned]) -> Option<(Uuid, std::io::Error)> {
    for record in pruned {
        if let Some(staged) = &record.staged {
            match fs::remove_dir_all(staged) {
                Ok(()) => record.purged = true,
                Err(error) => return Some((record.id, error)),
            }
        }
    }
    None
}

fn stage_one(
    home: &Path,
    backups: &Path,
    staged_root: &Path,
    verify_root: &Path,
    candidate: &Candidate,
    limit: u64,
) -> Result<Pruned> {
    let jobs = home.join("jobs");
    let source_dir = jobs.join(candidate.id.to_string());
    ensure!(
        source_dir.is_dir(),
        "task directory disappeared: {}",
        candidate.id
    );
    let bundle = backups.join(format!("{}-{}-{}.tar", candidate.id, now(), Uuid::new_v4()));
    let staged = staged_root.join(candidate.id.to_string());
    let result = (|| {
        let manifest = mirror::create_bundle(&source_dir, &bundle, limit)?;
        ensure!(manifest.job == candidate.id, "bundle identity mismatch");
        ensure!(
            archive::sha256_file(&bundle)? == manifest.bundle_sha256,
            "bundle digest changed after creation"
        );
        // 只写成功不足以证明可恢复：再安装一次并比对记录内容。
        let restored = mirror::install_bundle(verify_root, candidate.id, &bundle, limit)?;
        let live = read_job(&source_dir)?;
        let stored = read_job(&restored)?;
        ensure!(
            serde_json::to_vec(&live)? == serde_json::to_vec(&stored)?,
            "restored record differs from the live record"
        );
        ensure!(
            live.finished_at == Some(candidate.finished_at),
            "task finish time changed after planning"
        );
        fs::remove_dir_all(&restored)?;
        fs::rename(&source_dir, &staged)?;
        File::open(&jobs)?.sync_all()?;
        File::open(staged_root)?.sync_all()?;
        Ok(Pruned {
            id: candidate.id,
            phase: candidate.phase.clone(),
            finished_at: candidate.finished_at,
            bytes: candidate.bytes,
            bundle: bundle.clone(),
            bundle_bytes: manifest.bytes,
            bundle_sha256: manifest.bundle_sha256,
            staged: Some(staged.clone()),
            purged: false,
        })
    })();
    if result.is_err() {
        // 半成品归档与已移出的目录都必须撤销：任务仍在 jobs/ 时，
        // 一份看似完整的归档会让人误以为它已经备份并清理过。
        let _ = fs::remove_file(&bundle);
        if staged.exists() {
            let _ = fs::rename(&staged, &source_dir);
        }
    }
    result
}

/// 回滚已移动的任务目录，并删掉这批刚生成、已不再代表「归档」的临时归档。
///
/// 任务仍在 `jobs/` 里时，一份残留的归档会让人误以为它已被清理；归档可以在下次
/// 清理时重新生成，因此这里删掉它们比留下更好。
fn rollback(home: &Path, pruned: &[Pruned]) {
    let jobs = home.join("jobs");
    for record in pruned.iter().rev() {
        if let Some(staged) = &record.staged {
            let _ = fs::rename(staged, jobs.join(record.id.to_string()));
        }
        let _ = fs::remove_file(&record.bundle);
    }
    let _ = File::open(&jobs).and_then(|file| file.sync_all());
}

/// 执行计划：先写归档并验证可恢复，再把任务目录移出 `jobs/`。
///
/// 任一条失败都会把本批已移动的目录移回，任务库保持原状。
pub fn apply(home: &Path, config: &Config, plan: &Plan, purge: bool) -> Result<PruneReport> {
    apply_with(home, config, plan, purge, stage_one)
}

/// 只挂在同一调度路径上的归档+移动步骤；测试用这一层注入失败，验证整批回滚。
fn apply_with(
    home: &Path,
    config: &Config,
    plan: &Plan,
    purge: bool,
    mut stage: impl FnMut(&Path, &Path, &Path, &Path, &Candidate, u64) -> Result<Pruned>,
) -> Result<PruneReport> {
    let _lock = offline_guard(home)?;
    ensure!(
        plan.home == home,
        "plan was generated for a different home: {}",
        plan.home.display()
    );
    // 计划与执行之间可能有人写入；用同一时钟重新核对候选集合。
    let current = self::plan(home, config, plan.older_than_secs, plan.keep_last, plan.now)?;
    let before = plan
        .candidates
        .iter()
        .map(|candidate| (candidate.id, candidate.finished_at, candidate.bytes))
        .collect::<Vec<_>>();
    let after = current
        .candidates
        .iter()
        .map(|candidate| (candidate.id, candidate.finished_at, candidate.bytes))
        .collect::<Vec<_>>();
    ensure!(
        before == after,
        "task store changed since the plan was generated; re-run `sshpool jobs prune`"
    );
    if current.candidates.is_empty() {
        return Ok(PruneReport {
            schema: SCHEMA,
            home: home.to_path_buf(),
            purged: false,
            staged_root: None,
            pruned: Vec::new(),
            skipped: current.skipped,
            job_bytes_moved: 0,
            bundle_bytes: 0,
            remaining_jobs: current.jobs,
            remaining_bytes: current.total_bytes,
        });
    }
    let backups = home.join("backups").join("jobs");
    fs::create_dir_all(&backups)?;
    let staged_root = backups.join(format!("pruned-{}-{}", now(), Uuid::new_v4()));
    fs::create_dir(&staged_root)?;
    File::open(&backups)?.sync_all()?;
    let verify_root = staged_root.join(format!(".verify-{}", Uuid::new_v4()));
    fs::create_dir(&verify_root)?;
    let mut pruned = Vec::new();
    let mut failure = None;
    for candidate in &current.candidates {
        match stage(
            home,
            &backups,
            &staged_root,
            &verify_root,
            candidate,
            current.bundle_limit,
        ) {
            Ok(record) => pruned.push(record),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    if let Some(error) = failure {
        rollback(home, &pruned);
        let _ = fs::remove_dir_all(&verify_root);
        // 空目录也会让运维以为存在一批已归档的任务；回滚后没有 staged 目录就该清掉。
        let _ = fs::remove_dir(&staged_root);
        return Err(error.context("retention batch aborted; moved task directories were restored"));
    }
    if verify_root.exists() {
        fs::remove_dir_all(&verify_root)?;
    }
    let purge_failure = if purge {
        let failure = purge_staged(&mut pruned);
        File::open(&staged_root)?.sync_all()?;
        failure
    } else {
        None
    };
    if let Some((failed, error)) = purge_failure {
        // 归档都已生成且验证过；删不掉的移动目录只是多占空间。
        // 报告实际删到哪一条比丢掉整份报告更安全，也不必回滚已经完成的归档。
        let staged_root = Some(staged_root);
        let remaining = inspect(home, config)?;
        let report = PruneReport {
            schema: SCHEMA,
            home: home.to_path_buf(),
            purged: false,
            staged_root: staged_root.clone(),
            job_bytes_moved: pruned
                .iter()
                .fold(0_u64, |sum, record| sum.saturating_add(record.bytes)),
            bundle_bytes: pruned
                .iter()
                .fold(0_u64, |sum, record| sum.saturating_add(record.bundle_bytes)),
            pruned,
            skipped: current.skipped,
            remaining_jobs: remaining.jobs,
            remaining_bytes: remaining.total_bytes,
        };
        // 标准输出只留给成功路径；失败报告走 stderr，调用方仍返回非零退出码。
        eprintln!("{}", serde_json::to_string_pretty(&report)?);
        return Err(error).context(format!(
            "failed to purge the staged task directory for {failed}; archives are intact and the remaining staged directories can be removed manually"
        ));
    }
    let staged_root = if pruned
        .iter()
        .any(|record| record.staged.as_ref().is_some_and(|p| p.exists()))
    {
        Some(staged_root)
    } else {
        let _ = fs::remove_dir(&staged_root);
        None
    };
    File::open(&backups)?.sync_all()?;
    let remaining = inspect(home, config)?;
    Ok(PruneReport {
        schema: SCHEMA,
        home: home.to_path_buf(),
        purged: purge,
        staged_root,
        job_bytes_moved: pruned
            .iter()
            .fold(0_u64, |sum, record| sum.saturating_add(record.bytes)),
        bundle_bytes: pruned
            .iter()
            .fold(0_u64, |sum, record| sum.saturating_add(record.bundle_bytes)),
        pruned,
        skipped: current.skipped,
        remaining_jobs: remaining.jobs,
        remaining_bytes: remaining.total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::{apply_with, plan};
    use crate::{
        config::{Build, Config},
        model::{Attempt, Job, Phase},
    };
    use anyhow::{Result, bail};
    use std::{fs, path::Path};

    fn write_job(home: &Path, job: &mut Job) -> Result<()> {
        let directory = home.join("jobs").join(job.id.to_string());
        fs::create_dir_all(&directory)?;
        let source = directory.join("source.tar");
        {
            let file = fs::File::create(&source)?;
            let mut builder = tar::Builder::new(file);
            let payload = b"x";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o600);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, "a.txt", &payload[..])?;
            builder.finish()?;
        }
        job.source_sha256 = Some(crate::archive::sha256_file(&source)?);
        fs::write(directory.join("job.json"), serde_json::to_vec_pretty(job)?)?;
        fs::write(directory.join(".revision"), job.revision.to_string())?;
        Ok(())
    }

    fn job() -> Job {
        Job {
            id: uuid::Uuid::new_v4(),
            revision: 1,
            build: Build::default(),
            phase: Phase::Succeeded,
            created_at: 1,
            finished_at: Some(1),
            attempts: vec![Attempt {
                node: "w".into(),
                container: "c".into(),
                started_at: 1,
                outcome: Some("ok".into()),
                cleanup_confirmed: Some(true),
                watchdog_deadline: None,
                cleanup_proof: None,
            }],
            exit_code: Some(0),
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: true,
            queue_deadline: None,
            source_sha256: None,
        }
    }

    #[test]
    fn a_stage_failure_removes_the_untrusted_bundle_and_keeps_the_task_in_place() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("jobs"))?;
        let mut record = job();
        write_job(root.path(), &mut record)?;
        let config = Config::default();
        let plan = plan(root.path(), &config, 1, 0, 10_000)?;
        let mut wrong = plan.candidates[0].clone();
        wrong.finished_at += 1;
        let backups = root.path().join("backups").join("jobs");
        fs::create_dir_all(&backups)?;
        let staged = backups.join("batch");
        fs::create_dir(&staged)?;
        let verify = staged.join("verify");
        fs::create_dir(&verify)?;
        let error = super::stage_one(root.path(), &backups, &staged, &verify, &wrong, u64::MAX)
            .expect_err("finish time must be rechecked after bundling");
        assert!(
            format!("{error:#}").contains("finish time changed"),
            "{error:#}"
        );
        // 任务仍在 jobs/，归档与 staged 目录都已撤销。
        assert!(
            root.path()
                .join("jobs")
                .join(record.id.to_string())
                .is_dir()
        );
        assert!(!staged.join(record.id.to_string()).exists());
        let bundles = fs::read_dir(&backups)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tar"))
            .count();
        assert_eq!(bundles, 0, "失败后不能留下看似完整的归档");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_purge_failure_stops_at_the_first_error_and_keeps_archives() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let first = root.path().join("first");
        let second = root.path().join("second");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;
        fs::write(first.join("job.json"), b"{}")?;
        fs::write(second.join("job.json"), b"{}")?;
        let mut pruned = vec![
            super::Pruned {
                id: uuid::Uuid::new_v4(),
                phase: crate::model::Phase::Succeeded,
                finished_at: 1,
                bytes: 2,
                bundle: first.join("bundle.tar"),
                bundle_bytes: 1,
                bundle_sha256: "0".repeat(64),
                staged: Some(first.clone()),
                purged: false,
            },
            super::Pruned {
                id: uuid::Uuid::new_v4(),
                phase: crate::model::Phase::Succeeded,
                finished_at: 2,
                bytes: 2,
                bundle: second.join("bundle.tar"),
                bundle_bytes: 1,
                bundle_sha256: "1".repeat(64),
                staged: Some(second.clone()),
                purged: false,
            },
        ];
        // 目录只读：其中文件无法删除，remove_dir_all 会失败。
        fs::set_permissions(&first, fs::Permissions::from_mode(0o500))?;
        let failure = super::purge_staged(&mut pruned);
        fs::set_permissions(&first, fs::Permissions::from_mode(0o700))?;
        let (failed, _error) = failure.expect("只读目录必须让 purge 失败");
        assert_eq!(failed, pruned[0].id);
        assert!(!pruned[0].purged);
        assert!(!pruned[1].purged, "第一条失败后不应继续删后面的目录");
        assert!(second.is_dir(), "后续目录必须保留");
        Ok(())
    }

    #[test]
    fn a_late_failure_restores_every_moved_directory_and_drops_partial_bundles() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("jobs"))?;
        let mut first = job();
        let mut second = job();
        write_job(root.path(), &mut first)?;
        write_job(root.path(), &mut second)?;
        let config = Config::default();
        let plan = plan(root.path(), &config, 1, 0, 10_000)?;
        assert_eq!(plan.candidates.len(), 2);
        let mut calls = 0;
        let error = apply_with(
            root.path(),
            &config,
            &plan,
            false,
            |home, backups, staged, verify, candidate, limit| {
                calls += 1;
                if calls == 2 {
                    bail!("injected failure while staging the second task");
                }
                super::stage_one(home, backups, staged, verify, candidate, limit)
            },
        )
        .expect_err("injected failure must abort the batch");
        assert!(
            format!("{error:#}").contains("injected failure"),
            "{error:#}"
        );
        // 两条任务都还在 jobs/，第一条已被移动的目录被移回。
        assert!(root.path().join("jobs").join(first.id.to_string()).is_dir());
        assert!(
            root.path()
                .join("jobs")
                .join(second.id.to_string())
                .is_dir()
        );
        let bundles = fs::read_dir(root.path().join("backups").join("jobs"))?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tar"))
            .count();
        assert_eq!(bundles, 0, "回滚后不应留下「已归档」的假象");
        let staged = fs::read_dir(root.path().join("backups").join("jobs"))?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("pruned-"))
            .count();
        assert_eq!(staged, 0, "回滚后不应留下空的批次目录");
        Ok(())
    }
}
