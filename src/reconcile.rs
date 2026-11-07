//! 在线核对「清理未确认」的 Worker，并用远端看门狗证据解除隔离。
//!
//! 隔离的本意是避免两个执行者同时提交结果；它不应该要求重启整个控制面。
//! 本模块只依据可复现的证据放行：容器不存在、容器已停止，或容器租约已过期且
//! SSH 仍然不可达。任何一条都意味着没有进程还能继续产出结果。
use crate::{
    model::{Job, Phase, now},
    state::State,
    watchdog,
};
use anyhow::Result;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// 允许的节点与控制面时钟偏差上界；租约判定必须扣除这段余量。
pub const LEASE_CLOCK_SKEW_SECS: u64 = 60;

/// 单个 attempt 的核对结果；`detail` 直接展示给运维。
#[derive(Clone, Debug, Serialize)]
pub struct AttemptReport {
    pub job: Uuid,
    pub node: String,
    pub container: String,
    pub phase: Phase,
    pub proven: bool,
    pub proof: Option<String>,
    pub detail: String,
}

/// 一次核对的结果；按节点汇总，便于只看被隔离的 Worker。
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub checked: usize,
    pub proven: usize,
    /// 已恢复自动重跑的任务；它们被重新排队，不代表已经成功。
    pub resumed: Vec<Uuid>,
    /// 证据成立但容器删除失败的节点；租约证据仍然有效。
    pub cleanup_errors: Vec<String>,
    pub attempts: Vec<AttemptReport>,
}

/// 只有幂等、禁网且仍有重试额度的任务，才能在证明旧容器终止后自动重跑。
pub fn resume_allowed(job: &Job) -> bool {
    job.phase == Phase::Interrupted
        && job.cleanup_confirmed
        && job.build.retries > 0
        && job.build.idempotent
        && !job.build.network
        && job.attempts.len() <= job.build.retries
        && !job.cancel_requested
        && job
            .attempts
            .iter()
            .all(|attempt| attempt.cleanup_confirmed == Some(true))
}

/// 核对所有（或指定）节点的未确认清理；不改动没有争议的任务。
pub async fn reconcile(state: &Arc<State>, only: Option<&str>) -> Result<Report> {
    // 与任务领取共用调度锁，避免在核对期间有任务被派到正在检查的节点上。
    let _scheduling = state.scheduling.lock().await;
    let nodes = state.nodes().await;
    let jobs = state
        .jobs
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut report = Report {
        checked: 0,
        proven: 0,
        resumed: Vec::new(),
        cleanup_errors: Vec::new(),
        attempts: Vec::new(),
    };
    for job in jobs {
        // 仍在 Running 的任务由执行者自己负责清理：此时容器可能刚创建、也可能正在运行，
        // 对外部核对来说既不是「遗留」也没有「未确认的终止」。把这类 attempt 当待核对
        // 会在容器尚未创建时读出 absent，从而写入一条假的「已证明清理」记录。
        if job.phase == Phase::Running {
            continue;
        }
        let pending = job
            .attempts
            .iter()
            .enumerate()
            .filter(|(_, attempt)| {
                attempt.cleanup_confirmed != Some(true)
                    && only.is_none_or(|name| attempt.node == name)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if pending.is_empty() {
            continue;
        }
        let mut candidate = job.clone();
        let mut changed = false;
        for index in pending {
            let attempt = candidate.attempts[index].clone();
            report.checked += 1;
            let node = match nodes.iter().find(|node| node.name == attempt.node) {
                Some(node) => node.clone(),
                None => {
                    report.attempts.push(AttemptReport {
                        job: job.id,
                        node: attempt.node.clone(),
                        container: attempt.container.clone(),
                        phase: job.phase.clone(),
                        proven: false,
                        proof: None,
                        detail:
                            "worker removed from configuration; its containers cannot be proven"
                                .into(),
                    });
                    continue;
                }
            };
            let remote = watchdog::inspect(&node, job.id, &attempt.container)
                .await
                .map_err(|error| format!("{error:#}"));
            let decision = watchdog::decide(&attempt, remote.clone(), now(), LEASE_CLOCK_SKEW_SECS);
            if decision.proven {
                // 证据成立后再尽力删除；删除失败不推翻容器已经停止的结论。
                // 只有「容器存在但已停止」才值得再删一次；SSH 不可达时删除必然失败。
                if matches!(remote, Ok(watchdog::RemoteState::Stopped))
                    && let Err(error) =
                        watchdog::remove_after_proof(&node, job.id, &attempt.container).await
                {
                    report
                        .cleanup_errors
                        .push(format!("{}: {error:#}", attempt.node));
                }
                candidate.attempts[index].cleanup_confirmed = Some(true);
                candidate.attempts[index].cleanup_proof =
                    decision.proof.map(|proof| proof.as_str().to_string());
                changed = true;
                report.proven += 1;
            }
            report.attempts.push(AttemptReport {
                job: job.id,
                node: attempt.node.clone(),
                container: attempt.container.clone(),
                phase: job.phase.clone(),
                proven: decision.proven,
                proof: decision.proof.map(|proof| proof.as_str().to_string()),
                detail: decision.detail,
            });
        }
        if !changed {
            continue;
        }
        candidate.cleanup_confirmed = candidate
            .attempts
            .iter()
            .all(|attempt| attempt.cleanup_confirmed == Some(true));
        let transition = state.transitions.lock().await;
        let (published, _) = state.checkpoint_candidate_locked(candidate).await?;
        drop(transition);
        state
            .event(
                job.id,
                "cleanup_reconcile",
                if published.cleanup_confirmed {
                    "all attempts proven terminated"
                } else {
                    "some attempts still unproven"
                },
            )
            .await?;
        if !resume_allowed(&published) {
            continue;
        }
        let Ok(permit) = state.uploads.clone().try_acquire_owned() else {
            state
                .event(
                    job.id,
                    "resume_skipped",
                    "no active-job capacity; cleanup proof retained",
                )
                .await?;
            continue;
        };
        let mut resumed = published.clone();
        resumed.phase = Phase::Queued;
        resumed.finished_at = None;
        resumed.exit_code = None;
        resumed.message = Some(format!(
            "resumed after remote watchdog proof ({} attempt(s) proven)",
            resumed
                .attempts
                .iter()
                .filter(|attempt| attempt.cleanup_confirmed == Some(true))
                .count()
        ));
        let transition = state.transitions.lock().await;
        let (resumed, _) = match state.checkpoint_candidate_locked(resumed).await {
            Ok(value) => value,
            Err(error) => {
                drop(transition);
                return Err(error.context("cannot publish resumed job"));
            }
        };
        drop(transition);
        state
            .event(
                job.id,
                "resumed",
                "cleanup proven; retrying on another worker",
            )
            .await?;
        report.resumed.push(resumed.id);
        crate::runner::spawn_job(state.clone(), resumed.id, permit);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::resume_allowed;
    use crate::{
        config::Build,
        model::{Attempt, Job, Phase},
    };

    fn attempt(node: &str, confirmed: Option<bool>) -> Attempt {
        Attempt {
            node: node.into(),
            container: format!("sshpool-{node}-1"),
            started_at: 0,
            outcome: Some("SSH connection interrupted".into()),
            cleanup_confirmed: confirmed,
            watchdog_deadline: Some(1_000),
            cleanup_proof: confirmed
                .filter(|confirmed| *confirmed)
                .map(|_| "watchdog-lease-expired".to_string()),
        }
    }

    fn job(phase: Phase, build: Build, attempts: Vec<Attempt>, confirmed: bool) -> Job {
        Job {
            id: uuid::Uuid::new_v4(),
            revision: 1,
            build,
            phase,
            created_at: 0,
            finished_at: Some(1),
            attempts,
            exit_code: None,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: confirmed,
            queue_deadline: None,
            source_sha256: None,
            owner: None,
        }
    }

    #[test]
    fn resume_needs_a_complete_proof_and_retry_budget() {
        let build = Build {
            retries: 1,
            idempotent: true,
            network: false,
            ..Build::default()
        };
        let proven = job(
            Phase::Interrupted,
            build.clone(),
            vec![attempt("first", Some(true))],
            true,
        );
        assert!(resume_allowed(&proven));
        // 清理未确认不能重跑。
        assert!(!resume_allowed(&job(
            Phase::Interrupted,
            build.clone(),
            vec![attempt("first", Some(false))],
            false,
        )));
        // 尚未证明的 attempt 也不能被部分放行。
        assert!(!resume_allowed(&job(
            Phase::Interrupted,
            build.clone(),
            vec![attempt("first", Some(true)), attempt("second", None)],
            false,
        )));
        // 已运行两次、只剩一次额度时不能再重试。
        assert!(!resume_allowed(&job(
            Phase::Interrupted,
            build.clone(),
            vec![attempt("first", Some(true)), attempt("second", Some(true))],
            true,
        )));
        // 非幂等、联网任务与用户取消都不自动重跑。
        assert!(!resume_allowed(&job(
            Phase::Interrupted,
            Build {
                idempotent: false,
                ..build.clone()
            },
            vec![attempt("first", Some(true))],
            true,
        )));
        assert!(!resume_allowed(&job(
            Phase::Interrupted,
            Build {
                network: true,
                ..build.clone()
            },
            vec![attempt("first", Some(true))],
            true,
        )));
        let mut cancelled = job(
            Phase::Interrupted,
            build.clone(),
            vec![attempt("first", Some(true))],
            true,
        );
        cancelled.cancel_requested = true;
        assert!(!resume_allowed(&cancelled));
        // 真正失败的终态不会被重放。
        assert!(!resume_allowed(&job(
            Phase::Failed,
            build,
            vec![attempt("first", Some(true))],
            true,
        )));
    }
}
