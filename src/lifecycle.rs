//! 取消与执行期限：向远端主动请求停止，并把结果变成可审计的说明。
//!
//! 只杀掉控制面这一侧的 SSH 客户端不等于停止任务：`docker exec` 的目标进程仍在
//! 远端运行，还可能继续写产物、继续占用配额。所以取消和到期都要显式发送停止请求，
//! 并在返回前重新读取容器状态。无法确认时，调用方必须走「中断 + 隔离」路径，
//! 而不是把任务报成已取消或已失败。

use crate::{
    config::Node,
    transport,
    watchdog::{self, RemoteState},
};
use anyhow::{Result, ensure};
use uuid::Uuid;

/// 请求停止时留给远端进程的 SIGTERM 宽限期；到期后 Docker 会 SIGKILL。
pub const STOP_GRACE_SECS: u64 = 20;

/// 停止请求发出后，等待 `docker exec` 客户端退出的上限。
pub const EXEC_DRAIN_SECS: u64 = 30;

/// `docker stop` 返回后等待容器真正退出的上限；只用于吸收正常延迟。
pub const STOP_SETTLE_SECS: u64 = 15;

// 时间窗口必须有界且非零：零会让「等待退出」变成「立刻判定失败」，
// 过大则超出 runner 的兜底预算。编译期检查，避免改常量时静默破坏语义。
const _: () = {
    assert!(STOP_SETTLE_SECS >= 5 && STOP_SETTLE_SECS <= 60);
    assert!(EXEC_DRAIN_SECS > 0 && EXEC_DRAIN_SECS <= 120);
};

/// 触发停止的原因；两者都要求同样的远端动作，只是记录不同。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// 用户通过 API 或 Ctrl-C 请求取消。
    ClientCancel,
    /// 执行期限到达。
    Deadline,
}

impl StopCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientCancel => "client-cancel",
            Self::Deadline => "deadline",
        }
    }
}

/// 可持久化的停止结论；`confirmed` 为假时任务不能进入「已取消/已失败」的干净终态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopReport {
    pub confirmed: bool,
    pub detail: String,
    /// 未确认时的原始失败原因；确认停止或未启动时为空。
    pub reason: Option<String>,
}

/// 按标签确认身份后请求远端停止，再重新读取状态。
///
/// 容器已经 Absent 或 Stopped 时不再发送停止命令：没有进程需要被停止，
/// 而且此时标签校验仍会拒绝把别人的容器当成自己的任务。
pub async fn request_stop(
    node: &Node,
    id: Uuid,
    container: &str,
    grace: u64,
) -> Result<RemoteState> {
    let state = watchdog::inspect(node, id, container).await?;
    if state != RemoteState::Running {
        return Ok(state);
    }
    ensure!(
        grace > 0 && grace <= 300,
        "stop grace must be 1..300 seconds"
    );
    let script = format!(
        "docker stop --time {} {} >/dev/null",
        grace,
        transport::quote(container)
    );
    // `docker stop` 自己最多阻塞 grace 秒，再留出连接与调度的余量。
    //
    // 这条命令是幂等且单调的：容器已经停下时再 stop 一次仍然返回 0，也不会有
    // 任何副作用。因此握手中断（命令根本没跑）可以安全重试 —— 否则一次网络抖动
    // 就会把「明明停下来了」记录成「无法确认」，进而错误隔离 Worker。
    let (code, _, stderr) = transport::idempotent(node, &script, grace + 60).await?;
    ensure!(
        code == 0,
        "docker stop exited {code}: {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    // `docker stop` 返回 0 只代表命令成功，容器可能还需要几秒才真正退出
    // （慢盘、进程回收）。只读一次状态会把这段正常延迟误判成「没停下来」，
    // 进而把一次成功的取消记成中断并隔离 Worker。
    let mut after = watchdog::inspect(node, id, container).await?;
    for _ in 0..STOP_SETTLE_SECS {
        if after != RemoteState::Running {
            return Ok(after);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        after = watchdog::inspect(node, id, container).await?;
    }
    ensure!(
        after != RemoteState::Running,
        "container is still running {}s after the stop request",
        STOP_SETTLE_SECS
    );
    Ok(after)
}

/// 容器还没启动就决定停止；此时没有远端进程需要停，但仍要留下审计记录。
///
/// 取消经常落在「已派发、容器尚未创建」这段窗口里（镜像检查、create、隔离校验）。
/// 这类取消必须和运行中取消一样可审计，否则事后看不出任务为什么没跑。
pub fn describe_pre_start(cause: StopCause, stage: &str) -> StopReport {
    StopReport {
        confirmed: true,
        detail: format!(
            "{cause}; container never started ({stage})",
            cause = cause.as_str()
        ),
        reason: None,
    }
}

/// 把停止请求的结果变成一条可审计的说明；不吞掉失败原因。
///
/// 只有 `Absent` 与 `Stopped` 算确认。`Running` 即使出现在 `Ok` 里也不确认：
/// 那是「读到了状态」，不是「停止成功」，混淆两者会把仍在写产物的任务报成已取消。
pub fn describe(cause: StopCause, result: &Result<RemoteState>) -> StopReport {
    match result {
        Ok(RemoteState::Absent) => StopReport {
            confirmed: true,
            detail: format!("{}; remote container absent", cause.as_str()),
            reason: None,
        },
        Ok(RemoteState::Stopped) => StopReport {
            confirmed: true,
            detail: format!("{}; remote container stopped", cause.as_str()),
            reason: None,
        },
        Ok(RemoteState::Running) => StopReport {
            confirmed: false,
            detail: format!("{}; remote container is still running", cause.as_str()),
            reason: Some("container is still running after the stop request".into()),
        },
        Err(error) => StopReport {
            confirmed: false,
            detail: format!("{}; remote stop unconfirmed: {error:#}", cause.as_str()),
            reason: Some(format!("{error:#}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{StopCause, StopReport, describe};
    use crate::watchdog::RemoteState;

    fn report(cause: StopCause, result: Result<RemoteState, String>) -> StopReport {
        describe(cause, &result.map_err(anyhow::Error::msg))
    }

    #[test]
    fn absent_and_stopped_containers_confirm_the_stop() {
        for (state, expected) in [
            (RemoteState::Absent, "remote container absent"),
            (RemoteState::Stopped, "remote container stopped"),
        ] {
            let report = report(StopCause::ClientCancel, Ok(state));
            assert!(report.confirmed);
            assert_eq!(report.detail, format!("client-cancel; {expected}"));
            assert!(
                report.reason.is_none(),
                "a confirmed stop has nothing to explain"
            );
        }
    }

    /// 仍然在跑就是没停下来；此时不能把任务报成已取消。
    #[test]
    fn a_running_container_is_never_reported_as_stopped() {
        let report = report(StopCause::Deadline, Ok(RemoteState::Running));
        // `request_stop` 本身会拒绝这个结果；这里保证说明层也不会把人骗过去。
        assert!(!report.confirmed);
        assert!(report.detail.contains("deadline"));
        assert!(report.detail.contains("running"));
        assert!(
            report.reason.as_deref().is_some_and(|r| !r.is_empty()),
            "an unconfirmed stop must keep a reason for triage"
        );
    }

    /// 未启动就停止同样是「已确认」，但说明里必须写明发生在哪个阶段。
    #[test]
    fn a_stop_before_container_creation_is_audited_with_its_stage() {
        for stage in ["before create", "before start"] {
            let report = super::describe_pre_start(StopCause::ClientCancel, stage);
            assert!(report.confirmed);
            assert_eq!(
                report.detail,
                format!("client-cancel; container never started ({stage})")
            );
            assert!(report.reason.is_none());
        }
        let report = super::describe_pre_start(StopCause::Deadline, "before create");
        assert!(report.detail.starts_with("deadline;"));
    }

    /// 停止命令超时是「不知道」而不是「停下了」；隔离逻辑依赖这个区分。
    #[test]
    fn a_timed_out_stop_never_confirms_anything() {
        for cause in [StopCause::ClientCancel, StopCause::Deadline] {
            let report = report(cause, Err("SSH command timed out after 80s on live".into()));
            assert!(!report.confirmed, "{cause:?} must stay unconfirmed");
            assert!(report.detail.starts_with(cause.as_str()));
            assert_eq!(
                report.reason.as_deref(),
                Some("SSH command timed out after 80s on live")
            );
        }
    }

    /// SSH 失败时把真实原因写进说明，而不是只写一句「取消失败」。
    #[test]
    fn an_unreachable_worker_keeps_the_reason_and_stays_unconfirmed() {
        let report = report(
            StopCause::Deadline,
            Err("SSH command timed out after 80s on live".into()),
        );
        assert!(!report.confirmed);
        assert!(
            report
                .detail
                .starts_with("deadline; remote stop unconfirmed: ")
        );
        assert!(report.detail.contains("timed out after 80s on live"));
    }
}
