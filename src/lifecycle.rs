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
    let (code, _, stderr) = transport::capture(node, &script, grace + 60).await?;
    ensure!(
        code == 0,
        "docker stop failed: {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    let after = watchdog::inspect(node, id, container).await?;
    ensure!(
        after != RemoteState::Running,
        "container is still running after the stop request"
    );
    Ok(after)
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
        },
        Ok(RemoteState::Stopped) => StopReport {
            confirmed: true,
            detail: format!("{}; remote container stopped", cause.as_str()),
        },
        Ok(RemoteState::Running) => StopReport {
            confirmed: false,
            detail: format!("{}; remote container is still running", cause.as_str()),
        },
        Err(error) => StopReport {
            confirmed: false,
            detail: format!("{}; remote stop unconfirmed: {error:#}", cause.as_str()),
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
    }

    /// 停止命令超时是「不知道」而不是「停下了」；隔离逻辑依赖这个区分。
    #[test]
    fn a_timed_out_stop_never_confirms_anything() {
        for cause in [StopCause::ClientCancel, StopCause::Deadline] {
            let report = report(cause, Err("SSH command timed out after 80s on live".into()));
            assert!(!report.confirmed, "{cause:?} must stay unconfirmed");
            assert!(report.detail.starts_with(cause.as_str()));
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
