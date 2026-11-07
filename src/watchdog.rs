//! 远端看门狗证据：容器自带的有界寿命，以及远程容器状态。
//!
//! SSH 掉线时无法证明旧容器已经停止，因此控制面不允许换机重跑。唯一不依赖
//! SSH 的终止证据是容器入口本身：`docker create ... -c 'sleep timeout+lease'`
//! 让 PID1 有确定寿命，PID1 退出后容器必然停止，执行中的 `docker exec` 也随之被杀。
//! 这里只按时间与状态做判定，不猜测进程、不忽略标签校验。
use crate::{config::Node, model::Attempt, transport};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use uuid::Uuid;

/// PID1 `sleep` 结束后容器停止；该值必须与 `runner` 创建容器时使用的一致。
pub const LEASE_GRACE_SECS: u64 = 180;

/// 远端容器当前状态；只有 Absent 与 Stopped 能证明没有进程可以继续提交结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteState {
    Absent,
    Stopped,
    Running,
}

/// 终止证据来源，随任务记录一起持久化，便于事后审计。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Proof {
    /// 容器已不存在（从未创建成功或已删除）。
    RemoteAbsent,
    /// 容器存在但未运行，`--restart=no` 保证它不会自行恢复执行。
    RemoteStopped,
    /// SSH 不可达，但看门狗租约已过期，PID1 不可能仍在睡眠。
    LeaseExpired,
}

impl Proof {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RemoteAbsent => "remote-absent",
            Self::RemoteStopped => "remote-stopped",
            Self::LeaseExpired => "watchdog-lease-expired",
        }
    }
}

/// 单个 attempt 的判定结果；未证明时给出原因，证明时给出可审计的来源。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub proven: bool,
    pub proof: Option<Proof>,
    pub detail: String,
}

fn pending(detail: impl Into<String>) -> Decision {
    Decision {
        proven: false,
        proof: None,
        detail: detail.into(),
    }
}

fn proven(proof: Proof) -> Decision {
    Decision {
        proven: true,
        proof: Some(proof),
        detail: proof.as_str().into(),
    }
}

/// 判定一个尚未确认清理的 attempt 是否已经有终止证据。
///
/// `remote` 是探测结果或探测失败原因；`at` 是控制面当前时间；`skew` 是允许的
/// 节点与控制面时钟偏差。租约判定必须加上偏差上界，否则会过早放行。
pub fn decide(
    attempt: &Attempt,
    remote: Result<RemoteState, String>,
    at: u64,
    skew: u64,
) -> Decision {
    match remote {
        Ok(RemoteState::Absent) => proven(Proof::RemoteAbsent),
        Ok(RemoteState::Stopped) => proven(Proof::RemoteStopped),
        Ok(RemoteState::Running) => {
            pending("container is still running; wait for the remote watchdog lease")
        }
        Err(error) => {
            let Some(deadline) = attempt.watchdog_deadline else {
                // 旧记录没有租约，不能因为探测失败就假定旧容器已停止。
                return pending(format!(
                    "remote state unknown ({error}) and no watchdog lease was recorded"
                ));
            };
            let release = deadline.saturating_add(skew);
            if at >= release {
                proven(Proof::LeaseExpired)
            } else {
                pending(format!(
                    "remote state unknown ({error}); watchdog lease releases in {}s",
                    release - at
                ))
            }
        }
    }
}

/// 读取容器标签与运行状态；标签不匹配时拒绝把容器当成自己的任务。
pub async fn inspect(node: &Node, id: Uuid, container: &str) -> Result<RemoteState> {
    let format = transport::quote("{{index .Config.Labels \"io.sshpool.job\"}}|{{.State.Running}}");
    let script = format!(
        "docker inspect --format {} {}",
        format,
        transport::quote(container)
    );
    // 只读核对：连接层握手失败可以重试，但「容器不存在」是命令的真实结论，
    // 必须原样返回 Absent，不能被重试逻辑吞掉或改写成错误。
    let stdout = match transport::verified(node, &script, 20).await {
        Ok(stdout) => stdout,
        Err(error) => {
            let message = format!("{error:#}").to_lowercase();
            if message.contains("no such object") || message.contains("no such container") {
                return Ok(RemoteState::Absent);
            }
            bail!("cannot confirm container identity: {}", message.trim());
        }
    };
    let value = String::from_utf8_lossy(&stdout);
    let (label, running) = value
        .trim()
        .split_once('|')
        .context("unexpected docker inspect output")?;
    ensure!(
        label == id.to_string(),
        "container label mismatch; refusing to treat it as this job"
    );
    Ok(if running.trim() == "true" {
        RemoteState::Running
    } else {
        RemoteState::Stopped
    })
}

/// 证明终止后清理容器；清理失败不影响已经成立的终止证据。
pub async fn remove_after_proof(node: &Node, id: Uuid, container: &str) -> Result<()> {
    ensure!(
        inspect(node, id, container).await? != RemoteState::Running,
        "refusing to remove a running container"
    );
    // 标签校验与删除放在同一个远端 shell 里：删除前重新读一次标签，
    // 避免 inspect 与 rm 之间被同名容器替换。
    let script = format!(
        "label=$(docker inspect --format {} {}) || exit 3
[ \"$label\" = {} ] || exit 4
docker rm -f {} >/dev/null",
        transport::quote("{{index .Config.Labels \"io.sshpool.job\"}}"),
        transport::quote(container),
        transport::quote(&id.to_string()),
        transport::quote(container)
    );
    // 同一条脚本里已经重新校验过标签，重复执行只会得到一个「已经不存在」的结论，
    // 因此连接层抖动可以安全重试。
    let (code, _, stderr) = transport::idempotent(node, &script, 30).await?;
    match code {
        0 => Ok(()),
        3 => Ok(()), // 容器在证明之后消失：同样没有进程可以继续提交结果。
        4 => bail!("container label mismatch during removal; refusing to delete it"),
        _ => bail!(
            "container removal failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        ),
    }
}

/// 容器实际启动时刻；租约必须从这里起算，而不是从控制面分配任务的时刻。
pub async fn started_at(node: &Node, container: &str) -> Result<u64> {
    let script = format!(
        "docker inspect --format {} {}",
        transport::quote("{{.State.StartedAt}}"),
        transport::quote(container)
    );
    let stdout = match transport::verified(node, &script, 20).await {
        Ok(stdout) => stdout,
        Err(error) => bail!("cannot read container start time: {error:#}"),
    };
    parse_docker_time(String::from_utf8_lossy(&stdout).trim())
}

/// 解析 Docker 的 `2026-11-07T06:12:33.123456789Z`；只接受 UTC 零时区格式。
pub fn parse_docker_time(value: &str) -> Result<u64> {
    let bytes = value.as_bytes();
    ensure!(
        bytes.len() >= 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && value.ends_with('Z'),
        "unsupported container timestamp: {value}"
    );
    let number = |range: std::ops::Range<usize>| -> Result<i64> {
        let text = &value[range];
        ensure!(
            text.bytes().all(|byte| byte.is_ascii_digit()),
            "unsupported container timestamp: {value}"
        );
        text.parse::<i64>()
            .with_context(|| format!("invalid container timestamp {value}"))
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    ensure!(
        (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60,
        "container timestamp out of range: {value}"
    );
    let days = days_from_civil(year, month, day);
    ensure!(days >= 0, "container timestamp predates the epoch: {value}");
    Ok(days as u64 * 86_400 + (hour * 3_600 + minute * 60 + second) as u64)
}

/// Howard Hinnant 的 civil-from-days 逆运算；避免为一个时间戳引入额外依赖。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::{Decision, Proof, RemoteState, days_from_civil, decide, parse_docker_time};
    use crate::model::Attempt;

    fn attempt(deadline: Option<u64>) -> Attempt {
        Attempt {
            node: "worker".into(),
            container: "sshpool-job-1".into(),
            started_at: 100,
            outcome: Some("SSH connection interrupted".into()),
            cleanup_confirmed: Some(false),
            cleanup_proof: None,
            finished_at: None,
            schedule: None,
            watchdog_deadline: deadline,
        }
    }

    fn assert_decision(decision: Decision, proven: bool, proof: Option<Proof>) {
        assert_eq!(decision.proven, proven, "{}", decision.detail);
        assert_eq!(decision.proof, proof, "{}", decision.detail);
    }

    #[test]
    fn remote_absence_and_stop_are_direct_proof() {
        assert_decision(
            decide(&attempt(None), Ok(RemoteState::Absent), 0, 0),
            true,
            Some(Proof::RemoteAbsent),
        );
        assert_decision(
            decide(&attempt(None), Ok(RemoteState::Stopped), 0, 0),
            true,
            Some(Proof::RemoteStopped),
        );
        assert_decision(
            decide(&attempt(None), Ok(RemoteState::Running), u64::MAX, 0),
            false,
            None,
        );
    }

    #[test]
    fn unreachable_remote_waits_for_the_recorded_lease() {
        let error = || Err("ssh timeout".to_string());
        assert_decision(decide(&attempt(Some(1_000)), error(), 999, 0), false, None);
        assert_decision(
            decide(&attempt(Some(1_000)), error(), 1_000, 0),
            true,
            Some(Proof::LeaseExpired),
        );
        // 节点时钟可能快于控制面，偏差上界必须推迟放行。
        assert_decision(
            decide(&attempt(Some(1_000)), error(), 1_050, 120),
            false,
            None,
        );
        assert_decision(
            decide(&attempt(Some(1_000)), error(), 1_120, 120),
            true,
            Some(Proof::LeaseExpired),
        );
    }

    #[test]
    fn legacy_attempt_without_a_lease_never_gets_a_watchdog_proof() {
        assert_decision(
            decide(&attempt(None), Err("ssh timeout".to_string()), u64::MAX, 0),
            false,
            None,
        );
    }

    #[test]
    fn docker_timestamps_are_read_as_utc_seconds() {
        assert_eq!(
            parse_docker_time("2026-11-07T06:12:33.123456789Z").unwrap(),
            1_794_031_953
        );
        assert_eq!(parse_docker_time("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_docker_time("2024-02-29T23:59:59.9Z").unwrap(),
            1_709_251_199
        );
        for rejected in [
            "2026-11-07 06:12:33",
            "2026-13-07T06:12:33Z",
            "2026-11-07T24:12:33Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert!(parse_docker_time(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn civil_days_match_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }
}
