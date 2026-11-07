//! 外部观测：把控制面已有的结构化事实渲染成 Prometheus 文本格式。
//!
//! 这里**只读已经记录的数据**：任务记录的 `phase` / `exit_code` / 时间戳 / 尝试次数，
//! 节点探测得到的资源水位，以及访问审计各代的字节数。没有新增埋点，也没有文案猜测：
//! 失败分类只看「有没有退出码、退出码是不是 0」。具体失败原因仍在 `job.message`
//! 与各任务的 `events.jsonl` 里，由部署者选择的日志后端消费。
//!
//! 指标走独立的 `metrics_listen`，不挂在控制面的 `/v1/...` 上：Prometheus 默认 15 秒
//! 抓一次，若走控制面路由，光是抓取就会在几分钟内把有界的访问审计冲掉。抓取必须带
//! **根 token**（短期凭据不行），配置了 TLS 时该端口同样走 TLS；暴露的仍只有节点名
//! 与数值 —— 不含 SSH 目标、token、任务消息或任何自由文本。
use crate::{
    config::Node,
    model::{Health, Job, Phase},
    state::State,
};
use std::{fmt::Write, path::Path, sync::Arc, time::Duration};

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// 鉴权失败与错误响应的类型；不声明版本号，免得被当成 exposition 解析。
const PLAIN: &str = "text/plain; charset=utf-8";

/// 排队与执行时长的上界；最后再加 `+Inf`，这是直方图的硬要求。
const SECONDS: [u64; 6] = [5, 30, 120, 600, 1_800, 7_200];

/// 所有结果分类。顺序固定，渲染时的桶与计数共用同一份。
const CLASSES: [&str; 6] = [
    "succeeded",
    "failed-before-exit",
    "failed-exit-nonzero",
    "failed-after-exit",
    "cancelled",
    "interrupted",
];

/// 一次渲染所需的全部输入；纯函数便于用构造数据验证格式与分类。
pub struct Snapshot<'a> {
    pub jobs: &'a [Job],
    pub health: &'a [Health],
    pub nodes: &'a [Node],
    pub now: u64,
    /// 访问审计文件的 `(代次, 字节数)`；不存在的一代不出现。
    pub access: &'a [(usize, u64)],
}

/// 失败分类只看结构化字段，因此改了提示文案也不会改变含义。
///
/// - `failed-before-exit`：容器没给出退出码（调度、SSH、启动或超时未确认）
/// - `failed-exit-nonzero`：容器跑完但退出码非零
/// - `failed-after-exit`：容器以 0 退出，失败发生在之后（产物、清理、复制）
pub fn result(job: &Job) -> &'static str {
    match job.phase {
        Phase::Queued | Phase::Running => "active",
        Phase::Succeeded => "succeeded",
        Phase::Cancelled => "cancelled",
        Phase::Interrupted => "interrupted",
        Phase::Failed => match job.exit_code {
            Some(0) => "failed-after-exit",
            Some(_) => "failed-exit-nonzero",
            None => "failed-before-exit",
        },
    }
}

struct Histogram {
    /// 每个分类在每条边界以下的样本数（累计）。
    buckets: [Vec<u64>; 6],
    sum: [u64; 6],
    count: [u64; 6],
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| vec![0; SECONDS.len()]),
            sum: [0; 6],
            count: [0; 6],
        }
    }

    fn observe(&mut self, class: &str, seconds: u64) {
        let Some(index) = class_index(class) else {
            return;
        };
        for (bucket, boundary) in SECONDS.iter().enumerate() {
            if seconds <= *boundary {
                self.buckets[index][bucket] += 1;
            }
        }
        self.sum[index] += seconds;
        self.count[index] += 1;
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
        for (index, class) in CLASSES.iter().enumerate() {
            for (bucket, boundary) in SECONDS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{name}_bucket{{result=\"{class}\",le=\"{boundary}\"}} {}",
                    self.buckets[index][bucket]
                );
            }
            let _ = writeln!(
                out,
                "{name}_bucket{{result=\"{class}\",le=\"+Inf\"}} {}",
                self.count[index]
            );
            let _ = writeln!(out, "{name}_sum{{result=\"{class}\"}} {}", self.sum[index]);
            let _ = writeln!(
                out,
                "{name}_count{{result=\"{class}\"}} {}",
                self.count[index]
            );
        }
    }
}

pub fn render(snapshot: &Snapshot<'_>) -> String {
    let mut out = String::new();
    let mut by_class = std::collections::BTreeMap::new();
    let mut attempts = 0_u64;
    let mut retries = 0_u64;
    let mut active = 0_u64;
    let mut queued = 0_u64;
    let mut unconfirmed = 0_u64;
    let mut oldest_queued = 0_u64;
    let mut queue = Histogram::new();
    let mut duration = Histogram::new();

    for job in snapshot.jobs {
        let class = result(job);
        *by_class.entry(class).or_insert(0_u64) += 1;
        attempts += job.attempts.len() as u64;
        retries += job.attempts.len().saturating_sub(1) as u64;
        if !job.cleanup_confirmed {
            unconfirmed += 1;
        }
        match job.phase {
            Phase::Queued => {
                queued += 1;
                oldest_queued = oldest_queued.max(snapshot.now.saturating_sub(job.created_at));
            }
            Phase::Running => active += 1,
            _ => {}
        }
        // 排队时间 = 第一次被领取的时刻 - 提交时刻；从未领取就不存在这个事实。
        if let Some(first) = job.attempts.first() {
            queue.observe(class, first.started_at.saturating_sub(job.created_at));
        }
        // 执行时间 = 终态时刻 - 最后一次领取时刻（含清理，按事实记录，不猜）。
        if job.phase.terminal()
            && let (Some(finished), Some(last)) = (job.finished_at, job.attempts.last())
        {
            duration.observe(class, finished.saturating_sub(last.started_at));
        }
    }

    let _ = writeln!(
        out,
        "# HELP sshpool_jobs 终态任务数，按结构化失败分类；进行中的任务不计入\n# TYPE sshpool_jobs gauge"
    );
    for class in CLASSES {
        let _ = writeln!(
            out,
            "sshpool_jobs{{result=\"{class}\"}} {}",
            by_class.get(class).copied().unwrap_or(0)
        );
    }
    let _ = writeln!(
        out,
        "# HELP sshpool_job_attempts_total 所有已记录任务的尝试次数之和\n# TYPE sshpool_job_attempts_total counter\nsshpool_job_attempts_total {attempts}"
    );
    let _ = writeln!(
        out,
        "# HELP sshpool_job_retries_total 除首次之外的重试次数\n# TYPE sshpool_job_retries_total counter\nsshpool_job_retries_total {retries}"
    );
    let _ = writeln!(
        out,
        "# HELP sshpool_active_jobs 已领取且未结束的任务\n# TYPE sshpool_active_jobs gauge\nsshpool_active_jobs {active}"
    );
    let _ = writeln!(
        out,
        "# HELP sshpool_queued_jobs 等待领取的任务\n# TYPE sshpool_queued_jobs gauge\nsshpool_queued_jobs {queued}"
    );
    let _ = writeln!(
        out,
        "# HELP sshpool_queued_oldest_seconds 最老排队任务已等待的秒数\n# TYPE sshpool_queued_oldest_seconds gauge\nsshpool_queued_oldest_seconds {oldest_queued}"
    );
    let _ = writeln!(
        out,
        "# HELP sshpool_jobs_cleanup_unconfirmed 尚未确认远端清理的任务数\n# TYPE sshpool_jobs_cleanup_unconfirmed gauge\nsshpool_jobs_cleanup_unconfirmed {unconfirmed}"
    );

    queue.render(
        &mut out,
        "sshpool_job_queue_seconds",
        "从提交到第一次被领取的秒数",
    );
    duration.render(
        &mut out,
        "sshpool_job_duration_seconds",
        "从最后一次领取到终态的秒数（含远端清理）",
    );

    let _ = writeln!(
        out,
        "# HELP sshpool_node_ready 节点探测成功且处于接单状态\n# TYPE sshpool_node_ready gauge\n\
         # HELP sshpool_node_cpus 节点可用 CPU\n# TYPE sshpool_node_cpus gauge\n\
         # HELP sshpool_node_memory_available_mib 节点可用内存（MiB）\n# TYPE sshpool_node_memory_available_mib gauge\n\
         # HELP sshpool_node_disk_available_mib 容器运行时所在文件系统的可用磁盘（MiB）\n# TYPE sshpool_node_disk_available_mib gauge\n\
         # HELP sshpool_node_load 节点一分钟负载\n# TYPE sshpool_node_load gauge\n\
         # HELP sshpool_node_reserve_memory_mib 调度为宿主业务预留的内存（MiB）\n# TYPE sshpool_node_reserve_memory_mib gauge"
    );
    for (node, health) in snapshot.nodes.iter().zip(snapshot.health) {
        let name = escape(&node.name);
        // Prometheus 的样本值只接受数字：`true` 会让整份 exposition 被解析器拒绝。
        let ready = u8::from(health.error.is_none() && health.enabled);
        let _ = writeln!(out, "sshpool_node_ready{{node=\"{name}\"}} {ready}");
        // 探测失败时资源数字没有意义：报 0，而不是把旧快照当成当前水位。
        let (cpus, memory, disk, load) = match health.error {
            Some(_) => (0, 0, 0, 0.0),
            None => (
                health.cpus,
                health.memory_available_mib,
                health.disk_available_mib,
                health.load,
            ),
        };
        let _ = writeln!(out, "sshpool_node_cpus{{node=\"{name}\"}} {cpus}");
        let _ = writeln!(
            out,
            "sshpool_node_memory_available_mib{{node=\"{name}\"}} {memory}"
        );
        let _ = writeln!(
            out,
            "sshpool_node_disk_available_mib{{node=\"{name}\"}} {disk}"
        );
        let _ = writeln!(out, "sshpool_node_load{{node=\"{name}\"}} {load}");
        let _ = writeln!(
            out,
            "sshpool_node_reserve_memory_mib{{node=\"{name}\"}} {}",
            node.reserve_memory_mib
        );
    }

    let _ = writeln!(
        out,
        "# HELP sshpool_access_log_bytes 访问审计文件字节数，按代次\n# TYPE sshpool_access_log_bytes gauge"
    );
    for (generation, bytes) in snapshot.access {
        let _ = writeln!(
            out,
            "sshpool_access_log_bytes{{generation=\"{generation}\"}} {bytes}"
        );
    }
    out
}

fn class_index(class: &str) -> Option<usize> {
    CLASSES.iter().position(|known| *known == class)
}

/// Prometheus 标签值转义：反斜杠、双引号与换行。
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// 单次抓取的读超时：抓取端沉默或半开连接不该拖住下一次抓取。
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 同时进行中的抓取连接上限；超过就直接关闭，而不是排队到内存里。
const MAX_CONNECTIONS: usize = 32;
/// 请求行加头部的硬上限；超过就当作坏请求，不继续读。
const MAX_REQUEST_BYTES: usize = 8192;

/// 极简抓取服务：只接受带根 token 的 `GET /metrics` 与 `GET /`。
///
/// 抓取**不写访问审计**（Prometheus 15 秒一次会把有界日志冲掉），但也绝不留匿名入口：
/// 指标里有节点名与资源水位，谁能连上端口就等于能看到集群拓扑。这里只认根 token，
/// 短期凭据即使带 `read` 也不能抓 —— 指标是运维面，不是借出去的工作台接口。
///
/// 每条连接在独立任务里完成，并带读超时与连接上限。配置了 TLS 时该端口同样走 TLS
/// （与控制面共用同一份证书），因此根 token 不会以明文跨网络。
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<State>,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<()> {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (socket, address) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Some(config) = tls else {
                handle(socket, &state).await;
                return;
            };
            // 握手在独立任务里做并带时限：只连不说的客户端占不到 `accept()` 循环。
            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            match tokio::time::timeout(crate::tls::HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await
            {
                Ok(Ok(stream)) => handle(stream, &state).await,
                Ok(Err(error)) => {
                    eprintln!("sshpool: metrics TLS handshake from {address} failed: {error}")
                }
                Err(_) => eprintln!("sshpool: metrics TLS handshake from {address} timed out"),
            }
        });
    }
}

/// 抓取请求在鉴权后的去向：要么直接回固定响应，要么渲染指标。
enum Decision {
    Respond(Response),
    Render,
}

/// 一条连接的完整生命周期；TLS 与明文共用，因此对具体流类型没有要求。
async fn handle<S>(mut socket: S, state: &State)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        loop {
            let read = socket.read(&mut chunk).await?;
            if read == 0 {
                return Ok::<_, std::io::Error>(());
            }
            request.extend_from_slice(&chunk[..read]);
            // 请求行 + 头足够判断路径与凭据；不解析正文，也不接受正文。
            if request.windows(4).any(|window| window == b"\r\n\r\n")
                || request.len() > MAX_REQUEST_BYTES
            {
                return Ok(());
            }
        }
    })
    .await;

    let response = match read {
        Ok(Ok(())) => match decide(&request, state) {
            Decision::Respond(response) => response,
            Decision::Render => Response::new(200, render_state(state).await, CONTENT_TYPE),
        },
        // 读超时与读错误都不该产生日志噪声：抓取端行为，不是控制面状态。
        _ => Response::new(408, "request timeout", PLAIN),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
        response.extra
    );
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(response.body.as_bytes()).await;
    let _ = socket.flush().await;
}

/// 响应体只有固定字面量：不回显路径、token 或任何请求内容。
struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
    /// 额外的响应头（自带结尾 CRLF），401 用它声明 `WWW-Authenticate`。
    extra: &'static str,
}

impl Response {
    fn new(status: u16, body: impl Into<String>, content_type: &'static str) -> Self {
        Self {
            status,
            reason: match status {
                200 => "OK",
                401 => "Unauthorized",
                404 => "Not Found",
                405 => "Method Not Allowed",
                _ => "Request Timeout",
            },
            content_type,
            body: body.into(),
            extra: "",
        }
    }

    fn unauthorized() -> Self {
        Self {
            extra: "www-authenticate: Bearer\r\n",
            ..Self::new(401, "unauthorized", PLAIN)
        }
    }
}

fn decide(request: &[u8], state: &State) -> Decision {
    let text = String::from_utf8_lossy(request);
    // 只接受 GET：其他方法一律 405，而不是把 POST 也当成一次抓取。
    if text.split_whitespace().next() != Some("GET") {
        return Decision::Respond(Response::new(405, "method not allowed", PLAIN));
    }
    // 先鉴权再看路径：未认证时连「哪些路径存在」都不暴露。
    if !authorized(&text, state) {
        return Decision::Respond(Response::unauthorized());
    }
    let path = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    if matches!(path, "/" | "/metrics") {
        Decision::Render
    } else {
        Decision::Respond(Response::new(404, "not found", PLAIN))
    }
}

/// 头部名大小写不敏感；只接受整行 `Bearer <根 token>`，与 API 共用恒时比较。
fn authorized(text: &str, state: &State) -> bool {
    let actual = text
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .unwrap_or("");
    !actual.is_empty() && crate::token::same(actual, &format!("Bearer {}", state.token))
}

/// 从共享状态取一份一致性快照：任务记录加当前健康快照。
///
/// 不触发远端探测：抓取是高频操作，让它打 SSH 会把观测变成负载。
async fn render_state(state: &State) -> String {
    let nodes = state.nodes().await;
    let jobs = state
        .jobs
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let health = state.health_snapshot(&nodes).await;
    let access = self::access_sizes(&state.home);
    render(&Snapshot {
        jobs: &jobs,
        health: &health,
        nodes: &nodes,
        now: crate::model::now(),
        access: &access,
    })
}

/// 读取访问审计各代的字节数；读不到就当这一代不存在，抓取不因审计目录异常而失败。
pub fn access_sizes(home: &Path) -> Vec<(usize, u64)> {
    (0..crate::access::GENERATIONS)
        .filter_map(|generation| {
            let path = if generation == 0 {
                crate::access::path(home)
            } else {
                std::path::PathBuf::from(format!(
                    "{}.{generation}",
                    crate::access::path(home).display()
                ))
            };
            std::fs::metadata(path)
                .ok()
                .map(|metadata| (generation, metadata.len()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Build,
        model::{Attempt, Job, Phase},
    };

    fn job(phase: Phase, code: Option<i32>, started: u64, finished: Option<u64>) -> Job {
        Job {
            id: uuid::Uuid::new_v4(),
            revision: 0,
            build: Build::default(),
            phase,
            created_at: 0,
            finished_at: finished,
            attempts: vec![Attempt {
                node: "worker".into(),
                container: "owned".into(),
                started_at: started,
                outcome: None,
                cleanup_confirmed: Some(true),
                watchdog_deadline: None,
                cleanup_proof: None,
            }],
            exit_code: code,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: true,
            queue_deadline: None,
            source_sha256: None,
            owner: None,
        }
    }

    fn health(name: &str, error: Option<&str>) -> Health {
        Health {
            name: name.into(),
            enabled: true,
            os: "linux".into(),
            arch: "amd64".into(),
            cpus: 8,
            memory_available_mib: 2048,
            disk_available_mib: 40_000,
            load: 1.5,
            runtime_memory_mib: 4096,
            runtime_arch: "amd64".into(),
            error: error.map(str::to_string),
        }
    }

    fn node(name: &str) -> Node {
        Node {
            name: name.into(),
            ssh: "worker".into(),
            images: vec![],
            ssh_config: None,
            enabled: true,
            max_jobs: 1,
            reserve_memory_mib: 512,
            reserve_disk_mib: 0,
            max_load_per_cpu: 1.0,
            priority: 0,
        }
    }

    /// 失败分类只看退出码与阶段，不解析消息文案。
    #[test]
    fn failures_are_classified_by_structure_not_by_message() {
        let mut before = job(Phase::Failed, None, 0, Some(10));
        before.message = Some("no eligible worker: busy".into());
        assert_eq!(result(&before), "failed-before-exit");

        let mut nonzero = job(Phase::Failed, Some(2), 0, Some(10));
        nonzero.message = Some("exit 2".into());
        assert_eq!(result(&nonzero), "failed-exit-nonzero");

        // 以 0 退出但任务失败：失败发生在容器之后，不能算成编译错误。
        let after = job(Phase::Failed, Some(0), 0, Some(10));
        assert_eq!(result(&after), "failed-after-exit");
        assert_eq!(
            result(&job(Phase::Succeeded, Some(0), 0, Some(10))),
            "succeeded"
        );
    }

    /// 直方图必须真的分桶：两个排队时长不同的任务落在不同边界下。
    #[test]
    fn queue_and_duration_histograms_are_cumulative() {
        let mut slow = job(Phase::Succeeded, Some(0), 500, Some(900));
        slow.created_at = 0;
        let mut fast = job(Phase::Succeeded, Some(0), 3, Some(20));
        fast.created_at = 0;
        let jobs = vec![slow, fast];
        let nodes = vec![node("worker")];
        let healths = vec![health("worker", None)];
        let text = render(&Snapshot {
            jobs: &jobs,
            health: &healths,
            nodes: &nodes,
            now: 1_000,
            access: &[(0, 128)],
        });

        // 5 秒边界只有 3 秒那次；500 秒要等到 600 秒边界才进来，累计桶必须体现这点。
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_bucket{result="succeeded",le="5"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_bucket{result="succeeded",le="120"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_bucket{result="succeeded",le="600"} 2"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_bucket{result="succeeded",le="+Inf"} 2"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_sum{result="succeeded"} 503"#),
            "{text}"
        );
        // 执行时长 200 与 400：都在 600 以内。
        assert!(
            text.contains(r#"sshpool_job_duration_seconds_bucket{result="succeeded",le="600"} 2"#),
            "{text}"
        );
        assert!(
            text.contains(
                "sshpool_job_queue_seconds_bucket{result=\"failed-before-exit\",le=\"+Inf\"} 0"
            ),
            "{text}"
        );
    }

    #[test]
    fn gauges_report_queue_cleanup_and_resource_levels() {
        let mut queued = job(Phase::Queued, None, 0, None);
        queued.attempts.clear();
        queued.created_at = 900;
        let mut dirty = job(Phase::Running, None, 500, None);
        dirty.cleanup_confirmed = false;
        let jobs = vec![queued, dirty];
        let nodes = vec![node("worker"), node("dead")];
        let healths = vec![
            health("worker", None),
            health("dead", Some("ssh: connect timeout")),
        ];
        let text = render(&Snapshot {
            jobs: &jobs,
            health: &healths,
            nodes: &nodes,
            now: 1_000,
            access: &[(0, 512), (1, 4_096)],
        });
        assert!(text.contains("sshpool_queued_jobs 1\n"), "{text}");
        assert!(
            text.contains("sshpool_queued_oldest_seconds 100\n"),
            "{text}"
        );
        assert!(text.contains("sshpool_active_jobs 1\n"), "{text}");
        assert!(
            text.contains("sshpool_jobs_cleanup_unconfirmed 1\n"),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_ready{node="worker"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_ready{node="dead"} 0"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_cpus{node="worker"} 8"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_memory_available_mib{node="worker"} 2048"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_reserve_memory_mib{node="worker"} 512"#),
            "{text}"
        );
        // 探测失败：资源数字报 0，而不是沿用上一次快照。
        assert!(
            text.contains(r#"sshpool_node_cpus{node="dead"} 0"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_node_memory_available_mib{node="dead"} 0"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_access_log_bytes{generation="0"} 512"#),
            "{text}"
        );
        assert!(
            text.contains(r#"sshpool_access_log_bytes{generation="1"} 4096"#),
            "{text}"
        );
        // 进行中的任务不属于任何终态分类：直方图没有它的样本，不能凭空造 0。
        assert!(
            text.contains(r#"sshpool_job_queue_seconds_count{result="succeeded"} 0"#),
            "{text}"
        );
    }

    /// 标签值里的反斜杠、引号、换行都要转义；否则一条节点名就能破坏整份 exposition。
    #[test]
    fn labels_are_escaped() {
        let nodes = vec![node("a\"b\\c\nd")];
        let healths = vec![health("a\"b\\c\nd", None)];
        let text = render(&Snapshot {
            jobs: &[],
            health: &healths,
            nodes: &nodes,
            now: 0,
            access: &[],
        });
        assert!(
            text.contains(r#"sshpool_node_ready{node="a\"b\\c\nd"} 1"#),
            "{text}"
        );
        assert!(!text.contains('\r'), "exposition must use LF only");
    }

    /// 渲染不依赖状态锁之外的东西：同一份输入永远得到同一份输出（抓取可重复）。
    #[test]
    fn rendering_is_deterministic() {
        let jobs = vec![job(Phase::Succeeded, Some(0), 1, Some(2))];
        let nodes = vec![node("worker")];
        let healths = vec![health("worker", None)];
        let snapshot = Snapshot {
            jobs: &jobs,
            health: &healths,
            nodes: &nodes,
            now: 10,
            access: &[],
        };
        assert_eq!(render(&snapshot), render(&snapshot));
    }
}
