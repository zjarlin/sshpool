//! 外部观测：真实二进制在独立端口上提供 Prometheus 抓取点。
//!
//! 断言的是「抓取端拿到可解析的 exposition，且不依赖、也不污染控制面」：
//! 默认不开指标端口；打开后抓取不写访问审计；慢连接只丢自己那一条；
//! 未知路径 404；节点探测失败时资源数字报 0 而不是沿用旧快照。
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap, fs, io::Read, io::Write, net::TcpStream, path::Path, process::Stdio,
    time::Duration,
};

fn cli(home: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .arg("--home")
        .arg(home)
        .args(args)
        .output()?)
}

/// 端口在这里只是「租约」：绑定后立刻持有，配置写盘后才释放，紧接着 spawn。
///
/// 单纯 bind→close→记下端口会留一个窗口，同一测试二进制里并行启动的另一个
/// 控制面可能正好抢走它（CI 上真实发生过 `Address already in use`）。调用方
/// 仍然要能容忍这次失败，因为释放与子进程 bind 之间不可能完全原子。
struct Ports {
    listeners: Vec<std::net::TcpListener>,
}

impl Ports {
    fn reserve(count: usize) -> Result<Self> {
        let mut listeners = Vec::new();
        while listeners.len() < count {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            listeners.push(listener);
        }
        Ok(Self { listeners })
    }

    fn ports(&self) -> Vec<u16> {
        self.listeners
            .iter()
            .map(|listener| listener.local_addr().map(|address| address.port()))
            .collect::<std::io::Result<Vec<_>>>()
            .expect("bound listeners have addresses")
    }

    fn release(self) -> Vec<u16> {
        let ports = self.ports();
        drop(self.listeners);
        ports
    }
}

struct Controller {
    root: tempfile::TempDir,
    api: u16,
    metrics: u16,
    child: std::process::Child,
    log: std::path::PathBuf,
    token: String,
}

impl Controller {
    /// 端口租约可能被别人抢走，所以整次启动最多重试三次；失败重试不会掩盖
    /// 真正的启动缺陷，因为最后一次错误原样返回。
    fn start(enable_metrics: bool, nodes: &str) -> Result<Self> {
        let mut last = None;
        for _ in 0..3 {
            match Self::start_once(enable_metrics, nodes) {
                Ok(controller) => return Ok(controller),
                Err(error) => {
                    let text = format!("{error:#}");
                    if !text.contains("Address already in use") {
                        return Err(error);
                    }
                    last = Some(error);
                }
            }
        }
        Err(last.expect("the loop always runs once"))
    }

    fn start_once(enable_metrics: bool, nodes: &str) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let init = cli(root.path(), &["init"])?;
        ensure!(
            init.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let reserved = Ports::reserve(if enable_metrics { 4 } else { 3 })?;
        let ports = reserved.ports();
        let (api, ssh_listen, backend) = (ports[0], ports[1], ports[2]);
        let metrics = if enable_metrics { ports[3] } else { 0 };
        let metrics_line = if enable_metrics {
            format!("metrics_listen = \"127.0.0.1:{metrics}\"\n")
        } else {
            String::new()
        };
        // 不配 TLS：本测试只关心指标端口，TLS 已由 access_network 覆盖。
        let config = format!(
            r#"api_listen = "127.0.0.1:{api}"
ssh_listen = "127.0.0.1:{ssh_listen}"
ssh_backend = "127.0.0.1:{backend}"
max_upload_mib = 16
max_log_mib = 16
max_artifact_mib = 16
min_free_disk_mib = 0
max_active_jobs = 1
replica_min_ack = 0
{nodes}replicas = []
{metrics_line}"#
        );
        fs::write(root.path().join("config.toml"), config)?;
        // 写盘完成才释放端口租约，尽量把「释放」与「子进程 bind」之间的窗口压到最小。
        let ports = reserved.release();
        ensure!(
            ports.len() == if enable_metrics { 4 } else { 3 },
            "unexpected port count"
        );
        let log = root.path().join("serve.log");
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
            .arg("--home")
            .arg(root.path())
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::from(fs::File::create(&log)?))
            .spawn()?;
        let token = fs::read_to_string(root.path().join("token"))?
            .trim()
            .to_string();
        let controller = Self {
            root,
            api,
            metrics,
            child,
            log,
            token,
        };
        // 就绪判据是「控制面真的回了状态」，不是「端口 bind 了」。
        for _ in 0..100 {
            if controller.status() == Some(200) {
                return Ok(controller);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        anyhow::bail!("controller did not serve in time:\n{}", controller.output());
    }

    fn output(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// 用最小 HTTP 请求拿状态码；控制面在明文回环上，不需要 CA。
    fn status(&self) -> Option<u16> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.api)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        write!(
            stream,
            "GET /v1/status HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {}\r\nconnection: close\r\n\r\n",
            self.token
        )
        .ok()?;
        let mut text = String::new();
        stream.read_to_string(&mut text).ok()?;
        text.split_whitespace().nth(1)?.parse().ok()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 手写 HTTP 拿原始文本：抓取点不是 JSON，也不需要保持连接。
///
/// `authorization` 传完整头部值（`Bearer <token>`）；`None` 表示故意不带凭据。
fn scrape_with(port: u16, path: &str, authorization: Option<&str>) -> Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n");
    if let Some(value) = authorization {
        request.push_str(&format!("authorization: {value}\r\n"));
    }
    request.push_str("connection: close\r\n\r\n");
    write!(stream, "{request}")?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    Ok(text)
}

/// 带根 token 的成功抓取：绝大多数断言关心的是 exposition 本身。
fn scrape(port: u16, path: &str, token: &str) -> Result<String> {
    scrape_with(port, path, Some(&format!("Bearer {token}")))
}

/// 把响应拆成响应头与正文；调用方先断言状态行再取样本。
fn split(response: &str) -> (&str, &str) {
    response.split_once("\r\n\r\n").unwrap_or((response, ""))
}

/// 严格校验 exposition：每个样本值是有限数字，标签值不逃逸，
/// 同一 (指标, result) 的桶边界单调递增，`+Inf` 桶等于 count。
fn assert_parseable(body: &str) -> Result<()> {
    struct Histogram {
        boundaries: Vec<f64>,
        inf: Option<f64>,
    }
    let mut counts: HashMap<String, f64> = HashMap::new();
    let mut sums: HashMap<String, f64> = HashMap::new();
    let mut histograms: HashMap<String, Histogram> = HashMap::new();

    for line in body.lines() {
        if line.starts_with('#') {
            ensure!(
                line.starts_with("# HELP ") || line.starts_with("# TYPE "),
                "unexpected comment line: {line}"
            );
            continue;
        }
        ensure!(!line.trim().is_empty(), "blank line in exposition");
        let (sample, value) = line.rsplit_once(' ').context("sample needs a value")?;
        let value: f64 = value
            .parse()
            .with_context(|| format!("bad value: {line}"))?;
        ensure!(value.is_finite(), "non-finite value: {line}");
        let (name, labels) = match sample.split_once('{') {
            Some((name, rest)) => {
                ensure!(rest.ends_with('}'), "unclosed labels: {line}");
                (name, &rest[..rest.len() - 1])
            }
            None => (sample, ""),
        };
        let mut key = String::new();
        let mut le = None;
        for (label, value) in split_labels(labels)? {
            match label {
                "result" => key = value,
                "le" => le = Some(value),
                // 节点与代次是数据标签，参与去重但不需要额外语义。
                "node" | "generation" => {}
                other => anyhow::bail!("unexpected label {other}: {line}"),
            }
        }
        // 直方图三个后缀共用同一个族名：`_bucket` / `_count` / `_sum` 的样本名不同，
        // 只有归一到族名之后才能校验「+Inf 桶 == count」和「sum 存在」。
        let (family, suffix) = match name
            .strip_suffix("_bucket")
            .map(|base| (base, "bucket"))
            .or_else(|| name.strip_suffix("_count").map(|base| (base, "count")))
            .or_else(|| name.strip_suffix("_sum").map(|base| (base, "sum")))
        {
            Some((base, suffix)) => (base, Some(suffix)),
            None => (name, None),
        };
        let id = format!("{family}{{{key}}}");
        if suffix == Some("count") {
            counts.insert(id.clone(), value);
        } else if suffix == Some("sum") {
            sums.insert(id.clone(), value);
        } else if suffix == Some("bucket") {
            let entry = histograms.entry(id).or_insert(Histogram {
                boundaries: Vec::new(),
                inf: None,
            });
            match le.as_deref() {
                Some("+Inf") => entry.inf = Some(value),
                Some(boundary) => entry.boundaries.push(
                    boundary
                        .parse()
                        .with_context(|| format!("bad le: {line}"))?,
                ),
                None => anyhow::bail!("bucket without le: {line}"),
            }
        }
    }

    for (id, histogram) in &histograms {
        ensure!(
            !histogram.boundaries.is_empty() || histogram.inf.is_some(),
            "{id} has no buckets"
        );
        ensure!(
            histogram
                .boundaries
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "{id} has non-increasing buckets"
        );
        let count = counts
            .get(id)
            .with_context(|| format!("{id} missing count"))?;
        ensure!(
            (histogram.inf.unwrap_or(-1.0) - count).abs() < f64::EPSILON,
            "{id} +Inf bucket does not equal count"
        );
        ensure!(sums.contains_key(id), "{id} missing sum");
    }
    Ok(())
}

fn split_labels(labels: &str) -> Result<Vec<(&str, String)>> {
    let mut out = Vec::new();
    let mut rest = labels;
    while !rest.is_empty() {
        let (label, tail) = rest.split_once('=').context("label needs =")?;
        let Some(after) = tail.strip_prefix('"') else {
            anyhow::bail!("label value must be quoted: {labels}");
        };
        let mut value = String::new();
        let mut tail = after;
        loop {
            let mut chars = tail.char_indices();
            match chars.next() {
                Some((_, '\\')) => {
                    let (index, escaped) = chars.next().context("dangling escape")?;
                    value.push(match escaped {
                        '\\' => '\\',
                        '"' => '"',
                        'n' => '\n',
                        other => anyhow::bail!("bad escape: {other}"),
                    });
                    tail = &tail[index + escaped.len_utf8()..];
                }
                Some((index, '"')) => {
                    tail = &tail[index + 1..];
                    break;
                }
                Some((index, character)) => {
                    value.push(character);
                    tail = &tail[index + character.len_utf8()..];
                }
                None => anyhow::bail!("unterminated label value: {labels}"),
            }
        }
        out.push((label, value));
        rest = match tail.strip_prefix(',') {
            Some(rest) => rest,
            None if tail.is_empty() => "",
            None => anyhow::bail!("labels must be comma separated: {labels}"),
        };
    }
    Ok(out)
}

#[test]
fn the_parser_rejects_a_boolean_sample_and_counts_inf() {
    // 自检：`true` 不是样本值。这条曾经是真实缺陷（node_ready 输出了 true）。
    assert!(assert_parseable("sshpool_node_ready{node=\"a\"} 1\n").is_ok());
    assert!(assert_parseable("sshpool_node_ready{node=\"a\"} true\n").is_err());
    assert!(
        assert_parseable("sshpool_jobs{result=\"succeeded\"} 1\n").is_ok(),
        "a plain gauge needs no sum"
    );
    // 桶、count、sum 共用族名：三者齐全且 +Inf == count 才算完整。
    assert!(
        assert_parseable(
            "# TYPE x histogram\nx_bucket{result=\"a\",le=\"5\"} 1\nx_bucket{result=\"a\",le=\"+Inf\"} 2\nx_sum{result=\"a\"} 3\nx_count{result=\"a\"} 2\n"
        )
        .is_ok(),
        "a complete histogram must parse"
    );
    assert!(
        assert_parseable(
            "# TYPE x histogram\nx_bucket{result=\"a\",le=\"5\"} 1\nx_bucket{result=\"a\",le=\"+Inf\"} 1\nx_sum{result=\"a\"} 3\nx_count{result=\"a\"} 2\n"
        )
        .is_err(),
        "+Inf must equal count"
    );
    // 只写桶不写 count：旧解析器会当成「没有直方图」而漏判。
    assert!(
        assert_parseable(
            "# TYPE x histogram\nx_bucket{result=\"a\",le=\"5\"} 1\nx_bucket{result=\"a\",le=\"+Inf\"} 2\nx_sum{result=\"a\"} 3\n"
        )
        .is_err(),
        "a histogram without count must be rejected"
    );
}

#[tokio::test]
async fn metrics_are_off_by_default_and_opt_in_on_a_separate_port() -> Result<()> {
    let controller = Controller::start(false, "nodes = []\n")?;
    // 默认关闭：启动行写 off，且没有第二个监听端口可抓。
    assert!(
        controller.output().contains("metrics=off"),
        "{}",
        controller.output()
    );
    assert_eq!(controller.metrics, 0);
    Ok(())
}

#[tokio::test]
async fn scraping_is_parseable_and_never_writes_the_access_audit() -> Result<()> {
    let controller = Controller::start(true, "nodes = []\n")?;
    let audit = controller.root.path().join("access.jsonl");
    let before = fs::metadata(&audit).map(|m| m.len()).unwrap_or(0);
    // 探测本身就打了一次带 token 的 /v1/status；先让审计落盘再取基线。
    std::thread::sleep(Duration::from_millis(200));
    let before = fs::metadata(&audit).map(|m| m.len()).unwrap_or(before);

    let response = scrape(controller.metrics, "/metrics", &controller.token)?;
    let (head, body) = split(&response);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(
        head.to_lowercase()
            .contains("content-type: text/plain; version=0.0.4"),
        "{head}"
    );
    assert_parseable(body)?;
    // 空控制面也要有稳定的骨架，抓取端不用判断「有没有数据」。
    for sample in [
        "sshpool_jobs{result=\"succeeded\"} 0",
        "sshpool_active_jobs 0",
        "sshpool_queued_jobs 0",
        "sshpool_job_attempts_total 0",
    ] {
        assert!(body.contains(sample), "missing {sample} in:\n{body}");
    }

    let after = fs::metadata(&audit).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        before, after,
        "scraping must not write access.jsonl (a 15s scrape would flush the bounded log)"
    );

    // 未知路径 404，而不是把任何请求都当成指标。
    let missing = scrape(controller.metrics, "/v1/jobs", &controller.token)?;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    Ok(())
}

/// 指标端口不是匿名入口：没有凭据一律 401，且响应里一个样本都不给。
#[tokio::test]
async fn scraping_without_a_token_is_refused_without_leaking_samples() -> Result<()> {
    let controller = Controller::start(true, "nodes = [{name = \"lab\", ssh = \"127.0.0.1\"}]\n")?;
    for authorization in [None, Some("Bearer "), Some("Bearer wrong-token")] {
        let response = scrape_with(controller.metrics, "/metrics", authorization)?;
        let (head, body) = split(&response);
        assert!(
            head.starts_with("HTTP/1.1 401 Unauthorized"),
            "authorization {authorization:?} must be refused: {head}"
        );
        assert!(
            head.to_lowercase().contains("www-authenticate: bearer"),
            "a 401 must tell the client which scheme to use: {head}"
        );
        assert_eq!(
            body, "unauthorized",
            "the body must not vary with the guess"
        );
        assert!(
            !body.contains("sshpool_") && !body.contains("lab"),
            "a refused scrape must not leak metrics or node names: {body}"
        );
        // 未知路径也一样：未认证时连「哪些路径存在」都不该暴露。
        let response = scrape_with(controller.metrics, "/v1/jobs", authorization)?;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }
    Ok(())
}

/// 短期凭据即使带 `read` 也抓不到指标：指标是运维面，不是借出去的工作台接口。
#[tokio::test]
async fn a_short_lived_read_credential_cannot_scrape() -> Result<()> {
    let controller = Controller::start(true, "nodes = [{name = \"lab\", ssh = \"127.0.0.1\"}]\n")?;
    let issued = cli(
        controller.root.path(),
        &[
            "credential",
            "issue",
            "--subject",
            "workbench",
            "--scope",
            "read",
            "--scope",
            "admin",
        ],
    )?;
    ensure!(
        issued.status.success(),
        "credential issue failed: {}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let issued: serde_json::Value = serde_json::from_slice(&issued.stdout)?;
    let token = issued["token"].as_str().context("issued token")?;

    // 同一份凭据能读控制面（证明它本身有效），但抓不到指标。
    let mut stream = TcpStream::connect(("127.0.0.1", controller.api))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET /v1/status HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\nconnection: close\r\n\r\n"
    )?;
    let mut status = String::new();
    stream.read_to_string(&mut status)?;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");

    let response = scrape(controller.metrics, "/metrics", token)?;
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    Ok(())
}

/// 401 不写访问审计：抓取本来就不审计，被拒绝的抓取同样不该写。
#[tokio::test]
async fn a_refused_scrape_does_not_write_the_access_audit() -> Result<()> {
    let controller = Controller::start(true, "nodes = []\n")?;
    let audit = controller.root.path().join("access.jsonl");
    std::thread::sleep(Duration::from_millis(200));
    let before = fs::metadata(&audit).map(|m| m.len()).unwrap_or(0);
    for authorization in [None, Some("Bearer wrong-token")] {
        let response = scrape_with(controller.metrics, "/metrics", authorization)?;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }
    let after = fs::metadata(&audit).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        before, after,
        "the metrics port must not write access.jsonl"
    );
    Ok(())
}

#[tokio::test]
async fn a_silent_scraper_does_not_block_the_next_scrape() -> Result<()> {
    let controller = Controller::start(true, "nodes = []\n")?;
    for _ in 0..8 {
        std::mem::forget(TcpStream::connect(("127.0.0.1", controller.metrics))?);
    }
    let started = std::time::Instant::now();
    let response = scrape(controller.metrics, "/metrics", &controller.token)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "silent connections blocked the next scrape for {:?}",
        started.elapsed()
    );
    Ok(())
}

#[tokio::test]
async fn an_unprobeable_node_reports_zero_resources_not_a_stale_number() -> Result<()> {
    // SSH 目标不可达：探测必然失败，但节点仍然是配置的一部分。
    let nodes = "nodes = [{name = \"dead\", ssh = \"127.0.0.1\"}]\n";
    let controller = Controller::start(true, nodes)?;
    let response = scrape(controller.metrics, "/metrics", &controller.token)?;
    let (_, body) = split(&response);
    assert_parseable(body)?;
    assert!(
        body.contains("sshpool_node_ready{node=\"dead\"} 0"),
        "an unreachable node must be reported not-ready:\n{body}"
    );
    for metric in ["cpus", "memory_available_mib", "disk_available_mib"] {
        assert!(
            body.contains(&format!("sshpool_node_{metric}{{node=\"dead\"}} 0")),
            "a failed probe must not reuse an old {metric}:\n{body}"
        );
    }
    // 默认预留 4096 MiB 是配置事实，与探测成功与否无关。
    assert!(
        body.contains("sshpool_node_reserve_memory_mib{node=\"dead\"} 4096"),
        "{body}"
    );
    // 探测失败时控制面仍然服务：抓取不是探活的替代品。
    assert_eq!(controller.status(), Some(200));
    Ok(())
}
