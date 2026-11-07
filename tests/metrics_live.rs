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

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn cli(home: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .arg("--home")
        .arg(home)
        .args(args)
        .output()?)
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
    fn start(enable_metrics: bool, nodes: &str) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let init = cli(root.path(), &["init"])?;
        ensure!(
            init.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let api = free_port()?;
        let mut ssh_listen = free_port()?;
        while ssh_listen == api {
            ssh_listen = free_port()?;
        }
        let mut backend = free_port()?;
        while backend == api || backend == ssh_listen {
            backend = free_port()?;
        }
        let mut metrics = 0;
        if enable_metrics {
            metrics = free_port()?;
            while [api, ssh_listen, backend].contains(&metrics) {
                metrics = free_port()?;
            }
        }
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
fn scrape(port: u16, path: &str) -> Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n"
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    Ok(text)
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

    let response = scrape(controller.metrics, "/metrics")?;
    let (head, body) = response.split_once("\r\n\r\n").context("missing headers")?;
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
    let missing = scrape(controller.metrics, "/v1/jobs")?;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    Ok(())
}

#[tokio::test]
async fn a_silent_scraper_does_not_block_the_next_scrape() -> Result<()> {
    let controller = Controller::start(true, "nodes = []\n")?;
    for _ in 0..8 {
        std::mem::forget(TcpStream::connect(("127.0.0.1", controller.metrics))?);
    }
    let started = std::time::Instant::now();
    let response = scrape(controller.metrics, "/metrics")?;
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
    let body = scrape(controller.metrics, "/metrics")?;
    let (_, body) = body.split_once("\r\n\r\n").context("missing headers")?;
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
