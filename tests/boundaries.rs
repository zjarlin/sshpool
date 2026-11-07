use anyhow::Result;
use sshpool::{
    archive,
    config::{Build, Config, Node, Replica},
    model::{Attempt, Health, Job, Phase, queue_precedes},
    scheduler, transport,
};
use std::{fs, path::Path};

#[test]
fn source_snapshot_respects_ignore_rules_and_excludes_credentials() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("main.rs"), "fn main() {}")?;
    fs::write(root.path().join(".env"), "SECRET=never-send")?;
    fs::write(root.path().join("key.pem"), "private")?;
    fs::write(root.path().join(".gitignore"), "ignored.txt\n")?;
    fs::write(root.path().join("ignored.txt"), "private")?;
    fs::create_dir(root.path().join("target"))?;
    fs::write(root.path().join("target/binary"), "generated")?;
    let file = tempfile::NamedTempFile::new()?;
    let snapshot = archive::snapshot(root.path(), file.path(), 1048576)?;
    assert_eq!(snapshot.sha256, archive::sha256_file(file.path())?);
    let mut tar = tar::Archive::new(fs::File::open(file.path())?);
    let paths = tar
        .entries()?
        .map(|entry| Ok(entry?.path()?.into_owned()))
        .collect::<Result<Vec<_>>>()?;
    assert!(paths.contains(&"main.rs".into()));
    for secret in [".env", "key.pem", "ignored.txt", "target/binary"] {
        assert!(!paths.contains(&secret.into()));
    }
    Ok(())
}

#[test]
fn source_snapshot_is_deterministic_and_records_sha256() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("src"))?;
    fs::write(root.path().join("src/z.rs"), "newest")?;
    fs::write(root.path().join("src/a.rs"), "oldest")?;
    let first = tempfile::NamedTempFile::new()?;
    let second = tempfile::NamedTempFile::new()?;
    let first_result = archive::snapshot(root.path(), first.path(), 1048576)?;
    let second_result = archive::snapshot(root.path(), second.path(), 1048576)?;
    assert_eq!(first_result, second_result);
    assert_eq!(first_result.sha256.len(), 64);
    assert_eq!(first_result.sha256, archive::sha256_file(first.path())?);
    Ok(())
}

#[cfg(unix)]
#[test]
fn source_cannot_follow_symlink_to_company_data() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::NamedTempFile::new()?;
    std::os::unix::fs::symlink(outside.path(), root.path().join("company"))?;
    let archive = tempfile::NamedTempFile::new()?;
    assert!(archive::snapshot(root.path(), archive.path(), 1048576).is_err());
    Ok(())
}
fn archive_entry(path: &str, kind: tar::EntryType) -> Result<tempfile::NamedTempFile> {
    let file = tempfile::NamedTempFile::new()?;
    let mut builder = tar::Builder::new(fs::File::create(file.path())?);
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(0);
    header.set_entry_type(kind);
    let bytes = header.as_mut_bytes();
    bytes[..path.len()].copy_from_slice(path.as_bytes());
    header.set_cksum();
    builder.append(&header, std::io::empty())?;
    builder.finish()?;
    Ok(file)
}
#[test]
fn tar_traversal_links_and_undeclared_outputs_are_rejected() -> Result<()> {
    for path in ["../company", "/etc/passwd", "safe/../../company"] {
        let tar = archive_entry(path, tar::EntryType::Regular)?;
        assert!(
            archive::validate(tar.path(), 1048576, None).is_err(),
            "{path}"
        );
    }
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Fifo,
    ] {
        let tar = archive_entry("output", kind)?;
        assert!(archive::validate(tar.path(), 1048576, None).is_err());
    }
    let tar = archive_entry("secret.txt", tar::EntryType::Regular)?;
    assert!(archive::validate(tar.path(), 1048576, Some(&["result".into()])).is_err());
    Ok(())
}
#[test]
fn fetching_never_overwrites_existing_directory() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("company"), "must survive")?;
    let tar = archive_entry("company", tar::EntryType::Regular)?;
    assert!(archive::unpack_new(tar.path(), root.path(), 1048576).is_err());
    assert_eq!(
        fs::read_to_string(root.path().join("company"))?,
        "must survive"
    );
    Ok(())
}
#[test]
fn shell_arguments_remain_literal() -> Result<()> {
    let root = tempfile::tempdir()?;
    let sentinel = root.path().join("should-not-exist");
    let literal = format!(
        "hello'\n$(touch {}) `touch {}` $HOME",
        sentinel.display(),
        sentinel.display()
    );
    let output = std::process::Command::new("sh")
        .args(["-c", &format!("printf '%s' {}", transport::quote(&literal))])
        .output()?;
    assert_eq!(String::from_utf8(output.stdout)?, literal);
    assert!(!sentinel.exists());
    Ok(())
}
fn node_and_health() -> (Node, Health) {
    (
        Node {
            name: "worker".into(),
            ssh: "worker".into(),
            images: vec!["alpine:3.22".into()],
            ssh_config: None,
            enabled: true,
            max_jobs: 1,
            reserve_memory_mib: 4096,
            reserve_disk_mib: 10240,
            max_load_per_cpu: 0.8,
            priority: 0,
            slo: Default::default(),
        },
        Health {
            name: "worker".into(),
            enabled: true,
            os: "linux".into(),
            arch: "x86_64".into(),
            cpus: 8,
            memory_available_mib: 16384,
            disk_available_mib: 50000,
            load: 1.0,
            runtime_memory_mib: 16000,
            runtime_arch: "x86_64".into(),
            swap_used_mib: Some(0),
            memory_pressure_percent: Some(0.0),
            io_pressure_percent: Some(0.0),
            error: None,
        },
    )
}
#[test]
fn health_accepts_probe_output_without_controller_enabled_state() -> Result<()> {
    let health: Health = serde_json::from_value(serde_json::json!({
        "name": "",
        "os": "linux",
        "arch": "x86_64",
        "cpus": 32,
        "memory_available_mib": 58500,
        "disk_available_mib": 2780000,
        "load": 0.1,
        "runtime_memory_mib": 61975,
        "runtime_arch": "x86_64",
        "error": null
    }))?;
    assert!(!health.enabled);
    Ok(())
}
#[test]
fn scheduler_protects_reserves_platform_and_concurrent_slots() {
    let (node, health) = node_and_health();
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    assert!(scheduler::score(&node, &health, &build, &[]).is_ok());
    let mut pressure = health.clone();
    pressure.memory_available_mib = 4500;
    assert!(scheduler::score(&node, &pressure, &build, &[]).is_err());
    pressure = health.clone();
    pressure.disk_available_mib = 100;
    assert!(scheduler::score(&node, &pressure, &build, &[]).is_err());
    pressure = health.clone();
    pressure.load = 20.0;
    assert!(scheduler::score(&node, &pressure, &build, &[]).is_err());
    pressure = health.clone();
    pressure.runtime_arch = "aarch64".into();
    assert!(scheduler::score(&node, &pressure, &build, &[]).is_err());
    let job = Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: build.clone(),
        phase: Phase::Running,
        created_at: 0,
        finished_at: None,
        attempts: vec![Attempt {
            node: node.name.clone(),
            container: "owned".into(),
            started_at: 0,
            outcome: None,
            cleanup_confirmed: None,
            watchdog_deadline: None,
            cleanup_proof: None,
            finished_at: None,
            schedule: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    };
    assert!(scheduler::score(&node, &health, &build, &[job]).is_err());
}
#[test]
fn retry_and_path_policies_fail_closed() {
    let mut build = Build {
        retries: 1,
        ..Build::default()
    };
    assert!(build.validate().is_err());
    build.idempotent = true;
    assert!(build.validate().is_ok());
    build.network = true;
    assert!(build.validate().is_err());
    build.network = false;
    build.queue_priority = 10;
    assert!(build.validate().is_err());
    build.queue_timeout_secs = 60;
    assert!(build.validate().is_ok());
    build.queue_timeout_secs = 604_801;
    assert!(build.validate().is_err());
    for path in ["/", "../a", ".", "a/../b"] {
        assert!(archive::relative_path(Path::new(path)).is_err());
    }
}

#[test]
fn limited_queue_orders_priority_then_submission_time_with_stable_ids() {
    let build = Build {
        queue_timeout_secs: 60,
        ..Build::default()
    };
    let make_job = |priority, created_at| Job {
        id: uuid::Uuid::nil(),
        revision: 0,
        build: Build {
            queue_priority: priority,
            ..build.clone()
        },
        phase: Phase::Queued,
        created_at,
        finished_at: None,
        attempts: Vec::new(),
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: Some(created_at + 60),
        source_sha256: None,
        owner: None,
    };
    let lower = make_job(0, 1);
    let earlier = make_job(1, 2);
    let later = make_job(1, 3);
    assert!(queue_precedes(&earlier, &lower));
    assert!(queue_precedes(&earlier, &later));
    let mut older_id = later.clone();
    older_id.id = uuid::Uuid::from_u128(1);
    let mut newer_id = later;
    newer_id.id = uuid::Uuid::from_u128(2);
    assert!(queue_precedes(&older_id, &newer_id));
}
#[tokio::test]
async fn gateway_preserves_full_duplex_bytes_and_half_close() -> Result<()> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await?;
        socket.write_all(b"SSH-2.0-Test\r\n").await?;
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await?;
        socket.write_all(&request).await?;
        Ok::<_, anyhow::Error>(())
    });
    let front = TcpListener::bind("127.0.0.1:0").await?;
    let front_addr = front.local_addr()?;
    let proxy = tokio::spawn(sshpool::gateway::serve(front, backend_addr));
    let mut client = TcpStream::connect(front_addr).await?;
    client.write_all(b"opaque SSH bytes\0\xff").await?;
    client.shutdown().await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    assert_eq!(response, b"SSH-2.0-Test\r\nopaque SSH bytes\0\xff");
    server.await??;
    proxy.abort();
    Ok(())
}

#[test]
fn unapproved_images_are_rejected_even_when_already_installed() {
    let (node, health) = node_and_health();
    let build = Build {
        image: "company-app:private".into(),
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    assert!(scheduler::score(&node, &health, &build, &[]).is_err());
}

#[test]
fn uncertain_cleanup_quarantines_the_worker() {
    let (node, health) = node_and_health();
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    let mut job = Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: build.clone(),
        phase: Phase::Interrupted,
        created_at: 0,
        finished_at: Some(1),
        attempts: vec![Attempt {
            node: node.name.clone(),
            container: "owned".into(),
            started_at: 0,
            outcome: Some("SSH connection interrupted".into()),
            cleanup_confirmed: Some(false),
            watchdog_deadline: None,
            cleanup_proof: None,
            finished_at: None,
            schedule: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    };
    assert!(scheduler::score(&node, &health, &build, std::slice::from_ref(&job)).is_err());
    job.attempts[0].cleanup_confirmed = Some(true);
    job.cleanup_confirmed = true;
    assert!(scheduler::score(&node, &health, &build, &[job]).is_ok());
}

#[test]
fn a_later_success_cannot_clear_an_older_worker_quarantine() {
    let (node, health) = node_and_health();
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    let job = Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: build.clone(),
        phase: Phase::Succeeded,
        created_at: 0,
        finished_at: Some(2),
        attempts: vec![
            Attempt {
                node: node.name.clone(),
                container: "uncertain".into(),
                started_at: 0,
                outcome: Some("SSH connection interrupted".into()),
                cleanup_confirmed: Some(false),
                watchdog_deadline: None,
                cleanup_proof: None,
                finished_at: None,
                schedule: None,
            },
            Attempt {
                node: "second-node".into(),
                container: "successful".into(),
                started_at: 1,
                outcome: Some("exit 0".into()),
                cleanup_confirmed: Some(true),
                watchdog_deadline: None,
                cleanup_proof: None,
                finished_at: None,
                schedule: None,
            },
        ],
        exit_code: Some(0),
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: true,
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    };
    assert!(scheduler::score(&node, &health, &build, &[job]).is_err());
}

#[test]
fn enabled_replicas_require_distinct_failure_domains_and_positive_quorum() {
    let replica = |name: &str, domain: &str, host: &str| Replica {
        name: name.into(),
        ssh: name.into(),
        namespace: "test".into(),
        failure_domain: domain.into(),
        expected_host_id_sha256: host.repeat(64),
        ssh_config: None,
        enabled: true,
    };
    let mut config = Config {
        replica_min_ack: 2,
        replicas: vec![
            replica("one", "same-host", "a"),
            replica("two", "same-host", "b"),
        ],
        ..Config::default()
    };
    assert!(sshpool::config::validate(&config).is_err());
    config.replicas[1].failure_domain = "another-host".into();
    config.replicas[1].expected_host_id_sha256 = config.replicas[0].expected_host_id_sha256.clone();
    assert!(sshpool::config::validate(&config).is_err());
    config.replicas[1].expected_host_id_sha256 = "b".repeat(64);
    assert!(sshpool::config::validate(&config).is_ok());
    config.replicas[0].failure_domain = "local".into();
    assert!(sshpool::config::validate(&config).is_err());
    config.replicas[0].failure_domain = "same-host".into();
    config.replica_min_ack = 0;
    assert!(sshpool::config::validate(&config).is_err());
    config.replicas.clear();
    assert!(sshpool::config::validate(&config).is_ok());
}

/// 指标端点必须独立：与控制面同端口会让抓取走进鉴权与审计中间件。
#[test]
fn metrics_endpoint_cannot_reuse_a_control_plane_port() {
    let mut config = Config {
        metrics_listen: Some(Config::default().api_listen),
        ..Config::default()
    };
    assert!(sshpool::config::validate(&config).is_err());
    config.metrics_listen = Some(Config::default().ssh_listen);
    assert!(sshpool::config::validate(&config).is_err());
    config.metrics_listen = Some("127.0.0.1:9100".parse().unwrap());
    assert!(sshpool::config::validate(&config).is_ok());
    config.metrics_listen = None;
    assert!(sshpool::config::validate(&config).is_ok());
}

/// 指标端口必须带根 token 才能抓，而它本身没有 TLS 默认开关：
/// 绑定到非回环地址等于把 token 送上明文网络，因此默认拒绝。
#[test]
fn a_public_metrics_listener_must_be_allowed_explicitly() {
    let mut config = Config {
        metrics_listen: Some("127.0.0.1:9100".parse().unwrap()),
        ..Config::default()
    };
    assert!(sshpool::config::validate(&config).is_ok());
    // IPv6 回环同样算回环。
    config.metrics_listen = Some("[::1]:9100".parse().unwrap());
    assert!(sshpool::config::validate(&config).is_ok());

    config.metrics_listen = Some("0.0.0.0:9100".parse().unwrap());
    let refused = sshpool::config::validate(&config).unwrap_err().to_string();
    assert!(refused.contains("metrics_allow_remote"), "{refused}");
    // 打开远端开关还不够：明文 HTTP 上的 Bearer token 等于公开凭据。
    config.metrics_allow_remote = true;
    let refused = sshpool::config::validate(&config).unwrap_err().to_string();
    assert!(refused.contains("requires TLS"), "{refused}");
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = (root.path().join("cert.pem"), root.path().join("key.pem"));
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    config.tls_cert = Some(cert);
    config.tls_key = Some(key);
    assert!(sshpool::config::validate(&config).is_ok());
    config.tls_cert = None;
    config.tls_key = None;

    // 局域网地址与公网地址一样被拒绝；只放行回环，不放行「看起来像内网」。
    config.metrics_allow_remote = false;
    for address in ["192.0.2.10:9100", "[2001:db8::1]:9100", "0.0.0.0:9100"] {
        config.metrics_listen = Some(address.parse().unwrap());
        assert!(
            sshpool::config::validate(&config).is_err(),
            "non-loopback {address} was accepted without opting in"
        );
    }
    // 没开指标端口时这个开关无意义，但不该报错。
    config.metrics_listen = None;
    config.metrics_allow_remote = false;
    assert!(sshpool::config::validate(&config).is_ok());
}

#[test]
fn replica_namespace_cannot_escape_the_dedicated_remote_root() {
    let mut replica = Replica {
        name: "replica".into(),
        ssh: "replica-host".into(),
        namespace: "prod".into(),
        failure_domain: "host".into(),
        expected_host_id_sha256: "a".repeat(64),
        ssh_config: None,
        enabled: true,
    };
    assert!(sshpool::config::validate_replica(&replica).is_ok());
    for namespace in ["", "../escape", "/absolute", "a/b", ".", ".."] {
        replica.namespace = namespace.into();
        assert!(
            sshpool::config::validate_replica(&replica).is_err(),
            "unsafe namespace was accepted: {namespace}"
        );
    }
}

// ---------------------------------------------------------------------------
// 按实测完成时间选节点
//
// 判据统一是「排序结果是谁」，不是「某个分数是多少」：分数是实现细节，
// 「派给哪台」才是运维看得见的结论。
// ---------------------------------------------------------------------------

fn worker(name: &str, priority: i32) -> Node {
    Node {
        name: name.into(),
        ssh: name.into(),
        images: vec!["alpine:3.22".into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 0.8,
        priority,
        slo: Default::default(),
    }
}

fn machine(name: &str, cpus: u32, load: f64) -> Health {
    Health {
        name: name.into(),
        enabled: true,
        os: "linux".into(),
        arch: "x86_64".into(),
        cpus,
        memory_available_mib: 16384,
        disk_available_mib: 50000,
        load,
        runtime_memory_mib: 16000,
        runtime_arch: "x86_64".into(),
        swap_used_mib: Some(0),
        memory_pressure_percent: Some(0.0),
        io_pressure_percent: Some(0.0),
        error: None,
    }
}

fn amd64() -> Build {
    Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    }
}

/// 一条已结束的尝试：`finished_at` 由调用方决定，用来覆盖「旧记录没有结束时刻」。
fn run(node: &str, build: &Build, started_at: u64, finished_at: Option<u64>, outcome: &str) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        revision: 0,
        build: build.clone(),
        phase: Phase::Succeeded,
        created_at: started_at,
        finished_at,
        attempts: vec![Attempt {
            node: node.into(),
            container: format!("sshpool-{node}-1"),
            started_at,
            outcome: Some(outcome.into()),
            cleanup_confirmed: Some(true),
            watchdog_deadline: None,
            cleanup_proof: None,
            schedule: None,
            finished_at,
        }],
        exit_code: Some(0),
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: true,
        queue_deadline: None,
        source_sha256: None,
        owner: None,
    }
}

/// 在 `node` 上跑 `count` 次、每次耗时 `seconds` 的历史。
fn history(node: &str, build: &Build, count: usize, seconds: u64) -> Vec<Job> {
    (0..count)
        .map(|index| {
            let started = 1000 + index as u64 * 10_000;
            run(node, build, started, Some(started + seconds), "exit 0")
        })
        .collect()
}

/// 跑完整条排序链，返回选中的节点名。
fn chosen(nodes: &[Node], health: &[Health], build: &Build, jobs: &[Job]) -> String {
    let evidence = scheduler::Evidence::collect(jobs, build);
    let mut candidates: Vec<_> = nodes
        .iter()
        .zip(health)
        .filter_map(|(node, health)| scheduler::rank(node, health, build, jobs, &evidence).ok())
        .collect();
    candidates.sort_by(|left, right| left.rank_cmp(right));
    candidates
        .first()
        .map(|candidate| candidate.node.name.clone())
        .expect("at least one candidate must survive the hard filters")
}

/// 静态分更高（更多核心、更低负载）不代表更快：实测更短的那台必须胜出。
#[test]
fn a_measured_completion_time_outranks_more_idle_cores() {
    let build = amd64();
    let nodes = vec![worker("idle", 0), worker("busy", 0)];
    let health = vec![machine("idle", 32, 0.1), machine("busy", 8, 5.0)];
    let mut jobs = history("idle", &build, 3, 900);
    jobs.extend(history("busy", &build, 3, 30));
    // 没有历史时静态分决定：idle 更强。
    assert_eq!(chosen(&nodes, &health, &build, &[]), "idle");
    // 有历史时实测决定：busy 用 30 秒跑完过三次。
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "busy");
}

/// 没有实测的节点不能因为「没数据」被当成「最快」。
#[test]
fn a_node_without_measured_history_does_not_look_fastest() {
    let build = amd64();
    let nodes = vec![worker("measured", 0), worker("unknown", 0)];
    let health = vec![machine("measured", 2, 1.0), machine("unknown", 64, 0.0)];
    let jobs = history("measured", &build, 3, 600);
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "measured");
    // 依据必须说清「另一台没有实测」，否则事后会以为它被判定更慢。
    let unknown = scheduler::rank(
        &nodes[1],
        &health[1],
        &build,
        &jobs,
        &scheduler::Evidence::collect(&jobs, &build),
    )
    .unwrap();
    assert!(unknown.expected.is_none());
    assert!(
        unknown.basis().contains("no measured completion time"),
        "the basis must name the missing measurement: {}",
        unknown.basis()
    );
    let measured = scheduler::rank(
        &nodes[0],
        &health[0],
        &build,
        &jobs,
        &scheduler::Evidence::collect(&jobs, &build),
    )
    .unwrap();
    assert!(
        measured.basis().contains("eta 600s from 3 runs"),
        "the basis must show the measured bound: {}",
        measured.basis()
    );
}

/// 快的失败不是快的完成：3 秒就 exit 1 的尝试不能把节点算成最快的。
#[test]
fn a_fast_failure_is_not_a_completion_time() {
    let build = amd64();
    let jobs: Vec<Job> = (0..5)
        .map(|index| {
            let started = 1000 + index * 10;
            run("broken", &build, started, Some(started + 3), "exit 1")
        })
        .collect();
    assert!(
        scheduler::expected_seconds(&jobs, "broken", &build).is_none(),
        "a failing attempt is not a sample"
    );
    // 取而代之的是静态排序：broken 的核心更多，于是它被选中，且理由里标明没有实测。
    let nodes = vec![worker("broken", 0), worker("slow", 0)];
    let health = vec![machine("broken", 16, 0.0), machine("slow", 2, 1.0)];
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "broken");
    let candidate = scheduler::rank(
        &nodes[0],
        &health[0],
        &build,
        &jobs,
        &scheduler::Evidence::collect(&jobs, &build),
    )
    .unwrap();
    assert!(candidate.expected.is_none());
}

/// 旧记录没有 `finished_at`：那是「没有测量」，不是「零耗时」。
#[test]
fn an_attempt_without_a_finish_time_is_not_a_sample() {
    let build = amd64();
    let jobs: Vec<Job> = (0..5)
        .map(|index| run("legacy", &build, 1000 + index * 10, None, "exit 0"))
        .collect();
    assert!(
        scheduler::expected_seconds(&jobs, "legacy", &build).is_none(),
        "a missing finish time must not be read as an instant completion"
    );
    // 结束时刻早于开始说明时钟不可信，这类样本同样不能用。
    let skewed = vec![run("legacy", &build, 5000, Some(4000), "exit 0")];
    assert!(scheduler::expected_seconds(&skewed, "legacy", &build).is_none());
}

/// 只有同一类任务的历史才算证据：换了命令、镜像或资源申请就是另一回事。
#[test]
fn history_of_a_different_build_is_not_evidence() {
    let build = amd64();
    let jobs = history("worker", &build, 5, 60);
    // 同一台机器、同样的命令，但申请了 4 倍核心：耗时不能直接套用。
    let bigger = Build {
        cpus: 4.0,
        ..build.clone()
    };
    assert!(scheduler::expected_seconds(&jobs, "worker", &bigger).is_none());
    let other_command = Build {
        command: vec!["make".into(), "all".into()],
        ..build.clone()
    };
    assert!(scheduler::expected_seconds(&jobs, "worker", &other_command).is_none());
    let other_image = Build {
        image: "rust:1.90".into(),
        ..build.clone()
    };
    assert!(scheduler::expected_seconds(&jobs, "worker", &other_image).is_none());
    // 别的节点的历史也不能算到这台头上。
    assert!(scheduler::expected_seconds(&jobs, "someone-else", &build).is_none());
    assert_eq!(
        scheduler::expected_seconds(&jobs, "worker", &build)
            .unwrap()
            .seconds,
        60
    );
}

/// 少于三条样本不构成预期：一次顺利的构建不能改变以后的派发。
#[test]
fn fewer_than_three_samples_is_not_an_expectation() {
    let build = amd64();
    for count in 0..sshpool::scheduler::MIN_SAMPLES {
        let jobs = history("worker", &build, count, 42);
        assert!(
            scheduler::expected_seconds(&jobs, "worker", &build).is_none(),
            "{count} samples must not produce an expectation"
        );
    }
    let jobs = history("worker", &build, sshpool::scheduler::MIN_SAMPLES, 42);
    let expected = scheduler::expected_seconds(&jobs, "worker", &build).unwrap();
    assert_eq!(expected.seconds, 42);
    assert_eq!(expected.samples, sshpool::scheduler::MIN_SAMPLES);
}

/// 关心的是「最慢要等多久」，所以取最慢的一次，而不是被摊平的均值。
#[test]
fn the_expectation_is_the_slowest_run_not_the_average() {
    let build = amd64();
    let jobs = [10, 20, 30]
        .into_iter()
        .enumerate()
        .map(|(index, seconds)| {
            let started = 1000 + index as u64 * 10;
            run("worker", &build, started, Some(started + seconds), "exit 0")
        })
        .collect::<Vec<_>>();
    let expected = scheduler::expected_seconds(&jobs, "worker", &build).unwrap();
    assert_eq!(expected.seconds, 30, "the average would have been 20");
    assert_eq!(expected.samples, 3);
}

/// 只回看最近若干次：机器换了缓存之后，旧的慢样本不该永久拖住它。
#[test]
fn only_the_recent_window_decides() {
    let build = amd64();
    let mut jobs = vec![{
        let started = 1;
        run("worker", &build, started, Some(started + 9999), "exit 0")
    }];
    for index in 0..sshpool::scheduler::MIN_SAMPLES + 5 {
        let started = 1000 + index as u64 * 10;
        jobs.push(run("worker", &build, started, Some(started + 10), "exit 0"));
    }
    let expected = scheduler::expected_seconds(&jobs, "worker", &build).unwrap();
    assert_eq!(
        expected.seconds, 10,
        "the oldest outlier is outside the window"
    );
    assert_eq!(
        expected.samples,
        sshpool::scheduler::MIN_SAMPLES + 5,
        "the window keeps the most recent runs"
    );
}

/// 显式优先级是运维的意图，实测不能推翻它；两者都只影响排序，不影响硬过滤。
#[test]
fn explicit_priority_still_wins_over_a_shorter_measured_run() {
    let build = amd64();
    let nodes = vec![worker("preferred", 1), worker("fast", 0)];
    let health = vec![machine("preferred", 8, 1.0), machine("fast", 8, 1.0)];
    let mut jobs = history("preferred", &build, 5, 900);
    jobs.extend(history("fast", &build, 5, 5));
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "preferred");
    // 优先级相同则回到实测。
    let nodes = vec![worker("preferred", 0), worker("fast", 0)];
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "fast");
}

/// 硬过滤在前：实测最快的机器如果已经占满槽位，仍然不能被选中。
#[test]
fn a_measured_eta_cannot_bypass_a_hard_filter() {
    let build = amd64();
    let nodes = vec![worker("fast", 0), worker("slow", 0)];
    let health = vec![machine("fast", 8, 1.0), machine("slow", 8, 1.0)];
    let mut jobs = history("fast", &build, 5, 5);
    jobs.extend(history("slow", &build, 5, 900));
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "fast");
    // 给快的机器塞一个正在运行的任务：max_jobs=1，槽位已满。
    let mut busy = run("fast", &build, 99_000, None, "exit 0");
    busy.phase = Phase::Running;
    busy.attempts[0].outcome = None;
    busy.attempts[0].finished_at = None;
    jobs.push(busy);
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "slow");
    let refused = scheduler::rank(
        &nodes[0],
        &health[0],
        &build,
        &jobs,
        &scheduler::Evidence::collect(&jobs, &build),
    )
    .unwrap_err();
    assert_eq!(refused, "all slots reserved");
}

/// 同分同实测时顺序必须确定，不能随 HashMap 迭代顺序变化。
#[test]
fn ties_break_on_the_node_name_not_on_hash_order() {
    let build = amd64();
    let nodes = vec![worker("beta", 0), worker("alpha", 0)];
    let health = vec![machine("beta", 8, 1.0), machine("alpha", 8, 1.0)];
    assert_eq!(chosen(&nodes, &health, &build, &[]), "alpha");
    let nodes = vec![worker("alpha", 0), worker("beta", 0)];
    let health = vec![machine("alpha", 8, 1.0), machine("beta", 8, 1.0)];
    assert_eq!(chosen(&nodes, &health, &build, &[]), "alpha");
}

/// 一轮调度只解析一次历史，结果必须与逐节点查询一致。
#[test]
fn one_pass_evidence_matches_per_node_lookup() {
    let build = amd64();
    let nodes = vec![worker("a", 0), worker("b", 0), worker("c", 0)];
    let health = vec![
        machine("a", 8, 1.0),
        machine("b", 8, 1.0),
        machine("c", 8, 1.0),
    ];
    let mut jobs = history("a", &build, 4, 100);
    jobs.extend(history("b", &build, 3, 200));
    jobs.extend(history("c", &build, 2, 5));
    let evidence = scheduler::Evidence::collect(&jobs, &build);
    assert_eq!(evidence.expected("a").map(|eta| eta.seconds), Some(100));
    assert_eq!(evidence.expected("b").map(|eta| eta.seconds), Some(200));
    // c 只有 2 条样本：不足以产生预期，即便它「看起来最快」。
    assert!(evidence.expected("c").is_none());
    assert_eq!(chosen(&nodes, &health, &build, &jobs), "a");
    // 逐节点查询必须给出一模一样的结果，否则两处口径迟早分叉。
    for node in &nodes {
        assert_eq!(
            evidence.expected(&node.name),
            scheduler::expected_seconds(&jobs, &node.name, &build).as_ref()
        );
    }
}

// ---------------------------------------------------------------------------
// 业务预算（060-isolation「业务 SLO 实测」）
//
// 判据是「还接不接单」，不是「数字好不好看」。这里刻意不测聚合指标，
// 只看 `business_budget_allows` 与它让 `score` 给出的拒绝理由。
// ---------------------------------------------------------------------------

/// 给测试节点装上预算；`None` 的项保持不设门槛。
fn budgeted(
    max_swap_used_mib: Option<u64>,
    memory: Option<f64>,
    io: Option<f64>,
) -> sshpool::config::Slo {
    sshpool::config::Slo {
        max_swap_used_mib,
        max_memory_pressure_percent: memory,
        max_io_pressure_percent: io,
    }
}

/// 默认的 `node_and_health` 没有被任何预算约束：不设门槛就不能凭空拒绝。
#[test]
fn a_node_without_a_budget_keeps_taking_work() {
    let (node, health) = node_and_health();
    assert!(node.slo.is_empty());
    assert_eq!(scheduler::business_budget_allows(&node, &health), Ok(()));
    // 探测报出很差的数字也一样：没打开预算就不该改变现有调度行为。
    let mut bad = health.clone();
    bad.swap_used_mib = Some(30_000);
    bad.memory_pressure_percent = Some(95.0);
    bad.io_pressure_percent = Some(95.0);
    assert_eq!(scheduler::business_budget_allows(&node, &bad), Ok(()));
}

/// 预算内放行，超出后拒绝，理由里两个数字都要出现。
#[test]
fn swap_usage_above_the_budget_stops_new_work() {
    let (mut node, mut health) = node_and_health();
    node.slo = budgeted(Some(512), None, None);
    health.swap_used_mib = Some(512);
    assert!(scheduler::business_budget_allows(&node, &health).is_ok());
    health.swap_used_mib = Some(513);
    let reason = scheduler::business_budget_allows(&node, &health).unwrap_err();
    assert!(reason.contains("513"), "{reason}");
    assert!(reason.contains("512"), "{reason}");
}

/// 没测到 swap 不等于「用了 0」：配了门槛就必须拒绝。
#[test]
fn an_unmeasured_swap_reading_cannot_prove_the_budget_is_fine() {
    let (mut node, mut health) = node_and_health();
    node.slo = budgeted(Some(4096), None, None);
    health.swap_used_mib = None;
    let reason = scheduler::business_budget_allows(&node, &health).unwrap_err();
    assert!(reason.contains("not measured"), "{reason}");
}

/// PSI 是百分比：刚好卡在门槛上放行，超过一点就拒绝。
#[test]
fn pressure_at_the_budget_passes_and_above_it_refuses() {
    let (mut node, mut health) = node_and_health();
    node.slo = budgeted(None, Some(10.0), Some(20.0));
    health.memory_pressure_percent = Some(10.0);
    health.io_pressure_percent = Some(20.0);
    assert!(scheduler::business_budget_allows(&node, &health).is_ok());

    health.memory_pressure_percent = Some(10.01);
    let reason = scheduler::business_budget_allows(&node, &health).unwrap_err();
    assert!(reason.contains("memory pressure"), "{reason}");

    health.memory_pressure_percent = Some(1.0);
    health.io_pressure_percent = Some(20.5);
    let reason = scheduler::business_budget_allows(&node, &health).unwrap_err();
    assert!(reason.contains("io pressure"), "{reason}");
}

/// 老内核没有 PSI：配了门槛就没有证据，必须按拒绝处理而不是「默认 0」。
#[test]
fn a_kernel_without_psi_cannot_satisfy_a_pressure_budget() {
    let (mut node, mut health) = node_and_health();
    node.slo = budgeted(None, Some(5.0), None);
    health.memory_pressure_percent = None;
    let reason = scheduler::business_budget_allows(&node, &health).unwrap_err();
    assert!(reason.contains("no PSI support"), "{reason}");
}

/// 预算失败必须是从 `score` 出来的硬过滤的同一类结果：
/// 排序再快也不能越过它，而且不会被算成「另一台更快」。
#[test]
fn an_over_budget_node_is_excluded_by_the_hard_filter_not_outranked() {
    let (mut node, mut health) = node_and_health();
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    node.slo = budgeted(Some(1024), None, None);
    health.swap_used_mib = Some(1024 * 4);
    let reason = scheduler::score(&node, &health, &build, &[]).unwrap_err();
    assert!(
        reason.contains("business budget"),
        "the hard filter must say why: {reason}"
    );
    // 有实测也必须出局：预算是过滤条件，不是排序分。
    let jobs = history("worker", &build, 5, 1);
    let evidence = scheduler::Evidence::collect(&jobs, &build);
    assert!(scheduler::rank(&node, &health, &build, &jobs, &evidence).is_err());
}

/// 预算只影响这台节点，不能把整池都停掉：另一台没超预算的仍可接单。
#[test]
fn one_over_budget_worker_does_not_take_the_pool_down() {
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    let mut healthy = worker("healthy", 0);
    healthy.slo = budgeted(Some(4096), None, None);
    let mut tight = worker("tight", 0);
    tight.slo = budgeted(Some(4096), None, None);
    let mut tight_health = machine("tight", 8, 1.0);
    tight_health.swap_used_mib = Some(9000);
    let health = vec![machine("healthy", 8, 1.0), tight_health];
    let nodes = vec![healthy, tight];
    assert_eq!(chosen(&nodes, &health, &build, &[]), "healthy");
    let refused = scheduler::rank(
        &nodes[1],
        &health[1],
        &build,
        &[],
        &scheduler::Evidence::collect(&[], &build),
    )
    .unwrap_err();
    assert!(refused.contains("business budget"), "{refused}");
}

/// 探测失败时所有测量都是 `None`：预算之门默认关闭，绝不因为读不到就放行。
#[test]
fn a_failed_probe_reports_no_measurements_at_all() {
    let health = Health::failed("dead", "ssh: connect timeout".into());
    assert!(health.swap_used_mib.is_none());
    assert!(health.memory_pressure_percent.is_none());
    assert!(health.io_pressure_percent.is_none());
    let (mut node, _) = node_and_health();
    node.slo = budgeted(Some(1), Some(1.0), Some(1.0));
    assert!(scheduler::business_budget_allows(&node, &health).is_err());
}

/// 缺字段的旧探测结果仍能反序列化：三项测量一律是 `None`（没测过），不是 0。
#[test]
fn an_old_probe_payload_loads_with_unmeasured_pressure() -> Result<()> {
    let health: Health = serde_json::from_value(serde_json::json!({
        "name": "worker",
        "os": "linux",
        "arch": "x86_64",
        "cpus": 8,
        "memory_available_mib": 8192,
        "disk_available_mib": 40000,
        "load": 0.5,
        "runtime_memory_mib": 16000,
        "runtime_arch": "x86_64",
        "error": null
    }))?;
    assert!(health.swap_used_mib.is_none());
    assert!(health.memory_pressure_percent.is_none());
    assert!(health.io_pressure_percent.is_none());
    // 老载荷 + 已配预算 = 拒绝，而不是因为缺字段被当成健康。
    let (mut node, _) = node_and_health();
    node.slo = budgeted(Some(0), None, None);
    assert!(scheduler::business_budget_allows(&node, &health).is_err());
    Ok(())
}

/// 磁盘水位是同一个「还接不接单」问题：`reserve_disk_mib` 就是可用空间的下限。
///
/// 它没有单独放进 `slo`，因为语义已经存在且被强制；这里把它与预算放在一起断言，
/// 是为了让「磁盘水位」不被当成尚未实现的一项。
#[test]
fn disk_water_level_is_enforced_as_an_available_floor() {
    let (mut node, health) = node_and_health();
    let build = Build {
        platform: "linux/amd64".into(),
        ..Build::default()
    };
    // 默认快照有 50000 MiB 可用：下限设到 50001 就必须拒绝。
    node.reserve_disk_mib = 50_001;
    assert!(scheduler::score(&node, &health, &build, &[]).is_err());
    node.reserve_disk_mib = 50_000;
    let mut ok = health.clone();
    ok.disk_available_mib = 50_000;
    assert!(scheduler::score(&node, &ok, &build, &[]).is_ok());
    ok.disk_available_mib = 49_999;
    let reason = scheduler::score(&node, &ok, &build, &[]).unwrap_err();
    assert!(reason.contains("disk reserve"), "{reason}");
    // 探测失败时可用空间是 0，同样出局：读不到不等于「还有很多」。
    let failed = Health::failed("worker", "ssh: connect timeout".into());
    assert!(scheduler::score(&node, &failed, &build, &[]).is_err());
    // 它是硬过滤：有再好的实测也越不过去。
    let jobs = history("worker", &build, 5, 1);
    let evidence = scheduler::Evidence::collect(&jobs, &build);
    assert!(scheduler::rank(&node, &ok, &build, &jobs, &evidence).is_err());
}

/// 预算数值本身要校验：百分比写 101 只会变成一个永远不触发的门槛。
#[test]
fn a_budget_outside_the_percentage_range_is_rejected() {
    let (mut node, _) = node_and_health();
    node.slo = budgeted(None, Some(101.0), None);
    assert!(sshpool::config::validate_node(&node).is_err());
    node.slo = budgeted(None, Some(-0.1), None);
    assert!(sshpool::config::validate_node(&node).is_err());
    node.slo = budgeted(None, None, Some(f64::NAN));
    assert!(sshpool::config::validate_node(&node).is_err());
    node.slo = budgeted(Some(0), Some(100.0), Some(100.0));
    assert!(sshpool::config::validate_node(&node).is_ok());
}
