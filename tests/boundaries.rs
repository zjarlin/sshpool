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
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
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
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline: None,
        source_sha256: None,
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
            },
            Attempt {
                node: "second-node".into(),
                container: "successful".into(),
                started_at: 1,
                outcome: Some("exit 0".into()),
                cleanup_confirmed: Some(true),
            },
        ],
        exit_code: Some(0),
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: true,
        queue_deadline: None,
        source_sha256: None,
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
