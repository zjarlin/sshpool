use anyhow::Result;
use sshpool::{
    archive,
    config::{Build, Node},
    model::{Attempt, Health, Job, Phase},
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
    archive::snapshot(root.path(), file.path(), 1048576)?;
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
        build: build.clone(),
        phase: Phase::Running,
        created_at: 0,
        finished_at: None,
        attempts: vec![Attempt {
            node: node.name.clone(),
            container: "owned".into(),
            started_at: 0,
            outcome: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
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
    for path in ["/", "../a", ".", "a/../b"] {
        assert!(archive::relative_path(Path::new(path)).is_err());
    }
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
        build: build.clone(),
        phase: Phase::Interrupted,
        created_at: 0,
        finished_at: Some(1),
        attempts: vec![Attempt {
            node: node.name.clone(),
            container: "owned".into(),
            started_at: 0,
            outcome: None,
        }],
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
    };
    assert!(scheduler::score(&node, &health, &build, std::slice::from_ref(&job)).is_err());
    job.cleanup_confirmed = true;
    assert!(scheduler::score(&node, &health, &build, &[job]).is_ok());
}
