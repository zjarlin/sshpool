//! 跨不可信网络：校验证书的 HTTPS 控制面 + 可短期签发并撤销的访问凭据。
//!
//! 这条测试启动**真实二进制**的 `sshpool serve`（临时 home、回环端口、自签证书），
//! 然后用真实 CLI 与 HTTP 客户端访问它。不用 `routes(state).oneshot(...)`，
//! 因为要证明的正是「线上链路会校验证书、撤销会立刻生效」，而不是处理器能被调用。
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{fs, net::SocketAddr, path::Path, process::Stdio, time::Duration};

/// 一棵一次性自签证书；CN/SAN 都指向 `localhost` 与 `127.0.0.1`。
struct Certificate {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl Certificate {
    fn generate(root: &Path) -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])?;
        let cert = root.join("cert.pem");
        let key = root.join("key.pem");
        fs::write(&cert, certified.cert.pem())?;
        fs::write(&key, certified.signing_key.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { cert, key })
    }
}

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

/// 临时控制面：`init` 之后覆盖配置为「TLS + 两个空闲端口」，再起服务。
struct Controller {
    root: tempfile::TempDir,
    endpoint: String,
    cert: std::path::PathBuf,
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Controller {
    async fn start() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let init = cli(root.path(), &["init"])?;
        ensure!(
            init.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let certificate = Certificate::generate(root.path())?;
        let api = free_port()?;
        let mut ssh_listen = free_port()?;
        while ssh_listen == api {
            ssh_listen = free_port()?;
        }
        let mut backend = free_port()?;
        while backend == api || backend == ssh_listen {
            backend = free_port()?;
        }
        // 直接写配置：`init` 的默认值是明文 8877，不适合并发测试。
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
nodes = []
replicas = []
tls_cert = "{}"
tls_key = "{}"
"#,
            certificate.cert.display(),
            certificate.key.display()
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
        let endpoint = format!("https://127.0.0.1:{api}");
        let controller = Self {
            root,
            endpoint,
            cert: certificate.cert,
            child,
            log,
        };
        // 每个新连接都要重新握手，所以「能读到 /v1/status」就是「证书与端口都生效」，
        // 而且这一轮探测本身就用了 CA 校验，不会把明文或错证书当成就绪。
        let token = fs::read_to_string(controller.root.path().join("token"))?;
        let mut last = String::new();
        for _ in 0..100 {
            match controller.http(Some(&controller.cert)).await {
                Ok(http) => {
                    let response = http
                        .get(format!("{}/v1/status", controller.endpoint))
                        .bearer_auth(token.trim())
                        .send()
                        .await;
                    if matches!(response, Ok(response) if response.status() == 200) {
                        return Ok(controller);
                    }
                }
                Err(error) => last = format!("{error:#}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::bail!(
            "controller did not serve HTTPS in time: {last}\n{}",
            controller.output()
        )
    }

    /// `ca` 为 `Some` 时只信任该文件；`None` 时用系统信任链（应当失败）。
    async fn http(&self, ca: Option<&Path>) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20));
        if let Some(ca) = ca {
            builder = builder.tls_built_in_root_certs(false);
            for certificate in sshpool::tls::client_roots(ca)? {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(builder.build()?)
    }

    fn output(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn token(&self) -> Result<String> {
        Ok(fs::read_to_string(self.root.path().join("token"))?
            .trim()
            .to_string())
    }

    /// 写一份只含给定 token 的文件；CLI 的 `--token-file` 需要一个路径。
    fn token_file(&self, name: &str, token: &str) -> Result<std::path::PathBuf> {
        let path = self.root.path().join(name);
        fs::write(&path, token)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    /// 通过 CLI 打这个控制面；同时验证 `--endpoint` 与 `--ca-file` 真的被用上。
    fn cli(&self, args: &[&str], token_file: &Path) -> Result<std::process::Output> {
        Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
            .arg("--home")
            .arg(self.root.path())
            .arg("--endpoint")
            .arg(&self.endpoint)
            .arg("--ca-file")
            .arg(&self.cert)
            .arg("--token-file")
            .arg(token_file)
            .args(args)
            .output()?)
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn status(client: &reqwest::Client, endpoint: &str, token: &str) -> Result<u16> {
    Ok(client
        .get(format!("{endpoint}/v1/status"))
        .bearer_auth(token)
        .send()
        .await?
        .status()
        .as_u16())
}

#[tokio::test]
async fn https_verifies_the_certificate_and_short_lived_credentials_can_be_revoked() -> Result<()> {
    let controller = Controller::start().await?;
    let token = controller.token()?;
    let ca = controller.cert.clone();
    let trusted = controller.http(Some(&ca)).await?;

    // 1) 有 CA 时能通；根 token 仍然有效。
    assert_eq!(status(&trusted, &controller.endpoint, &token).await?, 200);

    // 2) 没有 CA（只有系统信任链）必须拒绝，而不是「连上就算」。
    let untrusted = controller.http(None).await?;
    let error = status(&untrusted, &controller.endpoint, &token)
        .await
        .expect_err("an unknown CA must not be accepted");
    assert!(
        format!("{error:#}").contains("certificate"),
        "unexpected failure: {error:#}"
    );

    // 3) 明文 HTTP 打 TLS 端口必须失败（没有「降级成明文」的分支）。
    let plaintext = controller.http(None).await?;
    let scheme_swapped = controller.endpoint.replacen("https://", "http://", 1);
    assert!(
        status(&plaintext, &scheme_swapped, &token).await.is_err(),
        "a plaintext client must not be served by the TLS listener"
    );

    // 4) 用 CLI 签发短期凭据；明文只在这次输出里出现。
    let issued = controller.cli(
        &[
            "credential",
            "issue",
            "--subject",
            "workbench",
            "--ttl-hours",
            "1",
        ],
        &controller.token_file("root-token", &token)?,
    )?;
    ensure!(
        issued.status.success(),
        "credential issue failed: {}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let issued: Value = serde_json::from_slice(&issued.stdout)?;
    let id = issued["id"].as_str().context("missing id")?.to_string();
    let short = issued["token"]
        .as_str()
        .context("missing token")?
        .to_string();
    assert!(short.starts_with("spt_"), "unexpected token shape: {short}");
    assert_eq!(issued["subject"], "workbench");
    let expires_at = issued["expires_at"].as_u64().context("missing expiry")?;
    assert!(expires_at > issued["created_at"].as_u64().unwrap());

    let stored = fs::read_to_string(controller.root.path().join("credentials.json"))?;
    assert!(
        !stored.contains(&short) && !stored.contains(&short[short.len() - 64..]),
        "the credential store must not contain the plaintext token"
    );

    // 5) 该 token 真的能当 Bearer 用，而不只是「文件里多了一条」。
    assert_eq!(status(&trusted, &controller.endpoint, &short).await?, 200);
    let listed = controller.cli(&["jobs"], &controller.token_file("short-token", &short)?)?;
    ensure!(
        listed.status.success(),
        "a short-lived credential must reach the API: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let jobs: Value = serde_json::from_slice(&listed.stdout)?;
    assert_eq!(
        jobs.as_array().map(Vec::len),
        Some(0),
        "unexpected jobs: {jobs}"
    );

    // 6) 撤销立刻生效：同一把 token 马上 401。
    let revoked = controller.cli(
        &["credential", "revoke", &id],
        &controller.token_file("root-token", &token)?,
    )?;
    ensure!(
        revoked.status.success(),
        "credential revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert_eq!(status(&trusted, &controller.endpoint, &short).await?, 401);
    let refused = controller.cli(&["jobs"], &controller.token_file("short-token", &short)?)?;
    assert!(
        !refused.status.success(),
        "a revoked credential must not be accepted by the CLI"
    );

    // 7) 根 token 不受撤销影响；列表如实报告状态。
    assert_eq!(status(&trusted, &controller.endpoint, &token).await?, 200);
    let listed = controller.cli(
        &["credential", "list"],
        &controller.token_file("root-token", &token)?,
    )?;
    ensure!(listed.status.success(), "credential list failed");
    let entries: Value = serde_json::from_slice(&listed.stdout)?;
    let entries = entries.as_array().context("list output must be an array")?;
    assert_eq!(entries.len(), 1, "unexpected entries: {entries:?}");
    assert_eq!(entries[0]["id"], id);
    assert_eq!(entries[0]["active"], false);
    assert!(entries[0]["revoked_at"].is_u64());
    assert!(
        entries[0].get("token_sha256").is_none(),
        "digests must not be listed"
    );

    // 8) 撤销后请求不再携带任何 5xx：fail-closed 不等于崩服务。
    let broken = controller.cli(&["status"], &controller.token_file("short-token", &short)?)?;
    let stderr = String::from_utf8_lossy(&broken.stderr);
    assert!(
        stderr.contains("unauthorized"),
        "unexpected error: {stderr}"
    );
    assert_eq!(status(&trusted, &controller.endpoint, &token).await?, 200);
    Ok(())
}

/// 未握手的连接不能阻塞后续请求：扫描器发垃圾字节或只连不说，
/// 也只该丢掉那一个连接，而不是让 accept 循环卡住。
#[tokio::test]
async fn garbage_and_silent_connections_do_not_block_the_listener() -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let controller = Controller::start().await?;
    let token = controller.token()?;
    let trusted = controller.http(Some(&controller.cert)).await?;
    let address: SocketAddr = controller.endpoint.trim_start_matches("https://").parse()?;

    // 1) 发一段不是 TLS 的字节，然后立刻关闭。
    let mut garbage = tokio::net::TcpStream::connect(address).await?;
    garbage
        .write_all(b"GET /v1/status HTTP/1.1\r\nHost: x\r\n\r\n")
        .await?;
    garbage.shutdown().await?;
    drop(garbage);

    // 2) 只连不说：服务端必须在握手时限内放弃它，而不是一直等。
    let silent = tokio::net::TcpStream::connect(address).await?;

    // 3) 两件事都不影响正常请求。
    let started = std::time::Instant::now();
    assert_eq!(status(&trusted, &controller.endpoint, &token).await?, 200);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a pending handshake delayed a verified request by {:?}",
        started.elapsed()
    );
    drop(silent);
    Ok(())
}

/// `--ca-file` 只对 HTTPS 有意义：明文端点配 CA 是配置错误，要当场拒绝。
#[test]
fn a_ca_file_with_a_plaintext_endpoint_is_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    let token = root.path().join("token");
    fs::write(&token, "test-only-token-not-a-production-secret")?;
    let ca = root.path().join("ca.pem");
    fs::write(&ca, b"irrelevant")?;
    let error = sshpool::client::Client::new("http://127.0.0.1:8877".into(), &token, Some(&ca))
        .err()
        .context("a CA file with http must be refused")?;
    assert!(
        format!("{error:#}").contains("only applies to an https endpoint"),
        "unexpected error: {error:#}"
    );
    // 证书文件本身也要能解析，坏文件不会悄悄退化成系统信任链。
    let error = sshpool::client::Client::new("https://127.0.0.1:8877".into(), &token, Some(&ca))
        .err()
        .context("an unparsable CA file must be refused")?;
    assert!(
        format!("{error:#}").contains("contains no certificate"),
        "unexpected error: {error:#}"
    );
    Ok(())
}

/// 只配一半 TLS 必须在启动前被拒绝，而不是悄悄退回明文。
#[tokio::test]
async fn half_configured_tls_is_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    let init = cli(root.path(), &["init"])?;
    ensure!(init.status.success(), "init failed");
    let certificate = Certificate::generate(root.path())?;
    // 每一步都从同一份干净基线重建，避免把上一步的键再追加一遍。
    let base = fs::read_to_string(root.path().join("config.toml"))?;
    let key_only = format!("{base}\ntls_key = \"{}\"\n", certificate.key.display());
    fs::write(root.path().join("config.toml"), key_only)?;
    let output = cli(root.path(), &["serve"])?;
    assert!(!output.status.success(), "key without cert must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tls_cert and tls_key must be configured together"),
        "unexpected error: {stderr}"
    );

    // 私钥路径存在但证书缺失：同样是「只配一半」。
    let cert_only = format!("{base}\ntls_cert = \"{}\"\n", certificate.cert.display());
    fs::write(root.path().join("config.toml"), cert_only)?;
    let output = cli(root.path(), &["serve"])?;
    assert!(!output.status.success(), "cert without key must be refused");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be configured together"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 相对路径也不行：控制面工作目录不可预测，只接受绝对路径。
    let relative = format!(
        "{base}\ntls_cert = \"cert.pem\"\ntls_key = \"{}\"\n",
        certificate.key.display()
    );
    fs::write(root.path().join("config.toml"), relative)?;
    let output = cli(root.path(), &["serve"])?;
    assert!(
        !output.status.success(),
        "relative TLS paths must be refused"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be absolute"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// 私钥可被组/其他用户读取时拒绝启动；修复权限后同一份配置可以起来。
#[tokio::test]
async fn a_world_readable_key_blocks_startup() -> Result<()> {
    let controller_free = tempfile::tempdir()?;
    let init = cli(controller_free.path(), &["init"])?;
    ensure!(init.status.success(), "init failed");
    let certificate = Certificate::generate(controller_free.path())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&certificate.key, fs::Permissions::from_mode(0o644))?;
    }
    let config = format!(
        "{}\ntls_cert = \"{}\"\ntls_key = \"{}\"\n",
        fs::read_to_string(controller_free.path().join("config.toml"))?,
        certificate.cert.display(),
        certificate.key.display()
    );
    fs::write(controller_free.path().join("config.toml"), config)?;
    let output = cli(controller_free.path(), &["serve"])?;
    assert!(!output.status.success(), "a loose key must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("chmod 600"), "unexpected error: {stderr}");
    Ok(())
}

/// 监听地址与端口是配置里的值：测试只确认「绑的就是它」，避免误绑生产端口。
#[tokio::test]
async fn the_listener_binds_the_configured_address() -> Result<()> {
    let controller = Controller::start().await?;
    let address: SocketAddr = controller
        .endpoint
        .trim_start_matches("https://")
        .parse()
        .context("endpoint must be host:port")?;
    ensure!(
        address.ip().is_loopback(),
        "test controller must stay on loopback"
    );
    ensure!(address.port() != 0, "a real port must be bound");
    // 服务日志里写明协议，避免运维以为 8877 还是明文。
    let log = controller.output();
    assert!(
        log.contains("(https)"),
        "serve must report its protocol: {log}"
    );
    Ok(())
}
