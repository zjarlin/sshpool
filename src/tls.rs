//! 控制面 HTTPS：只做「校验对端证书」这一件事，不提供关闭校验的开关。
//!
//! 服务端用配置里给出的证书链和私钥；客户端要么走系统信任链，要么显式指定
//! 一份 CA 文件（自建 CA、内网 ACME 或测试证书）。没有「跳过校验」选项：
//! 跨不可信网络时，能关掉的校验等于没有校验。
use anyhow::{Context, Result, ensure};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    fs,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// 握手必须有时限：否则一个只连不说的客户端就能独占 `accept()` 循环，
/// 让整个控制面停止接受新连接。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)
        .with_context(|| format!("cannot read TLS certificate {}", path.display()))?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("cannot parse TLS certificate {}", path.display()))?;
    ensure!(
        !certificates.is_empty(),
        "TLS certificate file {} contains no certificate",
        path.display()
    );
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    // 私钥被同组/其他用户可读是真实泄露风险，和 OpenSSH 一样直接拒绝启动。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("cannot stat TLS key {}", path.display()))?
            .permissions()
            .mode();
        ensure!(
            mode & 0o077 == 0,
            "TLS key {} must not be readable by group or others (chmod 600)",
            path.display()
        );
    }
    let file =
        fs::File::open(path).with_context(|| format!("cannot read TLS key {}", path.display()))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("cannot parse TLS key {}", path.display()))?
        .with_context(|| format!("TLS key file {} contains no private key", path.display()))?;
    Ok(key)
}

/// 构造服务端配置；证书或私钥有任何问题都在启动时失败，不进入「降级为明文」的分支。
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let certificates = load_certificates(cert)?;
    let key = load_private_key(key)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("TLS certificate does not match the private key")?;
    // 同时支持 HTTP/2 与 HTTP/1.1；两条协议栈都由 axum 的 serve 负责。
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 同时进行中的握手数上限。
///
/// 太少会在真实并发下排队；太多则让扫描器用无数据连接占满任务与内存。
/// 握手本身有时限，所以最坏情况是 `MAX_PENDING_HANDSHAKES × HANDSHAKE_TIMEOUT`。
const MAX_PENDING_HANDSHAKES: usize = 64;

/// 包一层 TLS 的监听器，交给 `axum::serve` 使用。
///
/// 握手在独立任务里完成，绝不占用 `accept()` 循环：`axum::serve` 每次只调用一次
/// `accept()`，如果在里面等握手，一个只连不说的客户端就能让整个控制面停止接受连接。
pub struct TlsListener {
    established:
        tokio::sync::mpsc::Receiver<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>,
    local: io::Result<SocketAddr>,
}

impl TlsListener {
    pub fn new(inner: TcpListener, config: Arc<ServerConfig>) -> Self {
        let local = inner.local_addr();
        let (sender, receiver) = tokio::sync::mpsc::channel(MAX_PENDING_HANDSHAKES);
        tokio::spawn(accept_loop(inner, TlsAcceptor::from(config), sender));
        Self {
            established: receiver,
            local,
        }
    }
}

async fn accept_loop(
    inner: TcpListener,
    acceptor: TlsAcceptor,
    sender: tokio::sync::mpsc::Sender<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (stream, address) = match inner.accept().await {
            Ok(pair) => pair,
            // 连接级错误（对端已重置等）不算致命，和 axum 自带监听器一样重试。
            Err(error) => {
                eprintln!("sshpool: API accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        // 没有名额时在内核 backlog 里等待，而不是无限制地 spawn：
        // 扫描器最多只能拖住 64 个握手，真客户端仍会排在后面被接走。
        let permit = match permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let acceptor = acceptor.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    if sender.send((tls, address)).await.is_err() {
                        // 服务端已经停止接受连接；这条连接直接关闭。
                        return;
                    }
                }
                Ok(Err(error)) => {
                    eprintln!("sshpool: TLS handshake from {address} failed: {error}");
                }
                Err(_) => {
                    eprintln!("sshpool: TLS handshake from {address} timed out");
                }
            }
            drop(permit);
        });
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(established) = self.established.recv().await {
                return established;
            }
            // 握手任务全部退出（只在进程关闭时发生）：返回一个永不完成的等待，
            // 让 `axum::serve` 停在 accept 上而不是 panic 或忙轮询。
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.local {
            Ok(address) => Ok(*address),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }
}

/// 客户端信任根：只从给定 CA 文件加载，不叠加系统根，便于内网部署确定边界。
pub fn client_roots(ca: &Path) -> Result<Vec<reqwest::Certificate>> {
    let pem = fs::read(ca).with_context(|| format!("cannot read CA file {}", ca.display()))?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)
        .with_context(|| format!("cannot parse CA file {}", ca.display()))?;
    ensure!(
        !certificates.is_empty(),
        "CA file {} contains no certificate",
        ca.display()
    );
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(cert: &Path, key: &Path, mode: u32) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        fs::write(cert, certified.cert.pem()).unwrap();
        fs::write(key, certified.signing_key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key, fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn a_world_readable_key_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (cert, key) = (root.path().join("cert.pem"), root.path().join("key.pem"));
        write_pair(&cert, &key, 0o644);
        let error = server_config(&cert, &key).unwrap_err().to_string();
        assert!(error.contains("chmod 600"), "{error}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(server_config(&cert, &key).is_ok());
        }
    }

    #[test]
    fn an_empty_or_missing_certificate_fails_at_startup() {
        let root = tempfile::tempdir().unwrap();
        let (cert, key) = (root.path().join("cert.pem"), root.path().join("key.pem"));
        assert!(server_config(&cert, &key).is_err());
        write_pair(&cert, &key, 0o600);
        fs::write(&cert, "not a certificate").unwrap();
        assert!(server_config(&cert, &key).is_err());
        fs::write(&key, "not a key").unwrap();
        assert!(server_config(&cert, &key).is_err());
    }

    #[test]
    fn a_mismatched_key_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (cert, key) = (root.path().join("cert.pem"), root.path().join("key.pem"));
        write_pair(&cert, &key, 0o600);
        let other = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        fs::write(&key, other.signing_key.serialize_pem()).unwrap();
        assert!(server_config(&cert, &key).is_err());
    }
}
