use crate::config::Node;
use anyhow::{Context, Result, bail, ensure};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};

/// 所有节点命令都通过系统 OpenSSH；保留已有密钥、跳板与主机校验。
pub fn command(node: &Node, script: &str) -> Command {
    let mut command = Command::new("ssh");
    command.args([
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=5",
        "-oServerAliveInterval=10",
        "-oServerAliveCountMax=3",
    ]);
    if let Some(config) = &node.ssh_config {
        command.arg("-F").arg(config);
    }
    let script = format!(
        "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; {script}"
    );
    command
        .arg(&node.ssh)
        .arg(format!("sh -c {}", quote(&script)));
    command.kill_on_drop(true);
    command
}
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn words(values: &[String]) -> String {
    values
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(" ")
}
async fn bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            return Ok(bytes);
        }
        ensure!(
            bytes.len() + count <= limit,
            "remote output exceeded {} bytes",
            limit
        );
        bytes.extend_from_slice(&chunk[..count]);
    }
}
/// 短命令只保留有界输出，并对整个 SSH 子进程设置超时。
pub async fn capture(node: &Node, script: &str, seconds: u64) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut child = command(node, script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        let (status, stdout, stderr) = tokio::try_join!(
            child.wait(),
            async {
                bounded(stdout, 1024 * 1024)
                    .await
                    .map_err(std::io::Error::other)
            },
            async { bounded(stderr, 65536).await.map_err(std::io::Error::other) }
        )?;
        Ok::<_, anyhow::Error>((status.code().unwrap_or(255), stdout, stderr))
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => {
            child.kill().await?;
            bail!("SSH command timed out after {seconds}s on {}", node.name)
        }
    }
}
pub async fn checked(node: &Node, script: &str, seconds: u64) -> Result<Vec<u8>> {
    let (code, stdout, stderr) = capture(node, script, seconds).await?;
    ensure!(
        code == 0,
        "{}: command exited {code}: {}",
        node.name,
        String::from_utf8_lossy(&stderr)
    );
    Ok(stdout)
}
/// 幂等命令的连接层重试上限。
///
/// 远端 sshd 在并发连接下会丢弃部分握手（实测 lima 并发 100 条时约 1/3 失败，
/// 报错为 `Connection timed out during banner exchange`）。这类失败发生在命令
/// 执行之前，重试不会改变命令语义。只对幂等命令启用：一旦命令可能已经执行
/// （`docker exec` 跑构建），重试就等于把「执行了但没收到回执」变成「又执行一次」。
pub const IDEMPOTENT_ATTEMPTS: usize = 3;

/// 幂等命令的连接层重试：只在「命令根本没跑起来」时重试，并把命令本身的结论原样返回。
///
/// 两个入口都要覆盖：`ssh` 既可能以 `Err` 超时返回，也可能正常退出并带回
/// **255**（OpenSSH 用它表示连接层错误，此时命令根本没跑）。只看 `Err` 会漏掉后者
/// —— 实测这正是「一次握手抖动就判任务中断」的来源。
///
/// 只允许用于**幂等**命令（只读核对、`docker stop`、标签校验后 `docker rm -f`）。
/// 有副作用的命令（`docker exec` 跑构建）绝不走这里：重试等于再执行一次。
pub async fn idempotent(
    node: &Node,
    script: &str,
    seconds: u64,
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut last = None;
    for attempt in 1..=IDEMPOTENT_ATTEMPTS {
        let retryable = attempt < IDEMPOTENT_ATTEMPTS;
        match capture(node, script, seconds).await {
            Ok((255, _, stderr)) if connection_only(&String::from_utf8_lossy(&stderr)) => {
                let message = format!(
                    "{}: command exited 255: {}",
                    node.name,
                    String::from_utf8_lossy(&stderr)
                );
                if !retryable {
                    return Err(anyhow::anyhow!("{message}"));
                }
                last = Some(anyhow::anyhow!("{message}"));
            }
            // 其他退出码是命令自己的结论（例如 no such container），不由传输层改写。
            Ok(value) => return Ok(value),
            Err(error) if retryable && connection_only(&format!("{error:#}")) => {
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("idempotent command never ran")))
}

/// 只读核对：重试仅限连接层失败，退出码非零不重试（那是命令本身的结论）。
pub async fn verified(node: &Node, script: &str, seconds: u64) -> Result<Vec<u8>> {
    let (code, stdout, stderr) = idempotent(node, script, seconds).await?;
    ensure!(
        code == 0,
        "{}: command exited {code}: {}",
        node.name,
        String::from_utf8_lossy(&stderr)
    );
    Ok(stdout)
}

/// 只接受「命令没跑起来」的连接层错误；执行超时与退出码失败都不算可重试。
fn connection_only(message: &str) -> bool {
    let message = message.to_lowercase();
    // 明确排除命令执行超时：那可能是远端已经在执行，重试会重复副作用。
    if message.contains("timed out after") {
        return false;
    }
    [
        "banner exchange",
        "connection refused",
        "connection reset",
        "connection closed",
        "broken pipe",
        "no route to host",
        "network is unreachable",
        "ssh: connect to host",
        "kex_exchange_identification",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

/// 上传项目归档；仅当失败发生在连接层时重试。
///
/// 重试安全：目标命令是 `tar -xf - -C /work`，把**同一份**归档解两次得到同一棵树，
/// 所以「传输中断后重发」不会留下半份源码。实测 lima 的 sshd 在家宽入口下会丢弃
/// 一部分握手（`Connection timed out during banner exchange`），不重试就会把这类
/// 一次性的环境抖动记成任务失败。
pub async fn upload(node: &Node, script: &str, source: &Path) -> Result<()> {
    let mut attempt = 1;
    loop {
        match upload_capture(node, script, source, 120).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                let message = format!("{error:#}");
                ensure!(
                    attempt < IDEMPOTENT_ATTEMPTS && connection_only(&message),
                    "{message}"
                );
                attempt += 1;
            }
        }
    }
}

/// 上传到显式受限的远端命令并保留有界标准输出，供原子写入后回报摘要。
pub async fn upload_capture(
    node: &Node,
    script: &str,
    source: &Path,
    seconds: u64,
) -> Result<Vec<u8>> {
    let mut child = command(node, script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().context("missing stdin")?;
    let stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        let mut file = tokio::fs::File::open(source).await?;
        let transfer = async move {
            tokio::io::copy(&mut file, &mut stdin).await?;
            stdin.shutdown().await?;
            // ChildStdin 的 shutdown 不负责关闭管道；必须释放句柄发送 EOF。
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        let (_, status, output, errors) = tokio::try_join!(
            transfer,
            child.wait(),
            async { bounded(stdout, 65536).await.map_err(std::io::Error::other) },
            async { bounded(stderr, 65536).await.map_err(std::io::Error::other) }
        )?;
        ensure!(
            status.success(),
            "input upload failed: {}",
            String::from_utf8_lossy(&errors)
        );
        Ok::<_, anyhow::Error>(output)
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => {
            child.kill().await?;
            bail!("source upload timed out")
        }
    }
}

/// 只执行调用方构造的固定远端读取命令，并把 stdout 写入本次创建的临时文件。
pub async fn download(node: &Node, script: &str, destination: &Path, seconds: u64) -> Result<()> {
    let mut child = command(node, script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().context("missing stdout")?;
    let stderr = child.stderr.take().context("missing stderr")?;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .await?;
        let transfer = async {
            tokio::io::copy(&mut stdout, &mut file).await?;
            file.flush().await?;
            file.sync_all().await?;
            Ok::<_, std::io::Error>(())
        };
        let (_, status, errors) = tokio::try_join!(transfer, child.wait(), async {
            bounded(stderr, 65536).await.map_err(std::io::Error::other)
        })?;
        ensure!(
            status.success(),
            "remote download failed: {}",
            String::from_utf8_lossy(&errors)
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => {
            child.kill().await?;
            bail!("remote download timed out")
        }
    }
}
pub fn spawn(node: &Node, script: &str) -> Result<Child> {
    Ok(command(node, script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

#[cfg(test)]
mod tests {
    use super::connection_only;

    /// 握手阶段的失败发生在命令执行之前，重试不改变语义。
    #[test]
    fn handshake_failures_are_retryable() {
        for message in [
            "live: command exited 255: Connection timed out during banner exchange",
            "ssh: connect to host 127.0.0.1 port 2223: Connection refused",
            "Connection reset by peer",
        ] {
            assert!(connection_only(message), "{message}");
        }
    }

    /// 命令可能已经在远端跑过；重试会重复副作用，所以绝不重试。
    #[test]
    fn timeouts_and_command_failures_are_never_retried() {
        for message in [
            "SSH command timed out after 20s on live",
            "live: command exited 1: docker: no such object",
            // 退出码 255 但信息不是连接层的，同样不能重试。
            "live: command exited 255: remote closed unexpectedly after exec",
            "container label mismatch; refusing to treat it as this job",
        ] {
            assert!(!connection_only(message), "{message}");
        }
    }
}
