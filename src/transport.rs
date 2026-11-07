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
pub async fn upload(node: &Node, script: &str, source: &Path) -> Result<()> {
    upload_capture(node, script, source, 120).await?;
    Ok(())
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
