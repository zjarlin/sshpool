//! SSH 控制会话与有界原始日志采集。
use super::WORKER;
use crate::{config::Node, transport};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::ChildStdin,
    sync::mpsc,
    task::JoinHandle,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    schema: u32,
    run_id: String,
    node: usize,
    pub(super) event: String,
    pub(super) data: Value,
}
pub(super) enum Event {
    Message(usize, Message),
    Closed(usize, Result<i32>),
}
pub(super) struct Agent {
    pub(super) stdin: Option<ChildStdin>,
    task: JoinHandle<()>,
}

pub(super) async fn send(agent: &mut Agent, value: Value) -> Result<()> {
    let input = agent.stdin.as_mut().context("SSH input already closed")?;
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(3), input.write_all(&bytes)).await??;
    Ok(())
}

pub(super) async fn start(
    node: &Node,
    index: usize,
    run_id: &str,
    output: &Path,
    trace: bool,
    events: mpsc::UnboundedSender<Event>,
) -> Result<Agent> {
    let prefix = if trace {
        "strace -f -q -ttt -s 65536 -e trace=process,ioctl,memfd_create,fcntl -o /dev/stderr "
    } else {
        ""
    };
    let script = format!("{prefix}python3 -u -c {}", transport::quote(WORKER));
    let mut child = transport::command(node, &script)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdin = child.stdin.take().context("missing worker stdin")?;
    let stdout = child.stdout.take().context("missing worker stdout")?;
    let mut stderr = child.stderr.take().context("missing worker stderr")?;
    let mut responses =
        tokio::fs::File::create(output.join(format!("node{index}-control.jsonl"))).await?;
    let mut errors =
        tokio::fs::File::create(output.join(format!("node{index}-stderr.log"))).await?;
    let expected_run = run_id.to_owned();
    let task = tokio::spawn(async move {
        let receive = async {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let count = (&mut reader)
                    .take(65537)
                    .read_until(b'\n', &mut line)
                    .await?;
                if count == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
                ensure!(
                    count <= 65536 && line.last() == Some(&b'\n'),
                    "worker response truncated or too large"
                );
                responses.write_all(&line).await?;
                let message: Message = serde_json::from_slice(&line)?;
                ensure!(
                    message.schema == 1 && message.node == index && message.run_id == expected_run,
                    "worker response identity mismatch"
                );
                events
                    .send(Event::Message(index, message))
                    .map_err(|_| anyhow::anyhow!("controller closed"))?;
            }
        };
        let capture = async {
            let mut count = 0;
            let mut buffer = [0; 8192];
            loop {
                let size = stderr.read(&mut buffer).await?;
                if size == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
                count += size;
                ensure!(count <= 32 * 1024 * 1024, "worker stderr exceeded 32 MiB");
                errors.write_all(&buffer[..size]).await?;
            }
        };
        let result = tokio::try_join!(receive, capture, async {
            Ok::<_, anyhow::Error>(child.wait().await?)
        })
        .map(|(_, _, status)| status.code().unwrap_or(255));
        let _ = events.send(Event::Closed(index, result));
    });
    Ok(Agent {
        stdin: Some(stdin),
        task,
    })
}

// 控制任务被取消时同时停止本地 SSH，远端从 EOF 或租约期限回收本次实例。
impl Drop for Agent {
    fn drop(&mut self) {
        self.stdin.take();
        self.task.abort();
    }
}
