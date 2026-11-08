//! 控制协议的流边界测试，不作为远端 QEMU 或双节点 SSI 的验收证据。
use super::*;
use serde_json::json;

async fn capture(bytes: &[u8]) -> Result<(Result<()>, Vec<String>, Vec<u8>)> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("control.jsonl");
    let file = tokio::fs::File::create(&path).await?;
    let (sender, mut receiver) = mpsc::channel(16);
    let read = async {
        let result = receive(bytes, file, "current", 0, &sender).await;
        drop(sender);
        result
    };
    let drain = async {
        let mut names = Vec::new();
        while let Some(event) = receiver.recv().await {
            if let Event::Message(_, message) = event {
                names.push(message.event);
            }
        }
        names
    };
    let (result, names) = tokio::join!(read, drain);
    Ok((result, names, tokio::fs::read(path).await?))
}

fn frame(run: &str, event: &str) -> String {
    let message = json!({"schema":1,"run_id":run,"node":0,"event":event,"data":{}});
    format!("{message}\n")
}

#[tokio::test]
async fn invalid_and_truncated_frames_preserve_the_received_bytes() -> Result<()> {
    for (bytes, error) in [
        (b"{\"schema\":".to_vec(), "truncated"),
        (vec![b' '; 65537], "too large"),
        (b"{}\n".to_vec(), "missing field"),
        (
            frame("previous", "prepared").into_bytes(),
            "identity mismatch",
        ),
    ] {
        let (result, names, raw) = capture(&bytes).await?;
        assert!(result.is_err_and(|problem| problem.to_string().contains(error)));
        assert!(names.is_empty());
        assert_eq!(raw, bytes);
    }
    Ok(())
}

#[tokio::test]
async fn consecutive_frames_are_delivered_in_order() -> Result<()> {
    let bytes = ["prepared", "started", "finished"]
        .map(|event| frame("current", event))
        .concat();
    let (result, names, raw) = capture(bytes.as_bytes()).await?;
    result?;
    assert_eq!(names, ["prepared", "started", "finished"]);
    assert_eq!(raw, bytes.as_bytes());
    Ok(())
}

#[tokio::test]
async fn small_frames_cannot_exceed_the_total_capture_limit() -> Result<()> {
    let bytes = frame("current", "prepared").repeat(CONTROL_LIMIT / 50);
    assert!(bytes.len() > CONTROL_LIMIT);
    let (result, names, raw) = capture(bytes.as_bytes()).await?;
    assert!(result.is_err_and(|problem| problem.to_string().contains("exceeded 256 KiB")));
    assert!(names.len() > 16);
    assert_eq!(raw, bytes.as_bytes()[..CONTROL_LIMIT]);
    Ok(())
}
