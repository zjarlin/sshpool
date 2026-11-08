//! 显式实验计划的双端准入：封存实际输入后才发送执行许可，不提供故障接管。
mod model;
mod session;
use crate::archive::sha256_bytes;
use anyhow::{Context, Result};
pub use model::*;
use model::{check_finished, check_started, ssh_node};
use serde_json::json;
use session::{Agent, Event, send, start};
use std::{path::Path, time::Duration};
use tokio::{sync::mpsc, time::Instant};

const WORKER: &str = include_str!("ssi_launch_worker.py");

/// 双端准备后统一判定；心跳、控制端断连及显式中止只回收本次子进程组。
pub async fn launch(
    plan: Plan,
    ssh_config: Option<&Path>,
    output: &Path,
    trace: bool,
) -> Result<Report> {
    validate(&plan)?;
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(output)
        .context("报告目录必须不存在，且父目录已经存在")?;
    let plan_bytes = serde_json::to_vec(&plan)?;
    let mut report = Report {
        schema: 1,
        run_id: uuid::Uuid::new_v4().simple().to_string(),
        plan_sha256: sha256_bytes(&plan_bytes),
        worker_sha256: sha256_bytes(WORKER.as_bytes()),
        admission_passed: false,
        commit_sent: [false; 2],
        nodes: Default::default(),
        errors: Vec::new(),
        full_ssi_accepted: false,
    };
    std::fs::write(output.join("plan.json"), serde_json::to_vec_pretty(&plan)?)?;
    let (sender, mut receiver) = mpsc::channel(16);
    let mut agents: [Option<Agent>; 2] = [None, None];
    let mut closed = [false; 2];
    for index in 0..2 {
        let node = ssh_node(&plan.peers[index], index, ssh_config)?;
        match start(&node, index, &report.run_id, output, trace, sender.clone()).await {
            Ok(mut agent) => {
                let request = json!({"schema":1,"run_id":report.run_id,"node":index,
                    "plan_sha256":report.plan_sha256,"settings":plan});
                if let Err(error) = send(&mut agent, request).await {
                    report
                        .errors
                        .push(format!("node{index} prepare send: {error:#}"));
                }
                agents[index] = Some(agent);
            }
            Err(error) => {
                closed[index] = true;
                report
                    .errors
                    .push(format!("node{index} SSH start: {error:#}"));
            }
        }
    }
    drop(sender);
    let began = Instant::now();
    let mut stopped_at = None;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    while closed != [true, true] {
        tokio::select! {
            event = receiver.recv() => match event {
                Some(Event::Message(index, message)) => {
                    let outcome = &mut report.nodes[index];
                    match message.event.as_str() {
                        "prepared" if outcome.prepared.is_none() && !report.admission_passed => {
                            match serde_json::from_value(message.data) {
                                Ok(prepared) => outcome.prepared = Some(prepared),
                                Err(error) => report.errors.push(format!("node{index} prepared: {error}")),
                            }
                        }
                        "started" if report.commit_sent[index] && outcome.started.is_none() && outcome.finished.is_none() => {
                            let result = outcome.prepared.as_ref().context("missing preparation")
                                .and_then(|prepared| check_started(prepared, &message.data));
                            if let Err(error) = result {
                                report.errors.push(format!("node{index} started: {error:#}"));
                            }
                            outcome.started = Some(message.data);
                        }
                        "finished" if outcome.finished.is_none() => {
                            if let Err(error) = check_finished(outcome, &message.data, &report.run_id, index) {
                                report.errors.push(format!("node{index} finished: {error:#}"));
                            }
                            if !message.data["errors"].as_array().is_some_and(Vec::is_empty)
                                || !message.data["forced_cleanup"].as_array().is_some_and(Vec::is_empty) {
                                report.errors.push(format!("node{index} failed or required forced cleanup"));
                            }
                            outcome.finished = Some(message.data);
                        }
                        _ => report.errors.push(format!("node{index} unexpected event: {}", message.event)),
                    }
                }
                Some(Event::Closed(index, result)) => {
                    closed[index] = true;
                    match result {
                        Ok(code) => report.nodes[index].ssh_exit = Some(code),
                        Err(error) => report.nodes[index].transport_error = Some(format!("{error:#}")),
                    }
                    if report.nodes[index].finished.is_none() || (report.admission_passed && report.nodes[index].ssh_exit != Some(0)) {
                        report.errors.push(format!("node{index} ended without a successful complete lifecycle"));
                    }
                }
                None => { report.errors.push("worker event channel closed".into()); break; }
            },
            _ = tick.tick() => {
                let limit = if report.admission_passed { plan.run_seconds + 45 } else { 45 };
                if began.elapsed() > Duration::from_secs(limit) {
                    report.errors.push("controller observation deadline expired".into());
                }
                if report.admission_passed && stopped_at.is_none() {
                    for index in 0..2 {
                        if closed[index] { continue; }
                        if let (Some(agent), Some(prepared)) = (&mut agents[index], &report.nodes[index].prepared)
                            && let Err(error) = send(agent, json!({"run_id":report.run_id,"node":index,
                                "op":"keepalive","token":prepared.token})).await {
                            report.errors.push(format!("node{index} keepalive: {error:#}"));
                        }
                    }
                }
            },
            _ = tokio::signal::ctrl_c() => report.errors.push("interrupted by controller operator".into()),
        }
        if !report.admission_passed
            && report.errors.is_empty()
            && let [Some(first), Some(second)] =
                report.nodes.each_ref().map(|node| node.prepared.as_ref())
        {
            let peers = [first.clone(), second.clone()];
            match assess(&plan, &peers, &report.run_id, &report.plan_sha256) {
                Ok(()) => {
                    report.admission_passed = true;
                    for (index, agent) in agents.iter_mut().enumerate() {
                        if let Some(agent) = agent {
                            match send(agent, json!({"run_id":report.run_id,"node":index,"op":"commit","peers":peers})).await {
                                    Ok(()) => report.commit_sent[index] = true,
                                    Err(error) => {
                                        report.errors.push(format!("node{index} commit: {error:#}"));
                                        break;
                                    }
                                }
                        }
                    }
                }
                Err(error) => report.errors.push(format!("{error:#}")),
            }
        }
        if !report.errors.is_empty() && stopped_at.is_none() {
            stopped_at = Some(Instant::now());
            for (index, agent) in agents.iter_mut().enumerate() {
                if closed[index] {
                    continue;
                }
                if let Some(agent) = agent {
                    let token = report.nodes[index]
                        .prepared
                        .as_ref()
                        .map(|p| p.token.as_str());
                    if let Err(error) = send(
                        agent,
                        json!({"run_id":report.run_id,"node":index,"op":"abort",
                        "token":token,"reason":report.errors[0]}),
                    )
                    .await
                    {
                        report.errors.push(format!("node{index} abort: {error:#}"));
                    }
                    agent.stdin.take();
                }
            }
        }
        if stopped_at.is_some_and(|time| time.elapsed() > Duration::from_secs(25)) {
            report.errors.push(
                "remote cleanup was not confirmed; inspect the recorded run before retrying".into(),
            );
            break;
        }
    }
    drop(agents);
    std::fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

/// 退出零仅表示已准入的两个进程正常结束，不等于客体功能或完整 SSI 通过。
pub fn processes_exited_successfully(report: &Report) -> bool {
    report.admission_passed
        && report.commit_sent == [true, true]
        && report.errors.is_empty()
        && report.nodes.iter().enumerate().all(|(index, node)| {
            node.ssh_exit == Some(0)
                && node.transport_error.is_none()
                && node.prepared.as_ref().is_some_and(|prepared| {
                    node.started
                        .as_ref()
                        .is_some_and(|started| check_started(prepared, started).is_ok())
                })
                && node.finished.as_ref().is_some_and(|value| {
                    check_finished(node, value, &report.run_id, index).is_ok()
                        && value["qemu_started"] == true
                        && value["qemu_exit"] == 0
                        && value["errors"] == json!([])
                        && value["forced_cleanup"] == json!([])
                })
        })
}
