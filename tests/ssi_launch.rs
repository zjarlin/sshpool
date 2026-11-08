use anyhow::Result;
use sshpool::ssi_launch::{self, Frozen, Image, Images, Peer, Plan, Prepared};
use std::path::PathBuf;

fn image(name: &str, value: char) -> Image {
    Image {
        path: PathBuf::from(format!("/lab/{name}")),
        sha256: value.to_string().repeat(64),
    }
}

fn plan() -> Plan {
    Plan {
        schema: 1,
        require_kernel: "7.1.0-rc3-sshpool-gvm-pf24".into(),
        peers: std::array::from_fn(|node| Peer {
            ssh: format!("lab-{node}"),
            machine_id_sha256: (node + 1).to_string().repeat(64),
            qemu: image("qemu", 'a'),
            guest_kernel: image("kernel", 'b'),
            initramfs: image("initramfs", 'c'),
            firmware: PathBuf::from("/lab/firmware"),
        }),
        addresses: [[192, 0, 2, 10].into(), [192, 0, 2, 11].into()],
        run_seconds: 60,
        ssh_port: Some(22230),
    }
}

fn prepared(plan: &Plan) -> [Prepared; 2] {
    std::array::from_fn(|node| {
        let frozen = |image: &Image| Frozen {
            sha256: image.sha256.clone(),
            bytes: 1234,
            seals: 15,
        };
        let peer = &plan.peers[node];
        Prepared {
            node,
            run_id: "run-identity".into(),
            plan_sha256: "plan-digest".into(),
            machine_id_sha256: peer.machine_id_sha256.clone(),
            kernel: plan.require_kernel.clone(),
            images: Images {
                qemu: frozen(&peer.qemu),
                guest_kernel: frozen(&peer.guest_kernel),
                initramfs: frozen(&peer.initramfs),
            },
            token: (node + 4).to_string().repeat(64),
            directory: format!("/lab/run/{node}"),
        }
    })
}

#[test]
fn actual_both_peer_reports_must_agree_before_commit() -> Result<()> {
    let mut plan = plan();
    ssi_launch::validate(&plan)?;
    ssi_launch::assess(&plan, &prepared(&plan), "run-identity", "plan-digest")?;
    plan.peers[1].qemu.sha256 = "d".repeat(64);
    // 两个文件各自符合清单仍不够；实际版本不同必须在 commit 前失败。
    ssi_launch::validate(&plan)?;
    assert!(
        ssi_launch::assess(&plan, &prepared(&plan), "run-identity", "plan-digest")
            .is_err_and(|error| error.to_string().contains("before commit"))
    );
    Ok(())
}

#[test]
fn stale_repeated_unsealed_or_different_guest_reports_are_rejected() {
    let plan = plan();
    for fault in 0..8 {
        let mut peers = prepared(&plan);
        match fault {
            0 => peers[1].run_id = "old-run".into(),
            1 => peers[1].plan_sha256 = "old-plan".into(),
            2 => peers[1].node = 0,
            3 => peers[1].token = peers[0].token.clone(),
            4 => peers[1].images.qemu.seals = 7,
            5 => peers[1].images.qemu.bytes = 0,
            6 => peers[1].images.initramfs.sha256 = "d".repeat(64),
            _ => peers[1].machine_id_sha256 = peers[0].machine_id_sha256.clone(),
        }
        assert!(
            ssi_launch::assess(&plan, &peers, "run-identity", "plan-digest").is_err(),
            "fault {fault}"
        );
    }
}

#[tokio::test]
async fn invalid_plan_never_opens_ssh_or_creates_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("must-not-exist");
    let mut plan = plan();
    plan.peers[1].machine_id_sha256 = plan.peers[0].machine_id_sha256.clone();
    assert!(
        ssi_launch::launch(plan, None, &output, false)
            .await
            .is_err()
    );
    assert!(!output.exists());
    Ok(())
}

#[test]
fn unsafe_or_ambiguous_plans_fail_closed() {
    for fault in 0..7 {
        let mut plan = plan();
        match fault {
            0 => plan.run_seconds = 901,
            1 => plan.ssh_port = Some(22),
            2 => plan.addresses[1] = plan.addresses[0],
            3 => plan.peers[0].qemu.path = "relative-qemu".into(),
            4 => plan.peers[1].ssh = "-oProxyCommand=bad".into(),
            5 => plan.peers[0].qemu.sha256 = "unknown".into(),
            _ => plan.require_kernel = "stock".into(),
        }
        assert!(ssi_launch::validate(&plan).is_err(), "fault {fault}");
    }
}

#[test]
fn incomplete_or_inconsistent_lifecycle_cannot_succeed() -> Result<()> {
    use serde_json::json;
    use sshpool::ssi_launch::{Outcome, Report};
    let plan = plan();
    for fault in 0..11 {
        let peers = prepared(&plan);
        let nodes = std::array::from_fn(|index| {
            let peer = peers[index].clone();
            Outcome {
                started: Some(
                    json!({"pid":100 + index,"sealed_executable":true,"images":peer.images}),
                ),
                finished: Some(json!({"schema":1,"run_id":"run-identity","node":index,
                    "directory":peer.directory,"qemu_started":true,"qemu_pid":100 + index,"qemu_exit":0,
                    "started_ns":1,"finished_ns":2,"errors":[],"forced_cleanup":[],
                    "stdout_sha256":"a".repeat(64),"stderr_sha256":"b".repeat(64)})),
                prepared: Some(peer),
                ssh_exit: Some(0),
                transport_error: None,
            }
        });
        let mut report = Report {
            schema: 1,
            run_id: "run-identity".into(),
            plan_sha256: "plan-digest".into(),
            worker_sha256: "c".repeat(64),
            admission_passed: true,
            commit_sent: [true, true],
            nodes,
            errors: Vec::new(),
            full_ssi_accepted: false,
        };
        assert!(ssi_launch::processes_exited_successfully(&report));
        let node = &mut report.nodes[1];
        match fault {
            0 => node.started = None,
            1 => node.finished = None,
            2 => node.ssh_exit = None,
            3 => node.transport_error = Some("disconnected".into()),
            4 => report.commit_sent[1] = false,
            5 => {
                node.started
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing start"))?["sealed_executable"] =
                    json!(false)
            }
            6 => {
                node.finished
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing finish"))?["qemu_pid"] = json!(999)
            }
            7 => {
                node.finished
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing finish"))?["run_id"] = json!("old")
            }
            8 => {
                node.finished
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing finish"))?["finished_ns"] = json!(1)
            }
            9 => {
                node.finished
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing finish"))?["forced_cleanup"] =
                    json!(["SIGTERM"])
            }
            _ => {
                node.finished
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("missing finish"))?["stdout_sha256"] =
                    json!(null)
            }
        }
        assert!(
            !ssi_launch::processes_exited_successfully(&report),
            "fault {fault}"
        );
    }
    Ok(())
}
