//! 启动计划、实际封存结果和双端准入规则。
use crate::{config, config::Node};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

const KERNEL: &str = "7.1.0-rc3-sshpool-gvm-pf24";

/// 远端只读输入；摘要必须来自用户已核验的运行时及客体镜像。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub path: PathBuf,
    pub sha256: String,
}

/// 专用实验节点身份与输入，不登记为普通 Worker，也不挂载业务磁盘。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub ssh: String,
    pub machine_id_sha256: String,
    pub qemu: Image,
    pub guest_kernel: Image,
    pub initramfs: Image,
    pub firmware: PathBuf,
}

/// 当前仅支持两个 PF24 x86 节点、四个客体 CPU 和 256 MiB 无磁盘客体。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub require_kernel: String,
    pub peers: [Peer; 2],
    pub addresses: [Ipv4Addr; 2],
    pub run_seconds: u64,
    pub ssh_port: Option<u16>,
}

/// 由远端从实际复制字节计算的封存结果；seals 必须包含禁止写入、伸缩及改封条。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Frozen {
    pub sha256: String,
    pub bytes: u64,
    pub seals: u32,
}

/// 三个镜像都绑定到仍保持打开的不可修改 fd。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Images {
    pub qemu: Frozen,
    pub guest_kernel: Frozen,
    pub initramfs: Frozen,
}

/// 同一 SSH 会话内的准备凭据；token 不可跨实例重放。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub node: usize,
    pub run_id: String,
    pub plan_sha256: String,
    pub machine_id_sha256: String,
    pub kernel: String,
    pub images: Images,
    pub token: String,
    pub directory: String,
}

/// 每个节点保留原始协议结果和 SSH 退出，缺失退出不能表示清理成功。
#[derive(Default, Debug, Serialize)]
pub struct Outcome {
    pub prepared: Option<Prepared>,
    pub started: Option<Value>,
    pub finished: Option<Value>,
    pub ssh_exit: Option<i32>,
    pub transport_error: Option<String>,
}

/// 启动报告只说明准入与进程生命周期；客体功能和持久化仍须独立验收。
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub run_id: String,
    pub plan_sha256: String,
    pub worker_sha256: String,
    pub admission_passed: bool,
    pub commit_sent: [bool; 2],
    pub nodes: [Outcome; 2],
    pub errors: Vec<String>,
    pub full_ssi_accepted: bool,
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(super) fn ssh_node(peer: &Peer, index: usize, ssh_config: Option<&Path>) -> Result<Node> {
    let node = Node {
        name: format!("ssi-launch-{index}"),
        ssh: peer.ssh.clone(),
        ssh_config: ssh_config.map(Path::to_path_buf),
        images: Vec::new(),
        enabled: false,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
        slo: Default::default(),
    };
    config::validate_node(&node)?;
    Ok(node)
}

/// 在连接任何主机之前拒绝不完整计划、重复身份或不受支持的实验边界。
pub fn validate(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == 1 && plan.require_kernel == KERNEL,
        "需要协议 1 的专用 PF24 实验计划"
    );
    ensure!(
        (1..=900).contains(&plan.run_seconds),
        "运行期限必须为 1–900 秒"
    );
    ensure!(
        plan.ssh_port.is_none_or(|port| port >= 1024),
        "SSH 转发只允许非特权回环端口"
    );
    ensure!(
        plan.addresses[0] != plan.addresses[1]
            && plan.addresses.iter().all(|ip| !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_broadcast()),
        "需要两个有效节点地址"
    );
    ensure!(
        plan.peers[0].ssh != plan.peers[1].ssh
            && plan.peers[0].machine_id_sha256 != plan.peers[1].machine_id_sha256,
        "节点别名与身份必须不同"
    );
    for (index, peer) in plan.peers.iter().enumerate() {
        ssh_node(peer, index, None)?;
        ensure!(
            is_digest(&peer.machine_id_sha256) && peer.firmware.is_absolute(),
            "节点身份或固件路径无效"
        );
        for image in [&peer.qemu, &peer.guest_kernel, &peer.initramfs] {
            ensure!(
                image.path.is_absolute() && is_digest(&image.sha256),
                "镜像需要绝对路径和 SHA-256"
            );
        }
    }
    Ok(())
}

/// 只接受本计划的两个实际封存报告；版本不一致时两端都还没有执行 QEMU。
pub fn assess(plan: &Plan, peers: &[Prepared; 2], run_id: &str, plan_sha256: &str) -> Result<()> {
    for (index, prepared) in peers.iter().enumerate() {
        let peer = &plan.peers[index];
        ensure!(
            prepared.node == index
                && prepared.run_id == run_id
                && prepared.plan_sha256 == plan_sha256
                && prepared.machine_id_sha256 == peer.machine_id_sha256
                && prepared.kernel == plan.require_kernel
                && is_digest(&prepared.token),
            "准备报告身份、计划或会话不符"
        );
        for (image, frozen) in [
            (&peer.qemu, &prepared.images.qemu),
            (&peer.guest_kernel, &prepared.images.guest_kernel),
            (&peer.initramfs, &prepared.images.initramfs),
        ] {
            ensure!(
                frozen.sha256 == image.sha256
                    && frozen.seals == 15
                    && (1..=256 * 1024 * 1024).contains(&frozen.bytes),
                "实际输入没有按计划完整封存"
            );
        }
    }
    ensure!(peers[0].token != peers[1].token, "准备 token 不能重复");
    ensure!(
        peers[0].images == peers[1].images,
        "SSI runtime/image mismatch before commit; neither peer may execute"
    );
    Ok(())
}

pub(super) fn check_started(prepared: &Prepared, value: &Value) -> Result<()> {
    ensure!(
        value["pid"].as_u64().is_some_and(|pid| pid > 1)
            && value["sealed_executable"] == true
            && serde_json::from_value::<Images>(value["images"].clone())? == prepared.images,
        "启动事件未绑定已封存的输入"
    );
    Ok(())
}

pub(super) fn check_finished(
    outcome: &Outcome,
    value: &Value,
    run_id: &str,
    node: usize,
) -> Result<()> {
    ensure!(
        value["schema"] == 1 && value["run_id"] == run_id && value["node"] == node,
        "结束事件身份不符"
    );
    ensure!(
        value["errors"]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
            && value["forced_cleanup"]
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
        "结束事件缺少错误或清理明细"
    );
    let times = (value["started_ns"].as_u64(), value["finished_ns"].as_u64());
    ensure!(
        matches!(times, (Some(start), Some(end)) if start > 0 && end > start),
        "结束事件缺少有效时间边界"
    );
    if let Some(prepared) = &outcome.prepared {
        ensure!(
            value["directory"] == prepared.directory,
            "运行目录与准备记录不符"
        );
    }
    match &outcome.started {
        Some(started) => {
            ensure!(
                value["qemu_started"] == true
                    && value["qemu_pid"] == started["pid"]
                    && value["qemu_exit"].as_i64().is_some(),
                "缺少已启动实例的退出记录"
            );
            for key in ["stdout_sha256", "stderr_sha256"] {
                ensure!(
                    value[key].as_str().is_some_and(is_digest),
                    "缺少实例日志摘要"
                );
            }
        }
        None => ensure!(
            value["qemu_started"] == false && value["qemu_exit"].is_null(),
            "实例执行与已观察的启动事件不符"
        ),
    }
    Ok(())
}
