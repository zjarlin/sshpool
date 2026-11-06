//! SSI 实验前的原生 TSC 频率和接口检查；不登记 Worker、不安装内核、不执行客体。
use crate::{config, config::Node, transport};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};

/// SSH 探针输出的原始数据；缺字段或协议变化均须拒绝，不能补成成功默认值。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub schema: u32,
    pub collected_unix_ns: u64,
    pub system: String,
    pub arch: String,
    pub kernel: String,
    pub machine_id_sha256: String,
    pub logical_cpus: u32,
    pub memory_bytes: u64,
    pub api_version: u32,
    pub get_tsc_khz: u32,
    pub tsc_control: u32,
    pub adjust_clock: u32,
    pub tsc_adjust: bool,
    pub vcpus: Vec<Vcpu>,
    pub closed_fds: u32,
    pub errors: Vec<String>,
}

/// 新建的两个 vCPU 的实际频率与 VM 时钟读数，供 Rust 判定并保留原始证据。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vcpu {
    pub index: u32,
    pub tsc_khz: u32,
    pub offset_supported: bool,
    pub clock: u64,
    pub clock_flags: u32,
    pub realtime: u64,
    pub host_tsc: u64,
}

/// 每个 SSH 目标保留探测成功数据或失败原因；单端失败不能被从报告中丢弃。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub ssh: String,
    pub probe: Option<Probe>,
    pub error: Option<String>,
}

/// CLI 返回的兼容报告；检查通过只代表原生时钟前提成立，不授予启动或擦盘权限。
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub scope: &'static str,
    pub peers: Vec<Peer>,
    pub native_tsc_precheck_passed: bool,
    pub blockers: Vec<String>,
    pub physical_topology_verified: bool,
    pub running_clock_verified: bool,
    pub full_ssi_accepted: bool,
    pub remaining: Vec<&'static str>,
}

/// 检查两个 SSH 结果；不把缩放能力位当作已实现的缩放协议，也不累计资源容量。
pub fn assess(peers: Vec<Peer>) -> Report {
    let mut blockers = Vec::new();
    if peers.len() != 2 {
        blockers.push("当前实验协议要求恰好两个执行节点".into());
    }
    let mut identities = HashSet::new();
    let mut frequencies = HashSet::new();
    for (index, peer) in peers.iter().enumerate() {
        let label = format!("peer{index}");
        if let Some(error) = &peer.error {
            blockers.push(format!("{label}: SSH/探针失败: {error}"));
        }
        let Some(probe) = &peer.probe else {
            blockers.push(format!("{label}: 没有有效探针结果"));
            continue;
        };
        if probe.schema != 1 || probe.system != "Linux" || probe.arch != "x86_64" {
            blockers.push(format!("{label}: 需要协议 1 的 x86_64 Linux 探针"));
        }
        let identity = &probe.machine_id_sha256;
        if identity.len() != 64 || !identity.bytes().all(|c| c.is_ascii_hexdigit()) {
            blockers.push(format!("{label}: 节点身份缺失或无效"));
        } else if !identities.insert(identity) {
            blockers.push(format!(
                "{label}: 重复节点身份，不能把两个 SSH 别名当成两个节点"
            ));
        }
        if probe.collected_unix_ns == 0 || probe.logical_cpus == 0 || probe.memory_bytes == 0 {
            blockers.push(format!("{label}: 时间或资源读数缺失"));
        }
        if probe.api_version != 12 || probe.get_tsc_khz != 1 || probe.adjust_clock & 14 != 14 {
            blockers.push(format!("{label}: 缺少需要的 KVM 时钟接口"));
        }
        if !probe.tsc_adjust {
            blockers.push(format!("{label}: KVM 没有暴露运行时所需 TSC_ADJUST"));
        }
        if probe.closed_fds != 4 || !probe.errors.is_empty() {
            blockers.push(format!("{label}: 探测或资源回收未完成: {:?}", probe.errors));
        }
        let indices: Vec<_> = probe.vcpus.iter().map(|cpu| cpu.index).collect();
        if indices != [0, 1] {
            blockers.push(format!("{label}: 需要两个独立 vCPU 的有序读数"));
        }
        for cpu in &probe.vcpus {
            if cpu.tsc_khz == 0 || !cpu.offset_supported {
                blockers.push(format!(
                    "{label}: vCPU {} 缺少原生频率或偏移接口",
                    cpu.index
                ));
            }
            frequencies.insert(cpu.tsc_khz);
        }
    }
    if frequencies.len() != 1 || frequencies.contains(&0) {
        let mut values: Vec<_> = frequencies.into_iter().collect();
        values.sort();
        blockers.push(format!(
            "原生 TSC 频率不一致或缺失: {values:?} kHz；当前运行时只支持偏移校准，不支持频率转换"
        ));
    }
    Report {
        schema: 1,
        scope: "native-tsc-preflight-only",
        native_tsc_precheck_passed: blockers.is_empty(),
        peers,
        blockers,
        physical_topology_verified: false,
        running_clock_verified: false,
        full_ssi_accepted: false,
        remaining: vec![
            "空 VM 未执行客体，快照 flags 不能替代运行时可靠时钟检查",
            "专用实验 VM、宿主故障域与回退记录",
            "精确研究内核/QEMU 哈希、完整 CPU 模型交集与网络访问控制",
            "实际配对启动、长期时钟漂移和跨物理 CPU/内存执行证据",
            "持久存储、Ceph、Docker、数据库恢复与故障接管",
        ],
    }
}

/// CLI 入口：通过已有 OpenSSH 传输探测两个显式目标；不需要注册控制面。
pub async fn preflight(targets: &[String], ssh_config: Option<&Path>) -> Result<Report> {
    ensure!(targets.len() == 2, "需要恰好两个 SSH 目标");
    ensure!(targets[0] != targets[1], "SSH 目标不能重复");
    let mut nodes = Vec::new();
    for (index, ssh) in targets.iter().enumerate() {
        // 仅复用统一 SSH 传输的数据结构；该节点不写入配置，也不参与任务调度。
        let node = Node {
            name: format!("preflight-{index}"),
            ssh: ssh.clone(),
            ssh_config: ssh_config.map(Path::to_path_buf),
            images: Vec::new(),
            enabled: false,
            max_jobs: 1,
            reserve_memory_mib: 0,
            reserve_disk_mib: 0,
            max_load_per_cpu: 1.0,
            priority: 0,
        };
        config::validate_node(&node)?;
        nodes.push(node);
    }
    let script = format!(
        "python3 -c {}",
        transport::quote(include_str!("ssi_probe.py"))
    );
    let peers = futures_util::future::join_all(nodes.iter().map(|node| async {
        let result = async {
            let bytes = transport::checked(node, &script, 20).await?;
            serde_json::from_slice::<Probe>(&bytes).context("SSI 探针返回了不完整或未知格式")
        }
        .await;
        match result {
            Ok(probe) => Peer {
                ssh: node.ssh.clone(),
                probe: Some(probe),
                error: None,
            },
            Err(error) => Peer {
                ssh: node.ssh.clone(),
                probe: None,
                error: Some(format!("{error:#}")),
            },
        }
    }))
    .await;
    Ok(assess(peers))
}
