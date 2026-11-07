//! 无 RAID 副本放置核算：按真实物理故障域汇总容量，并拒绝做不到的容错承诺。
//!
//! 这个模块只读一份拓扑描述，不做任何探测、格式化、挂载或集群操作。它回答三个问题：
//! 有几个**真正独立**的故障域、扣掉副本与恢复预留之后能写多少字节、
//! 以及按当前拓扑能不能对外承诺「容忍 N 台存储主机丢失」。
//!
//! 三条硬规则：
//! - 同一物理机上的多个 VM 只算一个域（`vm_of` 与同名 `failure_domain` 都会合并）；
//! - 物理宿主与其 VM 都申报磁盘时拒绝核算，因为容量会被重复计算；
//! - 域数、`min_size`、仲裁数任何一项不成立，就拒绝承诺并返回非零退出码。
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

/// 拓扑描述协议版本；只增不改。
pub const SCHEMA: u32 = 1;
/// 输入上限：几千台主机、上万块盘的描述已经超出人工核对范围，视为错误输入。
pub const MAX_HOSTS: usize = 256;
pub const MAX_DEVICES: usize = 4096;
pub const MAX_REPLICAS: usize = 16;
pub const MAX_TOPOLOGY_BYTES: u64 = 4 * 1024 * 1024;

/// 一份待核算的拓扑；未知字段一律拒绝，避免拼错的键被当成默认值。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub schema: u32,
    /// 期望的副本数（Ceph `size`）。
    pub replica_count: usize,
    /// 允许写入的最低副本数（Ceph `min_size`），必须小于等于副本数。
    pub min_size: usize,
    /// 恢复预留，千分比。必须显式声明，缺省成 0 会虚报可用容量。
    pub recovery_reserve_permille: u32,
    /// 仲裁（monitor）数量；省略表示本轮不核算仲裁拓扑。
    #[serde(default)]
    pub monitor_count: Option<usize>,
    pub hosts: Vec<Host>,
}

/// 一台主机：物理宿主或它上面的 VM，由 `vm_of` 显式说明归属。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    /// 物理故障域标识；同一物理机上的所有 VM 必须写成同一个值。
    pub failure_domain: String,
    /// 这台主机是另一台主机的 VM 时，写物理宿主的 `name`。
    #[serde(default)]
    pub vm_of: Option<String>,
    #[serde(default)]
    pub devices: Vec<Disk>,
}

/// 一块直接交给分布式存储管理的设备；不记录序列号、挂载点等内容。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    pub name: String,
    pub size_bytes: u64,
}

/// 核算结果；`scope` 与 `read_only` 让下游一眼看出这不是一次变更。
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Plan {
    pub schema: u32,
    pub scope: &'static str,
    pub read_only: bool,
    pub replica_count: usize,
    pub min_size: usize,
    pub recovery_reserve_permille: u32,
    pub monitor_count: Option<usize>,
    pub monitor_quorum: Option<usize>,
    pub tolerated_monitor_failures: Option<usize>,
    pub distinct_failure_domains: usize,
    pub data_failure_domains: usize,
    pub raw_capacity_bytes: u64,
    pub recovery_reserve_bytes: u64,
    /// 只按副本与容量算出的理论上限；不代表允许承诺。
    pub theoretical_usable_bytes: u64,
    /// 对外可用的容量：拒绝承诺时为 0，脚本忽略 `fault_tolerance_claim_allowed` 也写不进数据。
    pub usable_after_recovery_reserve_bytes: u64,
    /// 最多能同时失去几个故障域而不丢已确认写入；拒绝承诺时为 `null`。
    pub tolerated_domain_failures: Option<usize>,
    pub fault_tolerance_claim_allowed: bool,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub domains: Vec<DomainReport>,
}

/// 单个故障域的容量明细。
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DomainReport {
    pub failure_domain: String,
    pub hosts: Vec<String>,
    pub devices: usize,
    pub raw_bytes: u64,
    pub usable_bytes: u64,
    /// false 表示这个域放不下任何数据，只能当仲裁者。
    pub holds_data: bool,
}

/// 读取并解析拓扑文件；大小与类型在上限内才继续。
pub fn read_topology(path: &Path) -> Result<Topology> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("topology {} is not readable", path.display()))?;
    ensure!(metadata.is_file(), "topology must be a regular file");
    ensure!(
        metadata.len() <= MAX_TOPOLOGY_BYTES,
        "topology exceeds {MAX_TOPOLOGY_BYTES} bytes"
    );
    let bytes = std::fs::read(path)?;
    parse(&bytes)
}

/// 解析拓扑 JSON；未知字段、错误类型都直接失败，不做部分采纳。
pub fn parse(bytes: &[u8]) -> Result<Topology> {
    let topology: Topology = serde_json::from_slice(bytes)
        .context("拓扑描述不是协议 1 的 JSON（未知字段、缺失字段或类型不符）")?;
    Ok(topology)
}

/// 纯函数核算：同样的输入必须得到同样的输出，且不触碰磁盘与网络。
pub fn plan(topology: &Topology) -> Plan {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if topology.schema != SCHEMA {
        blockers.push(format!(
            "只接受协议 {SCHEMA} 的拓扑描述，收到 {}",
            topology.schema
        ));
    }
    if topology.hosts.is_empty() {
        blockers.push("拓扑没有申报任何主机".into());
    }
    if topology.hosts.len() > MAX_HOSTS {
        blockers.push(format!(
            "主机数 {} 超过单次核算上限 {MAX_HOSTS}",
            topology.hosts.len()
        ));
    }
    if topology.replica_count == 0 {
        blockers.push("副本数至少为 1".into());
    }
    if topology.replica_count > MAX_REPLICAS {
        blockers.push(format!(
            "副本数 {} 超过单次核算上限 {MAX_REPLICAS}",
            topology.replica_count
        ));
    }
    if topology.min_size == 0 {
        blockers.push("写入最低副本数至少为 1".into());
    }
    if topology.min_size > topology.replica_count {
        blockers.push(format!(
            "写入最低副本数 {} 超过副本数 {}，这样的写入永远无法满足",
            topology.min_size, topology.replica_count
        ));
    }
    if topology.recovery_reserve_permille > 1000 {
        blockers.push(format!(
            "恢复预留 {}‰ 超过原始容量的 1000‰",
            topology.recovery_reserve_permille
        ));
    }

    let index = index_hosts(topology, &mut blockers, &mut warnings);
    let groups = group_domains(topology, &index, &mut blockers, &mut warnings);

    let mut domains = Vec::with_capacity(groups.len());
    let mut raw_total: u128 = 0;
    let mut usable_total: u128 = 0;
    for group in &groups {
        // 预留比例可能大于 1000‰（已被 blocker 拒绝），这里仍要饱和，不能让它整数下溢。
        let reserve = group.raw as u128 * topology.recovery_reserve_permille as u128 / 1000;
        let usable = (group.raw as u128).saturating_sub(reserve);
        raw_total += group.raw as u128;
        usable_total += usable;
        domains.push(DomainReport {
            failure_domain: group.key.clone(),
            hosts: group.hosts.clone(),
            devices: group.devices,
            raw_bytes: group.raw,
            usable_bytes: usable as u64,
            holds_data: usable > 0,
        });
    }

    let distinct = domains.len();
    let data_domains = domains.iter().filter(|domain| domain.holds_data).count();
    let capacities: Vec<u64> = domains.iter().map(|domain| domain.usable_bytes).collect();
    let theoretical = max_feasible_data(&capacities, topology.replica_count);

    if domains.iter().any(|domain| domain.devices == 0) {
        blockers.push("存在没有任何磁盘的故障域，无法承载副本".into());
    }
    if data_domains < topology.replica_count {
        blockers.push(format!(
            "只有 {data_domains} 个故障域具备容量，放不下 {} 副本；\
             同一物理机上的多个 VM 不能凑成独立故障域",
            topology.replica_count
        ));
    }
    if data_domains < topology.min_size {
        blockers.push(format!(
            "只有 {data_domains} 个故障域具备容量，达不到写入最低副本数 {}",
            topology.min_size
        ));
    }
    if data_domains >= topology.replica_count
        && topology.replica_count > 0
        && theoretical == 0
        && domains.iter().any(|domain| domain.devices > 0)
    {
        blockers.push("扣掉副本与恢复预留之后可写容量为零".into());
    }

    let (monitor_quorum, monitor_tolerated) = match topology.monitor_count {
        None => (None, None),
        Some(count) => {
            if count == 0 {
                blockers.push("仲裁节点数至少为 1".into());
            } else if count % 2 == 0 {
                blockers.push(format!(
                    "仲裁节点数 {count} 是偶数，平票时无法形成多数派；只接受奇数"
                ));
            }
            if count > distinct {
                blockers.push(format!(
                    "仲裁节点数 {count} 超过独立故障域 {distinct}；仲裁者也要落在不同物理机上"
                ));
            }
            let quorum = count / 2 + 1;
            (Some(quorum), Some(count.saturating_sub(quorum)))
        }
    };

    let allowed = blockers.is_empty();
    Plan {
        schema: SCHEMA,
        scope: "read-only-storage-placement",
        read_only: true,
        replica_count: topology.replica_count,
        min_size: topology.min_size,
        recovery_reserve_permille: topology.recovery_reserve_permille,
        monitor_count: topology.monitor_count,
        monitor_quorum,
        tolerated_monitor_failures: monitor_tolerated,
        distinct_failure_domains: distinct,
        data_failure_domains: data_domains,
        raw_capacity_bytes: raw_total.min(u64::MAX as u128) as u64,
        recovery_reserve_bytes: raw_total.saturating_sub(usable_total).min(u64::MAX as u128) as u64,
        theoretical_usable_bytes: theoretical,
        usable_after_recovery_reserve_bytes: if allowed { theoretical } else { 0 },
        tolerated_domain_failures: if allowed {
            Some(topology.replica_count - topology.min_size)
        } else {
            None
        },
        fault_tolerance_claim_allowed: allowed,
        blockers,
        warnings,
        domains,
    }
}

struct Group {
    key: String,
    hosts: Vec<String>,
    devices: usize,
    raw: u64,
}

fn index_hosts(
    topology: &Topology,
    blockers: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> HashMap<String, usize> {
    let mut index = HashMap::new();
    let mut device_total = 0usize;
    for (position, host) in topology.hosts.iter().enumerate() {
        let name = host.name.trim();
        if name.is_empty() {
            blockers.push(format!("第 {} 台主机缺少名字", position + 1));
            continue;
        }
        if host.failure_domain.trim().is_empty() {
            blockers.push(format!("主机 {name} 缺少故障域标识"));
        }
        if name != host.name {
            warnings.push(format!("主机名 {name:?} 首尾有空白，已按去空白后核对"));
        }
        if index.insert(name.to_string(), position).is_some() {
            blockers.push(format!("主机名 {name} 重复；重复身份不能用来增加故障域"));
        }
        device_total += host.devices.len();
        let mut seen = HashMap::new();
        for disk in &host.devices {
            let disk_name = disk.name.trim();
            if disk_name.is_empty() {
                blockers.push(format!("主机 {name} 有一块磁盘缺少名字"));
            }
            if disk.size_bytes == 0 {
                blockers.push(format!("主机 {name} 的设备 {disk_name} 容量为零"));
            }
            if seen.insert(disk_name.to_string(), ()).is_some() {
                blockers.push(format!("主机 {name} 重复申报设备 {disk_name}"));
            }
        }
    }
    if device_total > MAX_DEVICES {
        blockers.push(format!(
            "设备数 {device_total} 超过单次核算上限 {MAX_DEVICES}"
        ));
    }
    index
}

fn group_domains(
    topology: &Topology,
    index: &HashMap<String, usize>,
    blockers: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    for position in 0..topology.hosts.len() {
        let host = &topology.hosts[position];
        let Some(root) = root_of(topology, index, position, blockers) else {
            continue;
        };
        let root_host = &topology.hosts[root];
        let key = root_host.failure_domain.trim().to_string();
        if host.vm_of.is_some() && host.failure_domain.trim() != key {
            blockers.push(format!(
                "主机 {} 声明是 {} 上的 VM，却写了不同的故障域（{} vs {key}）；\
                 同一物理机的 VM 不会因此变成独立故障域",
                host.name,
                root_host.name,
                host.failure_domain.trim()
            ));
            continue;
        }
        let slot = match positions.get(&key) {
            Some(slot) => *slot,
            None => {
                groups.push(Group {
                    key: key.clone(),
                    hosts: Vec::new(),
                    devices: 0,
                    raw: 0,
                });
                let slot = groups.len() - 1;
                positions.insert(key.clone(), slot);
                slot
            }
        };
        let group = &mut groups[slot];
        group.hosts.push(host.name.clone());
        group.devices += host.devices.len();
        for disk in &host.devices {
            group.raw = group.raw.saturating_add(disk.size_bytes);
        }
    }

    // 同一物理机既报物理盘又报 VM 盘时，容量归属不明：一份数据会被算两次。
    for group in &groups {
        let mut physical_disks = false;
        let mut virtual_disks = false;
        for name in &group.hosts {
            let Some(&position) = index.get(name) else {
                continue;
            };
            let host = &topology.hosts[position];
            if host.devices.is_empty() {
                continue;
            }
            match host.vm_of {
                None => physical_disks = true,
                Some(_) => virtual_disks = true,
            }
        }
        if physical_disks && virtual_disks {
            blockers.push(format!(
                "故障域 {} 里物理宿主和它的 VM 都申报了磁盘，容量会被重复计算；\
                 必须明确只由哪一层交给分布式存储",
                group.key
            ));
        }
        if physical_disks && group.hosts.len() > 1 {
            warnings.push(format!(
                "故障域 {} 由 {} 台主机共用（含物理宿主与其 VM），容量已合并为一个域",
                group.key,
                group.hosts.len()
            ));
        }
        if virtual_disks && !physical_disks {
            warnings.push(format!(
                "故障域 {} 的容量全部来自 VM 层磁盘；物理宿主没有申报磁盘",
                group.key
            ));
        }
    }
    groups
}

/// 沿 `vm_of` 找到物理宿主；未知目标与环都算缺陷，不做猜测。
fn root_of(
    topology: &Topology,
    index: &HashMap<String, usize>,
    start: usize,
    blockers: &mut Vec<String>,
) -> Option<usize> {
    let mut current = start;
    let mut seen = Vec::new();
    loop {
        if seen.contains(&current) {
            blockers.push(format!(
                "主机 {} 的虚拟化归属成环，无法确认物理故障域",
                topology.hosts[start].name
            ));
            return None;
        }
        seen.push(current);
        match topology.hosts[current].vm_of.as_deref() {
            None => return Some(current),
            Some(parent) => match index.get(parent.trim()) {
                Some(&next) => current = next,
                None => {
                    blockers.push(format!(
                        "主机 {} 声明 vm_of={parent}，但拓扑里没有这台物理主机",
                        topology.hosts[start].name
                    ));
                    return None;
                }
            },
        }
    }
}

/// 每个故障域能放下的数据量：副本必须落在不同域，且一个域对同一份数据最多放一份。
///
/// 可行性等价于 `副本数 × 数据量 ≤ Σ min(域容量, 数据量)`；该函数关于数据量单调，
/// 所以用整数二分求上限，不做浮点近似。
fn max_feasible_data(capacities: &[u64], replicas: usize) -> u64 {
    if replicas == 0 || capacities.is_empty() {
        return 0;
    }
    let total: u128 = capacities.iter().map(|capacity| *capacity as u128).sum();
    let mut low = 0u64;
    let mut high = (total / replicas as u128) as u64;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if feasible(capacities, replicas, middle) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

fn feasible(capacities: &[u64], replicas: usize, data: u64) -> bool {
    let room: u128 = capacities
        .iter()
        .map(|capacity| u128::from((*capacity).min(data)))
        .sum();
    room >= replicas as u128 * data as u128
}

#[cfg(test)]
mod tests {
    use super::{Topology, parse, plan};
    use serde_json::json;

    fn topology(value: serde_json::Value) -> Topology {
        parse(value.to_string().as_bytes()).expect("valid topology")
    }

    fn disk(name: &str, size: u64) -> serde_json::Value {
        json!({ "name": name, "size_bytes": size })
    }

    fn host(name: &str, domain: &str, disks: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "name": name,
            "failure_domain": domain,
            "devices": disks,
        })
    }

    fn base(hosts: Vec<serde_json::Value>, replicas: usize) -> serde_json::Value {
        json!({
            "schema": 1,
            "replica_count": replicas,
            "min_size": 1,
            "recovery_reserve_permille": 0,
            "hosts": hosts,
        })
    }

    #[test]
    fn vms_on_one_physical_host_do_not_buy_a_second_fault_domain() {
        let value = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "recovery_reserve_permille": 100,
            "hosts": [
                host("physical", "site-a/host-1", vec![disk("sda", 1000)]),
                json!({
                    "name": "vm-a",
                    "failure_domain": "site-a/host-1",
                    "vm_of": "physical",
                    "devices": [],
                }),
                json!({
                    "name": "vm-b",
                    "failure_domain": "site-a/host-1",
                    "vm_of": "physical",
                    "devices": [],
                }),
            ],
        });
        let report = plan(&topology(value));
        assert_eq!(report.distinct_failure_domains, 1);
        assert_eq!(report.data_failure_domains, 1);
        assert!(!report.fault_tolerance_claim_allowed);
        assert_eq!(report.usable_after_recovery_reserve_bytes, 0);
        assert!(report.tolerated_domain_failures.is_none());
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("放不下")),
            "{:?}",
            report.blockers
        );
    }

    #[test]
    fn a_vm_claiming_a_private_failure_domain_is_refused() {
        let value = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "recovery_reserve_permille": 0,
            "hosts": [
                host("physical", "site-a/host-1", vec![disk("sda", 1000)]),
                json!({
                    "name": "vm-a",
                    "failure_domain": "site-a/host-1-vm",
                    "vm_of": "physical",
                    "devices": [],
                }),
            ],
        });
        let report = plan(&topology(value));
        assert_eq!(report.distinct_failure_domains, 1);
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("不同的故障域"))
        );
    }

    #[test]
    fn three_capacity_domains_support_two_replicas_after_the_recovery_reserve() {
        let value = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "recovery_reserve_permille": 100,
            "monitor_count": 3,
            "hosts": [
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("b", "site-b", vec![disk("sdb", 1000)]),
                host("c", "site-c", vec![disk("sdc", 1000)]),
            ],
        });
        let report = plan(&topology(value));
        assert!(
            report.fault_tolerance_claim_allowed,
            "{:?}",
            report.blockers
        );
        assert_eq!(report.distinct_failure_domains, 3);
        assert_eq!(report.raw_capacity_bytes, 3000);
        assert_eq!(report.recovery_reserve_bytes, 300);
        // 900 × 3 / 2
        assert_eq!(report.theoretical_usable_bytes, 1350);
        assert_eq!(report.usable_after_recovery_reserve_bytes, 1350);
        assert_eq!(report.tolerated_domain_failures, Some(1));
        assert_eq!(report.monitor_quorum, Some(2));
        assert_eq!(report.tolerated_monitor_failures, Some(1));
    }

    #[test]
    fn two_domains_cannot_promise_three_replicas() {
        let value = base(
            vec![
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("b", "site-b", vec![disk("sdb", 1000)]),
            ],
            3,
        );
        let report = plan(&topology(value));
        assert!(!report.fault_tolerance_claim_allowed);
        assert_eq!(report.usable_after_recovery_reserve_bytes, 0);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("只有 2 个故障域具备容量"))
        );
    }

    #[test]
    fn min_size_above_the_replica_count_is_refused() {
        let mut value = base(
            vec![
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("b", "site-b", vec![disk("sdb", 1000)]),
                host("c", "site-c", vec![disk("sdc", 1000)]),
            ],
            2,
        );
        value["min_size"] = json!(3);
        let report = plan(&topology(value));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("写入最低副本数 3 超过副本数 2"))
        );
    }

    #[test]
    fn an_even_monitor_count_is_refused_because_it_can_tie() {
        let mut value = base(
            vec![
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("b", "site-b", vec![disk("sdb", 1000)]),
                host("c", "site-c", vec![disk("sdc", 1000)]),
            ],
            2,
        );
        value["monitor_count"] = json!(4);
        let report = plan(&topology(value));
        assert!(!report.fault_tolerance_claim_allowed);
        assert_eq!(report.monitor_quorum, Some(3));
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("偶数"))
        );
    }

    #[test]
    fn the_smallest_domain_caps_the_data_size_instead_of_averaging() {
        let mut value = base(
            vec![
                host("a", "site-a", vec![disk("sda", 100)]),
                host("b", "site-b", vec![disk("sdb", 100)]),
                host("c", "site-c", vec![disk("sdc", 1000)]),
            ],
            2,
        );
        value["min_size"] = json!(1);
        let report = plan(&topology(value));
        assert!(
            report.fault_tolerance_claim_allowed,
            "{:?}",
            report.blockers
        );
        // 不是 (100+100+1000)/2 = 600：两个小域各只能放 100，上限是 200。
        assert_eq!(report.usable_after_recovery_reserve_bytes, 200);
    }

    #[test]
    fn physical_and_virtual_disks_in_one_domain_are_refused_as_double_counting() {
        let value = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "recovery_reserve_permille": 0,
            "hosts": [
                host("physical", "site-a/host-1", vec![disk("sda", 1000)]),
                json!({
                    "name": "vm-a",
                    "failure_domain": "site-a/host-1",
                    "vm_of": "physical",
                    "devices": [disk("vda", 1000)],
                }),
                host("other", "site-b", vec![disk("sdb", 1000)]),
            ],
        });
        let report = plan(&topology(value));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("重复计算"))
        );
    }

    #[test]
    fn unknown_hosts_cycles_and_duplicate_names_fail_closed() {
        let duplicate = base(
            vec![
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("a", "site-b", vec![disk("sdb", 1000)]),
            ],
            1,
        );
        let report = plan(&topology(duplicate));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(report.blockers.iter().any(|item| item.contains("重复")));

        let dangling = base(
            vec![json!({
                "name": "vm-a",
                "failure_domain": "site-a",
                "vm_of": "missing",
                "devices": [disk("vda", 1000)],
            })],
            1,
        );
        let report = plan(&topology(dangling));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(
            report
                .blockers
                .iter()
                .any(|item| item.contains("没有这台物理主机"))
        );

        let cycle = json!({
            "schema": 1,
            "replica_count": 1,
            "min_size": 1,
            "recovery_reserve_permille": 0,
            "hosts": [
                json!({
                    "name": "a",
                    "failure_domain": "site-a",
                    "vm_of": "b",
                    "devices": [disk("sda", 10)],
                }),
                json!({
                    "name": "b",
                    "failure_domain": "site-a",
                    "vm_of": "a",
                    "devices": [],
                }),
            ],
        });
        let report = plan(&topology(cycle));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(report.blockers.iter().any(|item| item.contains("成环")));
    }

    #[test]
    fn misspelled_fields_and_missing_reserve_are_rejected_at_parse_time() {
        let misspelled = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "recovery_reserve_permille": 0,
            "hosts": [{
                "name": "a",
                "failure_domain": "site-a",
                "devices": [disk("sda", 1000)],
                "vm-off": "b",
            }],
        });
        assert!(parse(misspelled.to_string().as_bytes()).is_err());

        // 恢复预留必须显式声明：缺省成 0 会虚报可用容量。
        let missing_reserve = json!({
            "schema": 1,
            "replica_count": 2,
            "min_size": 1,
            "hosts": [host("a", "site-a", vec![disk("sda", 1000)])],
        });
        assert!(parse(missing_reserve.to_string().as_bytes()).is_err());
    }

    #[test]
    fn a_reserve_above_the_whole_capacity_is_refused() {
        let mut value = base(
            vec![
                host("a", "site-a", vec![disk("sda", 1000)]),
                host("b", "site-b", vec![disk("sdb", 1000)]),
            ],
            2,
        );
        value["recovery_reserve_permille"] = json!(1001);
        let report = plan(&topology(value));
        assert!(!report.fault_tolerance_claim_allowed);
        assert!(
            report
                .blockers
                .iter()
                .any(|item| item.contains("恢复预留 1001‰"))
        );
    }

    #[test]
    fn the_same_topology_renders_identically_twice() {
        let value = json!({
            "schema": 1,
            "replica_count": 3,
            "min_size": 2,
            "recovery_reserve_permille": 200,
            "monitor_count": 3,
            "hosts": [
                host("a", "site-a", vec![disk("sda", 4_000_000_000_000)]),
                host("b", "site-b", vec![disk("sdb", 4_000_000_000_000)]),
                host("c", "site-c", vec![disk("sdc", 4_000_000_000_000)]),
            ],
        });
        let topology = topology(value);
        assert_eq!(plan(&topology), plan(&topology));
    }
}
