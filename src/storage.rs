//! 新存储设备的只读准入检查；只报告现有占用，不格式化、挂载或创建集群对象。
use crate::{config, config::Node, transport};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// lsblk 单个设备的稳定字段；未知字段必须由 serde 拒绝，不能默认为空盘。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub read_only: bool,
    pub fs_type: String,
    pub fs_version: String,
    pub label: String,
    pub uuid: String,
    pub part_type: String,
    // 序列号和 WWN 仅用于本地摘要计算，不进入普通报告。
    #[serde(default, skip_serializing)]
    pub serial: String,
    #[serde(default, skip_serializing)]
    pub wwn: String,
    pub mountpoints: Vec<String>,
    pub holders: Vec<String>,
    pub children: Vec<Device>,
}

/// SSH 探针原始结果；只收集归属判断所需字段与可用工具状态。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub schema: u32,
    pub system: String,
    pub machine_id_sha256: String,
    pub devices: Vec<Device>,
    pub lvm_pvs: String,
    pub md_arrays: String,
    pub zfs_pools: String,
    pub errors: Vec<String>,
}

/// 稳定硬件身份以不可逆摘要展示；序列号和 WWN 不进入仓库或普通日志。
#[derive(Clone, Debug, Serialize)]
pub struct AdmissionReport {
    pub schema: u32,
    pub scope: &'static str,
    pub requested_device: String,
    pub intent_is_new_dedicated_device: bool,
    pub machine_id_sha256: String,
    pub device_identity_sha256: Option<String>,
    pub device: Option<Device>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub eligible_for_future_initialization: bool,
    pub format_authorized: bool,
    pub non_modifying_probe: bool,
}

/// 准入只允许显式声明为全新专用设备的整盘；已有任何用途都失败关闭。
pub fn assess(
    requested_device: &str,
    intent_is_new_dedicated_device: bool,
    probe: Probe,
) -> AdmissionReport {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    if probe.schema != 1 || probe.system != "Linux" {
        blockers.push("需要协议 1 的 Linux 只读探针".into());
    }
    if probe.machine_id_sha256.len() != 64
        || !probe
            .machine_id_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        blockers.push("主机稳定身份缺失或无效".into());
    }
    if !probe.errors.is_empty() {
        blockers.push(format!("只读探针未完整结束: {:?}", probe.errors));
    }
    if !intent_is_new_dedicated_device {
        blockers.push("必须显式确认设备是全新且专用于集群".into());
    }
    let selected = select_device(&probe.devices, requested_device).cloned();
    let Some(device) = selected.as_ref() else {
        blockers.push("目标设备不在块设备清单中".into());
        return report(
            requested_device,
            intent_is_new_dedicated_device,
            probe.machine_id_sha256,
            None,
            None,
            blockers,
            warnings,
        );
    };
    if device.kind != "disk" {
        blockers.push("只接受整块 disk，不接受分区或虚拟映射设备".into());
    }
    if device.read_only {
        blockers.push("目标设备处于只读状态".into());
    }
    if device.size_bytes == 0 {
        blockers.push("目标设备容量为零".into());
    }
    if !device.fs_type.trim().is_empty()
        || !device.fs_version.trim().is_empty()
        || !device.label.trim().is_empty()
        || !device.uuid.trim().is_empty()
        || !device.part_type.trim().is_empty()
    {
        blockers.push("目标设备已有文件系统、分区签名或卷标识".into());
    }
    if !device.mountpoints.is_empty()
        || device
            .mountpoints
            .iter()
            .any(|mountpoint| !mountpoint.is_empty())
    {
        blockers.push("目标设备仍被挂载".into());
    }
    if !device.holders.is_empty() {
        blockers.push(format!("目标设备仍被其他层使用: {:?}", device.holders));
    }
    if !device.children.is_empty() {
        blockers.push(format!(
            "目标设备存在 {} 个子设备，不能据此推断为空盘",
            device.children.len()
        ));
        inspect_children(&device.children, &mut blockers);
    }
    if !probe.lvm_pvs.trim().is_empty()
        || !probe.md_arrays.trim().is_empty()
        || !probe.zfs_pools.trim().is_empty()
    {
        blockers.push("主机存在 LVM、md 或 ZFS 状态，无法证明目标盘未参与".into());
    }
    let identity = stable_identity(device);
    if identity.is_none() {
        blockers.push("设备缺少序列号或 WWN，不能按稳定硬件身份重新核对".into());
    }
    if device.name.trim().is_empty() {
        warnings.push("目标设备缺少设备名".into());
        blockers.push("目标设备名称缺失".into());
    }
    report(
        requested_device,
        intent_is_new_dedicated_device,
        probe.machine_id_sha256,
        identity,
        selected,
        blockers,
        warnings,
    )
}

fn report(
    requested_device: &str,
    intent: bool,
    machine_id_sha256: String,
    device_identity_sha256: Option<String>,
    device: Option<Device>,
    blockers: Vec<String>,
    warnings: Vec<String>,
) -> AdmissionReport {
    AdmissionReport {
        schema: 1,
        scope: "read-only-storage-admission",
        requested_device: requested_device.into(),
        intent_is_new_dedicated_device: intent,
        machine_id_sha256,
        device_identity_sha256,
        device,
        eligible_for_future_initialization: blockers.is_empty(),
        format_authorized: false,
        non_modifying_probe: true,
        blockers,
        warnings,
    }
}

fn select_device<'a>(devices: &'a [Device], requested: &str) -> Option<&'a Device> {
    devices
        .iter()
        .find(|device| device.path == requested || format!("/dev/{}", device.name) == requested)
}

fn inspect_children(children: &[Device], blockers: &mut Vec<String>) {
    for child in children {
        if !child.fs_type.is_empty()
            || !child.uuid.is_empty()
            || !child.mountpoints.is_empty()
            || !child.holders.is_empty()
        {
            blockers.push(format!("子设备 {} 已有文件系统、挂载或使用者", child.path));
        }
        inspect_children(&child.children, blockers);
    }
}

fn stable_identity(device: &Device) -> Option<String> {
    let hardware = match (device.serial.trim(), device.wwn.trim()) {
        ("", "") => return None,
        (serial, "") => format!("serial:{serial}"),
        ("", wwn) => format!("wwn:{wwn}"),
        (serial, wwn) => format!("serial:{serial}\nwwn:{wwn}"),
    };
    let mut input = hardware;
    input.push('\n');
    Some(crate::archive::sha256_bytes(input.as_bytes()))
}

const PROBE_SCRIPT: &str = r#"python3 - <<'PY'
import hashlib,json,os,subprocess

def command(*args):
    try:
        return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=False).stdout.strip()
    except (FileNotFoundError,subprocess.TimeoutExpired):
        return ''

def stable_id():
    for path in ['/etc/machine-id','/var/lib/dbus/machine-id']:
        try:
            value=open(path,encoding='ascii').read().strip()
            if value:
                return hashlib.sha256(value.encode()).hexdigest()
        except OSError:
            pass
    return ''

def holders(name):
    if '/' in name:
        return []
    path=f'/sys/class/block/{name}/holders'
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []

def convert(row):
    return {
        'name': row.get('name',''),
        'path': row.get('path',''),
        'kind': row.get('type',''),
        'size_bytes': int(row.get('size',0) or 0),
        'read_only': bool(row.get('ro',False)),
        'fs_type': row.get('fstype') or '',
        'fs_version': row.get('fsver') or '',
        'label': row.get('label') or '',
        'uuid': row.get('uuid') or '',
        'part_type': row.get('parttype') or '',
        'serial': row.get('serial') or '',
        'wwn': row.get('wwn') or '',
        'mountpoints': [v for v in (row.get('mountpoints') or []) if v],
        'holders': holders(row.get('name','')),
        'children': [convert(child) for child in (row.get('children') or [])],
    }

errors=[]
try:
    result=subprocess.run(['lsblk','--json','--bytes','--output','NAME,PATH,TYPE,SIZE,RO,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINTS,PARTTYPE,SERIAL,WWN'],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=True)
    blockdevices=json.loads(result.stdout).get('blockdevices',[])
except Exception as exc:
    blockdevices=[]
    errors.append('lsblk failed: '+type(exc).__name__)

values={
    'schema':1,
    'system':__import__('platform').system(),
    'machine_id_sha256':stable_id(),
    'devices':[convert(row) for row in blockdevices if row.get('type') not in ('loop','ram')],
    'lvm_pvs':command('pvs','--noheadings','-o','pv_name,vg_name') if command('sh','-c','command -v pvs') else '',
    'md_arrays':command('mdadm','--detail','--scan') if command('sh','-c','command -v mdadm') else '',
    'zfs_pools':command('zpool','list','-H','-o','name') if command('sh','-c','command -v zpool') else '',
    'errors':errors,
}
print(json.dumps(values,sort_keys=True))
PY"#;

/// 通过已有 OpenSSH 运行只读探针；不创建 Node、不运行 sudo、不访问目录内容。
pub async fn probe(ssh: &str, ssh_config: Option<&Path>) -> Result<Probe> {
    let node = Node {
        name: "storage-admission".into(),
        ssh: ssh.into(),
        images: Vec::new(),
        ssh_config: ssh_config.map(Path::to_path_buf),
        enabled: false,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
    };
    config::validate_node(&node)?;
    let output = transport::checked(&node, PROBE_SCRIPT, 45).await?;
    serde_json::from_slice(&output).context("存储探针返回了不完整或未知格式")
}

/// 只接受 /dev/ 下的绝对设备名，防止参数被解释成 SSH 或 shell 选项。
pub fn validate_requested_device(device: &str) -> Result<()> {
    ensure!(
        device.starts_with("/dev/")
            && device.len() > 5
            && !device[5..].contains('/')
            && !device.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || "'\";$`|&<>*".contains(character)
            }),
        "device must be one /dev/<name> path without shell syntax"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Device, Probe, assess, validate_requested_device};

    fn device(name: &str) -> Device {
        Device {
            name: name.into(),
            path: format!("/dev/{name}"),
            kind: "disk".into(),
            size_bytes: 3_000_000_000_000,
            read_only: false,
            fs_type: String::new(),
            fs_version: String::new(),
            label: String::new(),
            uuid: String::new(),
            part_type: String::new(),
            serial: "SERIAL-SDB".into(),
            wwn: String::new(),
            mountpoints: Vec::new(),
            holders: Vec::new(),
            children: Vec::new(),
        }
    }

    fn probe(devices: Vec<Device>) -> Probe {
        Probe {
            schema: 1,
            system: "Linux".into(),
            machine_id_sha256: "a".repeat(64),
            devices,
            lvm_pvs: String::new(),
            md_arrays: String::new(),
            zfs_pools: String::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn a_declared_new_clean_disk_is_only_eligible_for_future_initialization() {
        let report = assess("/dev/sdb", true, probe(vec![device("sdb")]));
        assert!(report.blockers.is_empty(), "{:?}", report.blockers);
        assert!(report.eligible_for_future_initialization);
        assert!(!report.format_authorized);
        assert!(report.non_modifying_probe);
    }

    #[test]
    fn existing_partitions_filesystems_holders_and_pool_state_fail_closed() {
        let mut partitioned = device("sdb");
        partitioned.children.push(Device {
            name: "sdb1".into(),
            path: "/dev/sdb1".into(),
            kind: "part".into(),
            size_bytes: 1,
            read_only: false,
            fs_type: "ext4".into(),
            fs_version: String::new(),
            label: String::new(),
            uuid: "existing".into(),
            part_type: "linux".into(),
            serial: String::new(),
            wwn: String::new(),
            mountpoints: Vec::new(),
            holders: Vec::new(),
            children: Vec::new(),
        });
        let mut lvm = probe(vec![partitioned]);
        lvm.lvm_pvs = "occupied".into();
        let report = assess("/dev/sdb", true, lvm);
        assert!(!report.eligible_for_future_initialization);
        assert!(report.blockers.len() >= 2);
    }

    #[test]
    fn missing_intent_and_missing_device_do_not_grant_initialization() {
        assert!(
            !assess("/dev/sdb", false, probe(vec![device("sdb")]))
                .eligible_for_future_initialization
        );
        assert!(
            !assess("/dev/sdc", true, probe(vec![device("sdb")]))
                .eligible_for_future_initialization
        );
    }

    #[test]
    fn requested_device_rejects_options_and_shell_syntax() {
        for value in ["sda", "/dev/", "/dev/../sda", "/dev/sda;id", "/dev/sda\n"] {
            assert!(validate_requested_device(value).is_err());
        }
        assert!(validate_requested_device("/dev/nvme0n1").is_ok());
    }
}
