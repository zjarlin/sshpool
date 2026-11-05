use crate::{config::Node, model::Health, transport};

// 探测脚本只读系统指标；不遍历文件、不修改远程服务。
const PROBE: &str = r#"python3 - <<'PY'
import json,os,platform,shutil,subprocess
system=platform.system()
if system=='Linux':
    values={l.split(':')[0]:int(l.split()[1]) for l in open('/proc/meminfo') if ':' in l}
    available=values.get('MemAvailable',0)//1024
elif system=='Darwin':
    out=subprocess.check_output(['vm_stat'],text=True)
    page=int(out.split('page size of ')[1].split()[0])
    values={l.split(':')[0]:int(l.split(':')[1].strip().strip('.')) for l in out.splitlines()[1:] if ':' in l}
    available=sum(values.get(k,0) for k in ['Pages free','Pages inactive','Pages speculative']) * page//1048576
else:
    raise RuntimeError('Connect to Linux inside WSL2, not the Windows SSH service')
info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True,timeout=10))
if not all(info.get(flag) for flag in ['MemoryLimit','CpuCfsQuota','PidsLimit']): raise RuntimeError('container engine cannot enforce required cgroup limits')
root=info.get('DockerRootDir') or os.path.expanduser('~')
if not os.path.isdir(root): root=os.path.expanduser('~')
print(json.dumps(dict(name='',os=system.lower(),arch=platform.machine(),cpus=min(os.cpu_count() or 1,info.get('NCPU',1)),memory_available_mib=available,disk_available_mib=shutil.disk_usage(root).free//1048576,load=os.getloadavg()[0],runtime_memory_mib=info['MemTotal']//1048576,runtime_arch=info['Architecture'],error=None)))
PY"#;
pub async fn node(node: &Node) -> Health {
    let result = async {
        let output = transport::checked(node, PROBE, 20).await?;
        let mut health: Health = serde_json::from_slice(&output)?;
        health.name = node.name.clone();
        Ok::<_, anyhow::Error>(health)
    }
    .await;
    match result {
        Ok(health) => health,
        Err(error) => Health::failed(&node.name, format!("{error:#}")),
    }
}
pub async fn all(nodes: &[Node]) -> Vec<Health> {
    futures_util::future::join_all(nodes.iter().map(node)).await
}
pub fn platform_arch(value: &str) -> &str {
    match value {
        "x86_64" | "amd64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        other => other,
    }
}
