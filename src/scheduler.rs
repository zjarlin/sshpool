use crate::{
    config::{Build, Node},
    model::{Health, Job, Phase},
    probe::platform_arch,
};

/// 资源门槛是硬过滤，排序只在兼容且留有业务余量的节点之间进行。
pub fn score(node: &Node, health: &Health, build: &Build, active: &[Job]) -> Result<f64, String> {
    if !node.enabled {
        return Err("disabled".into());
    }
    if !node.images.contains(&build.image) {
        return Err("image not approved for this worker; use node prepare".into());
    }
    if let Some(error) = &health.error {
        return Err(error.clone());
    }
    if active.iter().any(|job| {
        job.attempts.iter().any(|attempt| {
            attempt.node == node.name
                && attempt.outcome.is_some()
                && (attempt.cleanup_confirmed == Some(false)
                    || (attempt.cleanup_confirmed.is_none() && !job.cleanup_confirmed))
        })
    }) {
        return Err("worker quarantined: previous container cleanup is unconfirmed; run `sshpool node reconcile <name>` to reconcile".into());
    }
    let running: Vec<_> = active
        .iter()
        .filter(|job| {
            job.phase == Phase::Running
                && job
                    .attempts
                    .last()
                    .is_some_and(|attempt| attempt.node == node.name)
        })
        .collect();
    if running.len() >= node.max_jobs {
        return Err("all slots reserved".into());
    }
    let memory_reserved: u64 = running.iter().map(|job| job.build.memory_mib).sum();
    let cpus_reserved: f64 = running.iter().map(|job| job.build.cpus).sum();
    if health.memory_available_mib < node.reserve_memory_mib + memory_reserved + build.memory_mib {
        return Err("host memory reserve".into());
    }
    if health.runtime_memory_mib < memory_reserved + build.memory_mib + 256 {
        return Err("container VM memory limit".into());
    }
    if health.disk_available_mib < node.reserve_disk_mib {
        return Err("disk reserve".into());
    }
    if health.cpus as f64 - cpus_reserved < build.cpus {
        return Err("CPU capacity".into());
    }
    if health.load > node.max_load_per_cpu * f64::from(health.cpus) {
        return Err("load threshold".into());
    }
    if build.platform != format!("linux/{}", platform_arch(&health.runtime_arch)) {
        return Err("platform mismatch (emulation is not selected automatically)".into());
    }
    Ok(f64::from(node.priority) * 100.0 + f64::from(health.cpus) - health.load - cpus_reserved)
}
