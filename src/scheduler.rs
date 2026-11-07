use crate::{
    config::{Build, Node},
    model::{Health, Job, Phase},
    probe::platform_arch,
};
use std::cmp::Ordering;

/// 完成时间样本的最少条数。少于这个数一律按「没有实测」处理：
/// 一条样本可能只是碰上一个顺利的早上，不能据此改变以后的派发。
pub const MIN_SAMPLES: usize = 3;

/// 每个节点每类任务最多回看多少条最近的成功样本。
///
/// 旧样本不删除，但只有最近的这些参与判断：机器换了盘、加了缓存之后，
/// 不必等历史全部滚出窗口才能快起来。
const WINDOW: usize = 8;

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

/// 一类任务：镜像、命令、平台和资源申请都相同。
///
/// 资源申请也算进「同一类」是因为耗时对核心数和内存很敏感：拿 8 核跑出来的
/// 时间当 1 核任务的预期，会把节点排序带偏，而且看不出偏在哪。
fn same_class(left: &Build, right: &Build) -> bool {
    left.image == right.image
        && left.command == right.command
        && left.platform == right.platform
        && left.memory_mib == right.memory_mib
        && left.cpus.total_cmp(&right.cpus).is_eq()
}

/// 一台节点上一类任务「最慢见过多久」。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    /// 窗口内最慢一次成功尝试的秒数，不是均值。
    pub seconds: u64,
    /// 参与判断的样本条数；至少要 [`MIN_SAMPLES`] 条才会产生预期。
    pub samples: usize,
}

impl std::fmt::Display for Expected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "eta {}s from {} runs",
            self.seconds, self.samples
        )
    }
}

/// 一轮调度里所有节点的实测耗时。
///
/// 每轮只遍历一次任务集合，而不是每台节点各扫一遍：任务从不删除，历史会随
/// 运行时间增长，而这段代码在调度锁内执行。
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    entries: Vec<(String, Expected)>,
}

impl Evidence {
    /// 从任务集合里摘出与 `build` 同类、且成功收尾的尝试，按节点归并。
    ///
    /// 三条刻意的取舍：
    ///
    /// - 只算 `exit 0`。一次 3 秒就失败的尝试会把失败的机器算成最快的那台。
    /// - 必须两端时刻齐全。缺 `finished_at` 的旧记录就是「没测过」，不按 0 补齐 ——
    ///   那等于让「没有测量」冒充「立刻完成」。
    /// - 取窗口内**最大值**而不是均值。要回答的问题是「这单最慢要等多久」，
    ///   均值会把冷启动、拉镜像、缺缓存摊平成一个从未真正发生过的数字。
    ///
    /// 样本不足的节点不产生条目：没有实测就不猜，交给静态排序。
    pub fn collect(jobs: &[Job], build: &Build) -> Self {
        let mut per_node: std::collections::BTreeMap<&str, Vec<(u64, u64)>> =
            std::collections::BTreeMap::new();
        for attempt in jobs
            .iter()
            .filter(|job| same_class(&job.build, build))
            .flat_map(|job| job.attempts.iter())
            .filter(|attempt| attempt.outcome.as_deref() == Some("exit 0"))
        {
            // 结束早于开始说明记录或时钟不可信；这类样本不能拿去算耗时。
            let Some(elapsed) = attempt
                .finished_at
                .and_then(|finished| finished.checked_sub(attempt.started_at))
            else {
                continue;
            };
            per_node
                .entry(attempt.node.as_str())
                .or_default()
                .push((attempt.started_at, elapsed));
        }
        let entries = per_node
            .into_iter()
            .filter_map(|(node, mut samples)| {
                samples.sort_unstable();
                let stale = samples.len().saturating_sub(WINDOW);
                samples.drain(..stale);
                let seconds = samples.iter().map(|(_, elapsed)| *elapsed).max()?;
                (samples.len() >= MIN_SAMPLES).then(|| {
                    (
                        node.to_string(),
                        Expected {
                            seconds,
                            samples: samples.len(),
                        },
                    )
                })
            })
            .collect();
        Self { entries }
    }

    pub fn expected(&self, node: &str) -> Option<&Expected> {
        self.entries
            .iter()
            .find(|(name, _)| name == node)
            .map(|(_, expected)| expected)
    }
}

/// 单台节点的预期完成时间；等价于 `Evidence::collect` 之后再查一次。
pub fn expected_seconds(jobs: &[Job], node: &str, build: &Build) -> Option<Expected> {
    Evidence::collect(jobs, build).expected(node).cloned()
}

/// 通过硬过滤的候选，连同「为什么排在前面」的依据。
#[derive(Clone, Debug)]
pub struct Candidate {
    pub node: Node,
    /// 静态分：CPU 余量与负载，不含实测。
    pub score: f64,
    /// 这台节点跑这类任务的实测耗时；`None` 表示没有足够样本。
    pub expected: Option<Expected>,
}

impl Candidate {
    /// 排序依据，从最强到最弱：
    ///
    /// 1. 显式 `priority`：运维写下的「先用这台」是意图，实测不该推翻它。
    /// 2. 实测完成时间：有实测的排在没实测的前面，都有时取更短的。
    /// 3. 静态分（核心数 - 负载）：两台都没实测时的旧行为。
    /// 4. 节点名：同分时给出确定顺序，不依赖 HashMap 迭代顺序。
    pub fn rank_cmp(&self, other: &Self) -> Ordering {
        other
            .node
            .priority
            .cmp(&self.node.priority)
            .then_with(|| match (&self.expected, &other.expected) {
                (Some(left), Some(right)) => left.seconds.cmp(&right.seconds),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
            .then_with(|| other.score.total_cmp(&self.score))
            .then_with(|| self.node.name.cmp(&other.node.name))
    }

    /// 写进审计的那一行：选中的事实与依据都在里面。
    pub fn basis(&self) -> String {
        match &self.expected {
            Some(expected) => format!("{} ({expected})", self.node.name),
            None => format!(
                "{} (no measured completion time for this build; priority {} and load only)",
                self.node.name, self.node.priority
            ),
        }
    }
}

/// 硬过滤 + 排序依据。`jobs` 同时是资源占用与历史样本的来源：
/// 任务不会从状态里删除，所以「历史」就是完整的任务集合。
pub fn rank(
    node: &Node,
    health: &Health,
    build: &Build,
    jobs: &[Job],
    evidence: &Evidence,
) -> Result<Candidate, String> {
    Ok(Candidate {
        node: node.clone(),
        score: score(node, health, build, jobs)?,
        expected: evidence.expected(&node.name).cloned(),
    })
}
