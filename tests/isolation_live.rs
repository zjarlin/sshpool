//! 真实远端隔离校验：默认忽略，需显式指定可达节点后运行。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=sshpool-anchor cargo test --test isolation_live -- --ignored --nocapture
//! ```
//!
//! 只在临时目录创建状态，容器标签使用一次性 UUID；不触碰既有任务与业务容器。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::{Build, Node},
    isolation, transport,
};
use uuid::Uuid;

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live".into(),
        ssh,
        images: vec!["alpine:3.22".into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 0,
    })
}

/// 容器内的实测探针；只读内核状态，不写宿主。
const PROBE: &str = r#"echo uid=$(id -u)
echo caps=$(awk "/^CapEff/{print \$2}" /proc/self/status)
echo nnp=$(awk "/^NoNewPrivs/{print \$2}" /proc/self/status)
echo memory_max=$(cat /sys/fs/cgroup/memory.max)
echo pids_max=$(cat /sys/fs/cgroup/pids.max)
touch /root-probe 2>/dev/null && echo rootfs=writable || echo rootfs=read-only
[ -e /var/run/docker.sock ] && echo socket=yes || echo socket=no
printf '#!/bin/sh\necho ran\n' > /work/probe; chmod +x /work/probe
/work/probe 2>/dev/null && echo work_exec=yes || echo work_exec=no
/bin/sh -c 'echo ran' > /tmp/x 2>/dev/null; printf '#!/bin/sh\necho ran\n' > /tmp/p; chmod +x /tmp/p
/tmp/p 2>/dev/null && echo tmp_exec=yes || echo tmp_exec=no
dd if=/dev/zero of=/work/quota bs=1M count=200 >/dev/null 2>&1 && echo quota=no || echo quota=yes"#;

/// 用 runner 的真实创建参数建容器，再按 `docker inspect` 校验声明与运行行为一致。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn declared_isolation_holds_on_a_real_container() -> Result<()> {
    let node = node()?;
    let id = Uuid::new_v4();
    let container = format!("sshpool-iso-{id}");
    let build = Build {
        memory_mib: 256,
        scratch_mib: 64,
        ..Build::default()
    };
    let args = isolation::container_args(id, &container, &build);

    let created =
        sshpool::transport::checked(&node, &format!("docker {}", transport::words(&args)), 60)
            .await;
    let result = async {
        created?;
        // 创建后、启动前的真实配置必须与声明一致。
        isolation::verify_created(&node, &container, id, &build).await?;
        sshpool::transport::checked(
            &node,
            &format!("docker start {}", transport::quote(&container)),
            30,
        )
        .await?;
        let output = sshpool::transport::checked(
            &node,
            &format!(
                "docker exec {} /bin/sh -c {}",
                transport::quote(&container),
                transport::quote(PROBE)
            ),
            60,
        )
        .await?;
        let report = String::from_utf8_lossy(&output).to_string();
        for expected in [
            "uid=65534",
            "caps=0000000000000000",
            "nnp=1",
            "memory_max=268435456",
            "pids_max=256",
            "rootfs=read-only",
            "socket=no",
            "work_exec=yes",
            "tmp_exec=no",
            "quota=yes",
        ] {
            ensure!(report.contains(expected), "missing {expected}:\n{report}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let removed = sshpool::transport::checked(
        &node,
        &format!("docker rm -f {} >/dev/null", transport::quote(&container)),
        60,
    )
    .await;
    result.and(removed.map(|_| ()))
}

/// 被改坏的容器必须在启动前被拒绝；否则隔离声明只是注释。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with Docker"]
async fn tampered_container_is_refused_before_start() -> Result<()> {
    let node = node()?;
    let id = Uuid::new_v4();
    let container = format!("sshpool-iso-{id}");
    let build = Build::default();
    // 故意省略只读根文件系统与 capability 收敛，模拟参数拼装回归。
    let script = format!(
        "docker create --name {} --label io.sshpool.job={id} --entrypoint=/bin/sh {} -c 'sleep 30'",
        transport::quote(&container),
        build.image
    );
    let created = sshpool::transport::checked(&node, &script, 60).await;
    let result = async {
        created?;
        let checked = isolation::verify_created(&node, &container, id, &build).await;
        ensure!(
            checked.is_err(),
            "a container with a writable root fs and full capabilities must be refused"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let removed = sshpool::transport::checked(
        &node,
        &format!("docker rm -f {} >/dev/null", transport::quote(&container)),
        60,
    )
    .await;
    result.and(removed.map(|_| ()))
}
