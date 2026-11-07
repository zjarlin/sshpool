//! 容器的隔离声明与「创建后、启动前」的实测校验。
//!
//! 声明写在 `container_args` 里，校验读取 `docker inspect` 的真实结果。两者分开，
//! 是因为命令行参数有可能被 Docker 自己改写（例如 tmpfs 默认加 `noexec`），
//! 只有实际 HostConfig 才能证明隔离确实生效。校验失败时不启动容器。
use crate::{
    config::{Build, Node},
    transport, watchdog,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use uuid::Uuid;

/// 镜像声明的每个 `VOLUME` 最多遮蔽成这么大的 tmpfs；缓存目录不需要更多。
pub const VOLUME_MIB: u64 = 64;

/// 一个镜像允许声明的卷数量上限；超过就是异常镜像，拒绝比逐个遮蔽更可信。
pub const MAX_VOLUMES: usize = 8;

/// 任务容器的全部创建参数；这是隔离声明的唯一来源，runner 与校验共用。
///
/// `/work` 显式带 `exec`：Docker 对 tmpfs 默认添加 `noexec`，否则编译出的二进制
/// 与测试程序无法执行，`cargo test` 之类的工作负载会直接失败。
///
/// `volumes` 是镜像声明的 `VOLUME` 目录。Docker 默认会把它们变成宿主上的匿名卷，
/// 既不受任务内存与磁盘上限约束，也无人清理。这里逐个用同路径的 tmpfs 遮蔽：
/// 容器内看到的仍是一个可写的空目录，但空间有上限、随容器消失，`docker inspect`
/// 的 `Mounts` 保持为空。
pub fn container_args(id: Uuid, name: &str, build: &Build, volumes: &[String]) -> Vec<String> {
    let mut args = vec![
        "create".into(),
        "--name".into(),
        name.into(),
        "--label".into(),
        format!("io.sshpool.job={id}"),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--user=65534:65534".into(),
        "--init".into(),
        format!("--memory={}m", build.memory_mib),
        format!("--memory-swap={}m", build.memory_mib),
        format!("--cpus={}", build.cpus),
        format!("--pids-limit={}", build.pids),
        "--ulimit=nofile=1024:1024".into(),
        "--ulimit=core=0:0".into(),
        "--restart=no".into(),
        "--log-driver=none".into(),
        format!("--platform={}", build.platform),
        format!(
            "--network={}",
            if build.network { "bridge" } else { "none" }
        ),
        format!(
            "--tmpfs=/work:rw,nosuid,nodev,exec,size={}m,mode=1777",
            build.scratch_mib
        ),
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777".into(),
        "--workdir=/work".into(),
        "--env=HOME=/work/.home".into(),
        "--env=TMPDIR=/tmp".into(),
        "--env=CARGO_HOME=/work/.cargo".into(),
        "--env=GRADLE_USER_HOME=/work/.gradle".into(),
        "--env=npm_config_cache=/work/.npm".into(),
        "--entrypoint=/bin/sh".into(),
        build.image.clone(),
        "-c".into(),
    ];
    // 位置无关：`--tmpfs` 都是 docker create 的选项，插在镜像名之前即可。
    let image_at = args.len() - 2;
    let shadow: Vec<String> = volumes
        .iter()
        .map(|path| {
            format!(
                "--tmpfs={path}:rw,nosuid,nodev,noexec,size={}m,mode=1777",
                VOLUME_MIB.min(build.scratch_mib)
            )
        })
        .collect();
    args.splice(image_at..image_at, shadow);
    // 主容器有独立的最长寿命；控制面掉线时，任务也不会无限运行。
    args.push(format!(
        "sleep {}",
        build.timeout_secs + watchdog::LEASE_GRACE_SECS
    ));
    args
}

/// 从 `docker image inspect` 的结果里取出镜像声明的 `VOLUME` 目录。
///
/// 只接受绝对路径；数量与形状都不合常规则拒绝——遮蔽一个畸形路径不如不跑。
pub fn declared_volumes(image: &serde_json::Value) -> Result<Vec<String>> {
    let volumes = match image["Config"]["Volumes"].as_object() {
        Some(volumes) => volumes,
        None => return Ok(Vec::new()),
    };
    ensure!(
        volumes.len() <= MAX_VOLUMES,
        "image declares {} volumes; at most {MAX_VOLUMES} are shadowed",
        volumes.len()
    );
    let mut paths = Vec::new();
    for path in volumes.keys() {
        ensure!(
            path.starts_with('/') && path.len() > 1,
            "image declares a volume that is not an absolute path: {path}"
        );
        ensure!(
            !path.contains("..") && !path.contains(['\0', ',', ':']),
            "image declares an unsupported volume path: {path}"
        );
        paths.push(path.clone());
    }
    paths.sort();
    Ok(paths)
}

/// `docker inspect` 中与隔离相关的子集；其余字段不参与判断，也不做兼容猜测。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    config: ConfigSection,
    host_config: HostConfig,
    #[serde(default)]
    mounts: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConfigSection {
    #[serde(default)]
    user: String,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    #[serde(default)]
    binds: Option<Vec<String>>,
    #[serde(default, rename = "LogConfig")]
    log_config: LogConfig,
    #[serde(default)]
    network_mode: String,
    #[serde(default)]
    port_bindings: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    restart_policy: RestartPolicy,
    #[serde(default)]
    auto_remove: bool,
    #[serde(default)]
    volume_driver: String,
    #[serde(default)]
    volumes_from: Option<Vec<String>>,
    #[serde(default)]
    cap_add: Option<Vec<String>>,
    #[serde(default)]
    cap_drop: Option<Vec<String>>,
    #[serde(default)]
    devices: Vec<serde_json::Value>,
    #[serde(default)]
    device_requests: Option<serde_json::Value>,
    #[serde(default)]
    dns: Option<serde_json::Value>,
    #[serde(default)]
    extra_hosts: Option<serde_json::Value>,
    #[serde(default)]
    group_add: Option<Vec<String>>,
    #[serde(default)]
    pid_mode: String,
    #[serde(default)]
    ipc_mode: String,
    #[serde(default)]
    userns_mode: String,
    #[serde(default)]
    publish_all_ports: bool,
    #[serde(default)]
    privileged: bool,
    #[serde(default)]
    readonly_rootfs: bool,
    #[serde(default)]
    security_opt: Option<Vec<String>>,
    #[serde(default)]
    tmpfs: Option<BTreeMap<String, String>>,
    #[serde(default)]
    init: bool,
    #[serde(default)]
    memory: i64,
    #[serde(default)]
    memory_swap: i64,
    #[serde(default)]
    nano_cpus: i64,
    #[serde(default)]
    pids_limit: i64,
    #[serde(default)]
    ulimits: Vec<Ulimit>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LogConfig {
    #[serde(default)]
    r#type: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RestartPolicy {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ulimit {
    name: String,
    hard: i64,
    soft: i64,
}

/// 校验一台已创建、尚未启动的容器是否符合声明；任何一项不满足都不启动。
pub fn verify(build: &Build, id: Uuid, raw: &str, volumes: &[String]) -> Result<()> {
    let inspect: Inspect =
        serde_json::from_str(raw).context("docker inspect did not return a container object")?;
    let host = &inspect.host_config;
    let config = &inspect.config;

    // 无宿主文件权限：只读系统层、空 capability、不挂载任何宿主资源。
    ensure!(
        host.readonly_rootfs,
        "container root filesystem is writable"
    );
    ensure!(
        host.cap_add.as_ref().is_none_or(|list| list.is_empty())
            && host
                .cap_drop
                .as_ref()
                .is_some_and(|list| list.iter().any(|item| item == "ALL")),
        "container capabilities are not fully dropped"
    );
    ensure!(
        host.security_opt
            .as_ref()
            .is_some_and(|list| list.iter().any(|item| item == "no-new-privileges")),
        "no-new-privileges is missing"
    );
    ensure!(
        config.user == "65534:65534",
        "container user is not the dedicated unprivileged account"
    );
    ensure!(!host.privileged, "container is privileged");
    ensure!(
        host.binds.as_ref().is_none_or(|list| list.is_empty()),
        "host bind mounts are present"
    );
    ensure!(
        host.volumes_from
            .as_ref()
            .is_none_or(|list| list.is_empty())
            && host.volume_driver.is_empty(),
        "host volumes are shared with the container"
    );
    // tmpfs 不出现在 `Mounts` 里，因此这里为空同时证明镜像的 VOLUME 已被遮蔽，
    // 没有匿名卷被挂到宿主上。
    ensure!(inspect.mounts.is_empty(), "container has filesystem mounts");
    ensure!(
        host.devices.is_empty()
            && host.device_requests.as_ref().is_none_or(is_empty_value)
            && host.dns.as_ref().is_none_or(is_empty_value)
            && host.extra_hosts.as_ref().is_none_or(is_empty_value)
            && host.group_add.as_ref().is_none_or(|list| list.is_empty()),
        "container has extra host access"
    );
    ensure!(
        host.port_bindings.is_empty() && !host.publish_all_ports,
        "container publishes ports"
    );
    ensure!(
        host.pid_mode.is_empty() && host.userns_mode.is_empty() && host.ipc_mode == "private",
        "container shares a host namespace"
    );
    ensure!(
        host.network_mode == if build.network { "bridge" } else { "none" },
        "container network mode does not match the build declaration"
    );
    ensure!(
        host.log_config.r#type == "none",
        "container logs reach the host disk"
    );
    ensure!(
        host.restart_policy.name == "no" && !host.auto_remove,
        "container lifetime is not bounded by the task"
    );
    // PID1 是 tini 而不是任务的 shell：否则任务留下的僵尸会吃掉 pids 上限。
    ensure!(host.init, "container has no init process");

    // 资源上限取自 cgroup，必须与请求一致；tmpfs 计入任务内存。
    let memory = i64::try_from(build.memory_mib)
        .context("memory limit exceeds i64")?
        .checked_mul(1024 * 1024)
        .context("memory limit overflows")?;
    ensure!(
        host.memory == memory && host.memory_swap == memory,
        "container memory limit does not match the request"
    );
    ensure!(
        host.nano_cpus == (build.cpus * 1e9).round() as i64,
        "container CPU limit does not match the request"
    );
    ensure!(
        host.pids_limit == i64::from(build.pids),
        "container PID limit does not match the request"
    );
    let ulimit = |name: &str| {
        host.ulimits
            .iter()
            .find(|limit| limit.name == name)
            .map(|limit| (limit.soft, limit.hard))
    };
    ensure!(
        ulimit("nofile") == Some((1024, 1024)) && ulimit("core") == Some((0, 0)),
        "container ulimits do not match the request"
    );

    // 工作区必须可执行（编译产物要在里面跑），临时目录必须不可执行。
    let tmpfs = host
        .tmpfs
        .as_ref()
        .context("container has no bounded tmpfs workspace")?;
    let work = tmpfs.get("/work").context("no /work tmpfs")?;
    let tmp = tmpfs.get("/tmp").context("no /tmp tmpfs")?;
    ensure!(
        option(work, "size") == Some(format!("{}m", build.scratch_mib)),
        "/work is not capped at the requested scratch size"
    );
    ensure!(
        option(work, "noexec").is_none() && option(work, "exec").is_some(),
        "/work must allow executing build artifacts"
    );
    ensure!(
        option(work, "nodev").is_some() && option(work, "nosuid").is_some(),
        "/work tmpfs is missing nodev or nosuid"
    );
    ensure!(
        option(tmp, "noexec").is_some() && option(tmp, "size") == Some("64m".into()),
        "/tmp must be a bounded noexec tmpfs"
    );
    ensure!(
        option(work, "mode") == Some("1777".into()) && option(tmp, "mode") == Some("1777".into()),
        "tmpfs workspaces must be world-writable with the sticky bit"
    );
    // 镜像声明的每个 VOLUME 都必须被同路径的 tmpfs 遮蔽：否则 Docker 会挂一个不受
    // 任务内存与磁盘上限约束、也不会随容器删除的匿名卷。
    let shadow_mib = VOLUME_MIB.min(build.scratch_mib);
    for volume in volumes {
        let shadow = tmpfs
            .get(volume)
            .with_context(|| format!("image VOLUME {volume} is not shadowed by a tmpfs"))?;
        ensure!(
            option(shadow, "size") == Some(format!("{shadow_mib}m")),
            "shadowed volume {volume} is not capped at {shadow_mib}m"
        );
        ensure!(
            option(shadow, "noexec").is_some() && option(shadow, "nodev").is_some(),
            "shadowed volume {volume} must be noexec and nodev"
        );
    }

    ensure!(
        config.working_dir == "/work"
            && config.entrypoint.as_deref() == Some(&["/bin/sh".to_string()]),
        "container entrypoint or working directory differs from the declaration"
    );
    ensure!(
        config.env.iter().any(|value| value == "HOME=/work/.home")
            && config.env.iter().any(|value| value == "TMPDIR=/tmp"),
        "container HOME or TMPDIR is not inside the bounded workspace"
    );
    ensure!(
        config.labels.get("io.sshpool.job") == Some(&id.to_string()),
        "container label does not identify this job"
    );
    Ok(())
}

/// 读取真实容器配置并校验；调用点位于 `docker create` 之后、`docker start` 之前。
pub async fn verify_created(
    node: &Node,
    container: &str,
    id: Uuid,
    build: &Build,
    volumes: &[String],
) -> Result<()> {
    let script = format!(
        "docker inspect --format {} {}",
        transport::quote("{{json .}}"),
        transport::quote(container)
    );
    // 只读核对：握手抖动时命令根本没跑，重试不会改变结论。
    let output = transport::verified(node, &script, 20).await?;
    verify(build, id, &String::from_utf8_lossy(&output), volumes)
}

fn is_empty_value(value: &serde_json::Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(|map| map.is_empty())
}

/// tmpfs 选项是逗号分隔的 `key` 或 `key=value`；只做字面匹配，不做单位换算。
fn option(options: &str, key: &str) -> Option<String> {
    options.split(',').find_map(|item| {
        let (name, value) = item.split_once('=').unwrap_or((item, ""));
        (name == key).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{VOLUME_MIB, container_args, declared_volumes, verify};
    use crate::config::Build;
    use uuid::Uuid;

    const ID: &str = "11111111-1111-1111-1111-111111111111";

    /// 与真实 Docker 29.1.3 `docker inspect` 结构一致的最小样本；测试改坏单个字段。
    fn inspect() -> serde_json::Value {
        serde_json::json!({
            "Config": {
                "User": "65534:65534",
                "Env": ["HOME=/work/.home", "TMPDIR=/tmp", "PATH=/usr/bin"],
                "Entrypoint": ["/bin/sh"],
                "WorkingDir": "/work",
                "Labels": {"io.sshpool.job": ID}
            },
            "HostConfig": {
                "Binds": null,
                "LogConfig": {"Type": "none", "Config": {}},
                "NetworkMode": "none",
                "PortBindings": {},
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "AutoRemove": false,
                "VolumeDriver": "",
                "VolumesFrom": null,
                "CapAdd": null,
                "CapDrop": ["ALL"],
                "Devices": [],
                "DeviceRequests": null,
                "Dns": null,
                "ExtraHosts": null,
                "GroupAdd": null,
                "PidMode": "",
                "IpcMode": "private",
                "UsernsMode": "",
                "PublishAllPorts": false,
                "Privileged": false,
                "ReadonlyRootfs": true,
                "SecurityOpt": ["no-new-privileges"],
                "Tmpfs": {
                    "/work": "rw,nosuid,nodev,exec,size=512m,mode=1777",
                    "/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"
                },
                "Init": true,
                "Memory": 1073741824,
                "MemorySwap": 1073741824,
                "NanoCpus": 1000000000,
                "PidsLimit": 256,
                "Ulimits": [
                    {"Name": "core", "Hard": 0, "Soft": 0},
                    {"Name": "nofile", "Hard": 1024, "Soft": 1024}
                ]
            },
            "Mounts": []
        })
    }

    fn check(value: &serde_json::Value) -> anyhow::Result<()> {
        check_with(value, &[])
    }

    fn check_with(value: &serde_json::Value, volumes: &[String]) -> anyhow::Result<()> {
        verify(
            &Build::default(),
            Uuid::parse_str(ID)?,
            &value.to_string(),
            volumes,
        )
    }

    fn rejected(mutate: impl Fn(&mut serde_json::Value)) {
        let mut value = inspect();
        mutate(&mut value);
        assert!(check(&value).is_err(), "{value}");
    }

    #[test]
    fn declared_container_isolation_matches_docker() -> anyhow::Result<()> {
        check(&inspect())?;
        // 创建参数本身也必须是同一份声明，避免只校验参数拼装的一半失败。
        let args = container_args(Uuid::parse_str(ID)?, "probe", &Build::default(), &[]);
        for required in [
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            "--network=none",
            "--restart=no",
            "--log-driver=none",
        ] {
            assert!(args.iter().any(|arg| arg == required), "{required}");
        }
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("--tmpfs=/work:") && arg.contains(",exec,"))
        );
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("--tmpfs=/tmp:") && arg.contains(",noexec,"))
        );
        Ok(())
    }

    /// 镜像声明的 VOLUME 必须被同路径的 tmpfs 遮蔽，而不是拒绝整个镜像或挂匿名卷。
    #[test]
    fn declared_volumes_are_shadowed_by_bounded_tmpfs() -> anyhow::Result<()> {
        let volumes = vec!["/home/gradle/.gradle".to_string()];
        let build = Build::default();
        let args = container_args(Uuid::parse_str(ID)?, "probe", &build, &volumes);
        let expected = format!(
            "--tmpfs=/home/gradle/.gradle:rw,nosuid,nodev,noexec,size={}m,mode=1777",
            VOLUME_MIB.min(build.scratch_mib)
        );
        assert!(args.iter().any(|arg| arg == &expected), "{expected}");
        // 遮蔽参数必须是 docker create 的选项，不能落在镜像名之后变成容器命令。
        let image_at = args.iter().position(|arg| arg == &build.image).unwrap();
        let shadow_at = args.iter().position(|arg| arg == &expected).unwrap();
        assert!(shadow_at < image_at, "the shadow must precede the image");

        // inspect 报出的真实配置里也要有这个 tmpfs，且 Mounts 为空。
        let mut value = inspect();
        value["HostConfig"]["Tmpfs"]["/home/gradle/.gradle"] = format!(
            "rw,nosuid,nodev,noexec,size={}m,mode=1777",
            VOLUME_MIB.min(build.scratch_mib)
        )
        .into();
        check_with(&value, &volumes)?;

        // 没有遮蔽（例如有人绕过了 container_args）就必须失败关闭。
        let unshadowed = inspect();
        let error = check_with(&unshadowed, &volumes).expect_err("must be shadowed");
        assert!(
            error.to_string().contains("/home/gradle/.gradle"),
            "{error}"
        );
        // 遮蔽了但没限制大小、或允许执行，同样拒绝。
        for options in [
            "rw,nosuid,nodev,noexec,mode=1777",
            "rw,nosuid,nodev,exec,size=64m,mode=1777",
            "rw,nosuid,nodev,noexec,size=1024m,mode=1777",
        ] {
            let mut value = inspect();
            value["HostConfig"]["Tmpfs"]["/home/gradle/.gradle"] = options.into();
            assert!(
                check_with(&value, &volumes).is_err(),
                "options {options} must be refused"
            );
        }
        Ok(())
    }

    /// 畸形或过多的 VOLUME 声明直接拒绝：遮蔽一个可疑路径不如不跑。
    #[test]
    fn unusable_volume_declarations_are_refused() {
        let good = serde_json::json!({"Config": {"Volumes": {"/a": {}, "/b": {}}}});
        assert_eq!(declared_volumes(&good).unwrap(), vec!["/a", "/b"]);
        assert!(
            declared_volumes(&serde_json::json!({"Config": {}}))
                .unwrap()
                .is_empty()
        );
        for bad in [
            serde_json::json!({"Config": {"Volumes": {"relative": {}}}}),
            serde_json::json!({"Config": {"Volumes": {"/a/../b": {}}}}),
            serde_json::json!({"Config": {"Volumes": {"/a,b": {}}}}),
            serde_json::json!({"Config": {"Volumes": {"/": {}}}}),
            serde_json::json!({"Config": {"Volumes": {
                "/1": {}, "/2": {}, "/3": {}, "/4": {}, "/5": {},
                "/6": {}, "/7": {}, "/8": {}, "/9": {}
            }}}),
        ] {
            assert!(declared_volumes(&bad).is_err(), "{bad}");
        }
    }

    /// `/work` 不可执行会让 cargo test 之类的产物直接 Permission denied。
    #[test]
    fn non_executable_workspace_is_rejected() {
        rejected(|value| {
            value["HostConfig"]["Tmpfs"]["/work"] =
                "rw,nosuid,nodev,noexec,size=512m,mode=1777".into()
        });
    }

    #[test]
    fn host_access_and_writable_root_are_rejected() {
        for mutate in [
            (|value| value["HostConfig"]["ReadonlyRootfs"] = false.into())
                as fn(&mut serde_json::Value),
            |value| value["HostConfig"]["Binds"] = serde_json::json!(["/:/host"]),
            |value| value["HostConfig"]["VolumesFrom"] = serde_json::json!(["other"]),
            |value| value["HostConfig"]["Privileged"] = true.into(),
            |value| value["HostConfig"]["CapAdd"] = serde_json::json!(["SYS_ADMIN"]),
            |value| value["HostConfig"]["PidMode"] = "host".into(),
            |value| value["HostConfig"]["UsernsMode"] = "host".into(),
            |value| {
                value["HostConfig"]["Devices"] = serde_json::json!([{ "PathOnHost": "/dev/sda" }])
            },
            |value| value["HostConfig"]["GroupAdd"] = serde_json::json!(["0"]),
            |value| value["Mounts"] = serde_json::json!([{ "Destination": "/host" }]),
            |value| value["Config"]["User"] = "0:0".into(),
        ] {
            rejected(mutate);
        }
    }

    #[test]
    fn network_and_lifetime_are_rejected_when_they_change() {
        rejected(|value| value["HostConfig"]["Init"] = false.into());
        rejected(|value| value["HostConfig"]["NetworkMode"] = "bridge".into());
        rejected(|value| value["HostConfig"]["PublishAllPorts"] = true.into());
        rejected(|value| value["HostConfig"]["PortBindings"] = serde_json::json!({"80/tcp": []}));
        rejected(|value| value["HostConfig"]["RestartPolicy"]["Name"] = "always".into());
        rejected(|value| value["HostConfig"]["LogConfig"]["Type"] = "json-file".into());
        rejected(|value| value["HostConfig"]["SecurityOpt"] = serde_json::json!([]));
    }

    #[test]
    fn resource_limits_must_match_the_request() {
        rejected(|value| value["HostConfig"]["Memory"] = 2_147_483_648_i64.into());
        rejected(|value| value["HostConfig"]["MemorySwap"] = (-1_i64).into());
        rejected(|value| value["HostConfig"]["NanoCpus"] = 2_000_000_000_i64.into());
        rejected(|value| value["HostConfig"]["PidsLimit"] = 4096.into());
        rejected(|value| value["HostConfig"]["Ulimits"][1]["Hard"] = 4096.into());
        rejected(|value| {
            value["HostConfig"]["Tmpfs"]["/work"] =
                "rw,nosuid,nodev,exec,size=1024m,mode=1777".into()
        });
        rejected(|value| {
            value["HostConfig"]["Tmpfs"]["/tmp"] = "rw,nosuid,nodev,size=64m,mode=1777".into()
        });
        rejected(|value| {
            value["HostConfig"]["Tmpfs"]["/work"] = "rw,nosuid,nodev,exec,size=512m".into()
        });
    }

    #[test]
    fn unreadable_or_foreign_container_is_rejected() {
        assert!(
            verify(
                &Build::default(),
                Uuid::parse_str(ID).unwrap(),
                "not json",
                &[]
            )
            .is_err()
        );
        rejected(|value| value["Config"]["Labels"]["io.sshpool.job"] = "other".into());
        rejected(|value| value["Config"]["WorkingDir"] = "/".into());
        rejected(|value| value["Config"]["Env"] = serde_json::json!(["HOME=/root"]));
    }
}
