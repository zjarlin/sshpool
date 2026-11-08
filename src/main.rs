use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sshpool::{
    client::Client,
    config::{self, Build, Node, Replica},
    gateway, metrics, probe, runner,
    state::State,
};
use std::{fs, path::PathBuf, sync::Arc};

/// SSHPool 将一个稳定的 SSH 工作台连接到隔离构建节点。
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, env = "SSHPOOL_HOME")]
    home: Option<PathBuf>,
    #[arg(long, global = true, env = "SSHPOOL_ENDPOINT")]
    endpoint: Option<String>,
    #[arg(long, global = true, env = "SSHPOOL_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// HTTPS 控制面的信任根（PEM）；不设时使用系统信任链。
    #[arg(long, global = true, env = "SSHPOOL_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// 创建私有控制面目录、配置与访问令牌。
    Init,
    /// 启动 HTTP 控制面与透明 SSH 转发。
    Serve,
    /// 登记或查看 SSH 执行节点。
    Node {
        #[command(subcommand)]
        command: NodeAction,
    },
    /// 管理任务状态的跨 SSH 主机副本。
    Replica {
        #[command(subcommand)]
        command: ReplicaAction,
    },
    /// 只读探测已登记节点。
    Doctor,
    /// 探测两个 SSH 目标的 SSI 原生 TSC 频率与接口；不安装软件或加入集群。
    SsiPreflight {
        #[arg(required = true, num_args = 2)]
        ssh: Vec<String>,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
    },
    /// 离线校验外部灾备包并生成数据库恢复证据。
    Dr {
        #[command(subcommand)]
        command: DrAction,
    },
    /// 只读核对应用的状态面与持久化约定；不改数据库、不改容器配置。
    ///
    /// 结论是「能不能按这份清单制定迁移方案」：声明与事实冲突、探针不完整、
    /// 键表不存在、去重唯一索引不存在，都会以退出码 2 拒绝。
    StateAudit {
        /// 状态清单（协议 1 的 JSON）；见 docs/state-audit.md。
        #[arg(long)]
        inventory: PathBuf,
        /// 现场探测的 SSH 目标；与 `--probe` 二选一。
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
        /// 离线复核一份已经采集好的探针结果；与 `--ssh` 二选一。
        #[arg(long)]
        probe: Option<PathBuf>,
        /// 报告写入文件；省略则打印到标准输出。
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 只读检查新存储设备；不格式化、不挂载，也不创建 RAID/LVM/OSD。
    StorageAdmission {
        #[arg(long)]
        ssh: String,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
        #[arg(long)]
        device: String,
        /// 只有已经核实是全新且专属于集群的空盘时才可指定。
        #[arg(long)]
        new_dedicated_device: bool,
    },
    /// 按真实物理故障域核算副本、写入门槛与恢复预留；只读，不改任何设备。
    StoragePlan {
        /// 拓扑描述 JSON（协议 1）；见 docs/ssi-physical-storage.md。
        #[arg(long)]
        topology: PathBuf,
    },
    /// 从运行中的控制面读取节点状态。
    Status,
    /// 管理短期访问凭据；明文只在签发时打印一次。
    Credential {
        #[command(subcommand)]
        command: CredentialAction,
    },
    /// 查询控制面的访问审计（谁、以什么身份、访问了哪个接口、允许或拒绝）。
    Access {
        /// 只显示该主体的记录。
        #[arg(long)]
        subject: Option<String>,
        /// 只看 `allowed` 或 `denied`。
        #[arg(long)]
        decision: Option<String>,
        /// 只显示该时刻（Unix 秒）之后的记录。
        #[arg(long)]
        since: Option<u64>,
        #[arg(long, default_value_t = sshpool::access::DEFAULT_LIMIT)]
        limit: usize,
    },
    /// 查看任务记录，或离线核对与清理任务库。
    Jobs {
        #[command(subcommand)]
        command: Option<JobsAction>,
    },
    /// 查看任务阶段与清理记录。
    Events { id: uuid::Uuid },
    /// 使用项目 sshpool.toml 提交隔离构建。
    Run {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// 跟随已有任务的日志。
    Logs { id: uuid::Uuid },
    /// 请求停止任务并清理其容器。
    Cancel { id: uuid::Uuid },
    /// 将产物解包到全新的目录，绝不覆盖现有文件。
    Fetch {
        id: uuid::Uuid,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 创建明确资源与平台的项目配置。
    ProjectInit {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        platform: Option<String>,
    },
    /// 安装可选构建包装命令，不修改 shell 配置。
    InstallShims,
    #[command(hide = true)]
    Shim {
        tool: String,
        #[arg(last = true)]
        arguments: Vec<String>,
    },
}
#[derive(Subcommand)]
enum CredentialAction {
    /// 签发一条短期凭据，并把明文 token 打印到标准输出。
    Issue {
        /// 审计用的主体名，例如工作台或人名。
        #[arg(long)]
        subject: String,
        /// 有效期（小时）；上限 90 天。
        #[arg(long, default_value_t = 12)]
        ttl_hours: u64,
        /// 授予的权限，可重复：read / submit / cancel / admin / scrape。
        ///
        /// `scrape` 只打开指标端口，不打开任何 `/v1/...` 路由；只写
        /// `--scope scrape` 时不会再自动补 `read`。
        #[arg(long = "scope", default_value = "read")]
        scopes: Vec<String>,
    },
    /// 立即撤销一条凭据；撤销后新请求被拒绝（已通过鉴权的进行中请求不会被中断）。
    Revoke { id: uuid::Uuid },
    /// 列出凭据及其到期/撤销状态（不含明文）。
    List,
    /// 清理「已过期且已撤销」的记录；默认只打印计划。
    Prune {
        #[arg(long)]
        apply: bool,
    },
}
#[derive(Subcommand)]
enum JobsAction {
    /// 从运行中的控制面列出任务记录。
    List,
    /// 离线核对任务目录、摘要和版本预留；不修改任何文件。
    Inspect,
    /// 生成到期任务清理计划；默认只打印计划。
    Prune {
        /// 结束时间早于该天数的终态任务才会进入候选。
        #[arg(long, default_value_t = 30)]
        older_than_days: u64,
        /// 最近完成的这么多条任务无论多旧都保留。
        #[arg(long, default_value_t = 10)]
        keep_last: usize,
        /// 真正执行：先写可恢复归档，再把任务目录移出 jobs/。
        #[arg(long)]
        apply: bool,
        /// 与 apply 连用：归档仍保留，但被移出的任务目录不再占用磁盘。
        #[arg(long, requires = "apply")]
        purge: bool,
    },
}
#[derive(Subcommand)]
enum NodeAction {
    Add {
        name: String,
        #[arg(long)]
        ssh: String,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
        #[arg(long, default_value_t = 4096)]
        reserve_memory_mib: u64,
        #[arg(long, default_value_t = 10240)]
        reserve_disk_mib: u64,
        #[arg(long, default_value_t = 0.8)]
        max_load_per_cpu: f64,
        #[arg(long, default_value_t = 1)]
        max_jobs: usize,
        #[arg(long, default_value_t = 0)]
        priority: i32,
        /// 已用 swap 上限（MiB）；超出后该节点暂停接单。省略则不设门槛。
        #[arg(long)]
        max_swap_used_mib: Option<u64>,
        /// 内存 PSI `some avg10` 上限（百分比，0–100）。
        #[arg(long)]
        max_memory_pressure_percent: Option<f64>,
        /// IO PSI `some avg10` 上限（百分比，0–100）。
        #[arg(long)]
        max_io_pressure_percent: Option<f64>,
    },
    List,
    /// 在线恢复节点接单；不重启控制面。
    Enable {
        name: String,
    },
    /// 在线停用节点；仍有活动任务时拒绝。
    Disable {
        name: String,
    },
    /// 在线修改调度设置（业务预算、资源预留、槽位、负载、优先级）；不重启控制面。
    ///
    /// 只提交显式给出的字段：省略等于保持原值，取消一条预算用 `--clear-slo`。
    Update {
        name: String,
        #[arg(long)]
        max_jobs: Option<usize>,
        #[arg(long)]
        reserve_memory_mib: Option<u64>,
        #[arg(long)]
        reserve_disk_mib: Option<u64>,
        #[arg(long)]
        max_load_per_cpu: Option<f64>,
        #[arg(long, allow_hyphen_values = true)]
        priority: Option<i32>,
        /// 已用 swap 上限（MiB）。
        #[arg(long)]
        max_swap_used_mib: Option<u64>,
        /// 内存 PSI `some avg10` 上限（百分比，0–100）。
        #[arg(long)]
        max_memory_pressure_percent: Option<f64>,
        /// IO PSI `some avg10` 上限（百分比，0–100）。
        #[arg(long)]
        max_io_pressure_percent: Option<f64>,
        /// 取消某项业务预算；可重复，取值同配置字段名。
        #[arg(long = "clear-slo", value_name = "FIELD")]
        clear_slo: Vec<String>,
    },
    /// 在线核对未确认清理并解除隔离；不重启控制面。
    Reconcile {
        /// 只核对这一台 Worker；省略则核对所有节点。
        name: Option<String>,
    },
    /// 显式准备容器镜像：在 Worker 上真实拉取，成功后写入允许清单；不重启控制面。
    Prepare {
        name: String,
        image: String,
    },
    /// 撤销镜像授权：只收缩允许清单，不删除 Worker 上的镜像层；不重启控制面。
    Revoke {
        name: String,
        image: String,
    },
}
#[derive(Subcommand)]
enum ReplicaAction {
    /// 登记一个已有 SSH 可达的状态副本。
    Add {
        name: String,
        #[arg(long)]
        ssh: String,
        /// 远端 ~/.sshpool-replica 下相互隔离的状态集合。
        #[arg(long, default_value = "default")]
        namespace: String,
        /// 独立物理故障域；同一宿主机上的别名必须共用同一个值。
        #[arg(long)]
        failure_domain: String,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
    },
    /// 移除配置；远端已有状态不会被删除。
    Remove {
        name: String,
    },
    List,
    /// 设置每次状态提交至少需要的副本确认数。
    Quorum {
        minimum: usize,
    },
    /// 通过 SSH 检查副本根目录归属与基本可用性。
    Check,
    /// 立即把一条本地任务重新推送到所有启用的副本。
    Sync {
        id: uuid::Uuid,
    },
    /// 从命名副本恢复本地不存在的任务；已有任务绝不覆盖。
    Restore {
        id: uuid::Uuid,
        #[arg(long)]
        from: String,
    },
    /// 为缺少摘要的旧任务验证源码并纳入副本保护。
    Adopt {
        id: uuid::Uuid,
    },
}
#[derive(Subcommand)]
enum DrAction {
    /// 校验归档摘要、内部文件清单、PostgreSQL 与 Redis 快照。
    Verify {
        archive: PathBuf,
        #[arg(long)]
        checksum: PathBuf,
    },
    /// 将 PostgreSQL COPY 行数输出转为可比较的 JSON。
    SqlCounts {
        #[arg(long, default_value = "-")]
        input: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
fn client(cli: &Cli, home: &std::path::Path) -> Result<Client> {
    let endpoint = cli
        .endpoint
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8877".into());
    let token = cli.token_file.clone().unwrap_or_else(|| home.join("token"));
    Client::new(endpoint, &token, cli.ca_file.as_deref())
}
async fn dispatch(cli: Cli) -> Result<i32> {
    let home = cli
        .home
        .clone()
        .map(Ok)
        .unwrap_or_else(config::default_home)?;
    match &cli.command {
        Action::Init => {
            ensure!(
                !home.join("config.toml").exists() && !home.join("token").exists(),
                "already initialized; existing state will not be overwritten"
            );
            fs::create_dir_all(&home)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
            }
            config::save(&home, &config::Config::default())?;
            config::atomic_write(
                &home.join("token"),
                format!(
                    "{}{}",
                    uuid::Uuid::new_v4().simple(),
                    uuid::Uuid::new_v4().simple()
                )
                .as_bytes(),
            )?;
            println!(
                "Initialized {}. Add nodes, then run sshpool serve.",
                home.display()
            );
        }
        Action::Serve => serve(home).await?,
        Action::Node { command } => node_command(&cli, &home, command).await?,
        Action::Replica { command } => replica_command(&home, command).await?,
        Action::SsiPreflight { ssh, ssh_config } => {
            let report = sshpool::ssi::preflight(ssh, ssh_config.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(if report.native_tsc_precheck_passed {
                0
            } else {
                2
            });
        }
        Action::StorageAdmission {
            ssh,
            ssh_config,
            device,
            new_dedicated_device,
        } => {
            sshpool::storage::validate_requested_device(device)?;
            let probe = sshpool::storage::probe(ssh, ssh_config.as_deref()).await?;
            let report = sshpool::storage::assess(device, *new_dedicated_device, probe);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(if report.eligible_for_future_initialization {
                0
            } else {
                2
            });
        }
        Action::StoragePlan { topology } => {
            let described = sshpool::placement::read_topology(topology)?;
            let report = sshpool::placement::plan(&described);
            println!("{}", serde_json::to_string_pretty(&report)?);
            // 与 storage-admission 一致：做不到的承诺必须是非零退出码，脚本不能只看标准输出。
            return Ok(if report.fault_tolerance_claim_allowed {
                0
            } else {
                2
            });
        }
        Action::Credential { command } => return credential_command(&home, command),
        Action::Access {
            subject,
            decision,
            since,
            limit,
        } => {
            let mut path = format!("/v1/access?limit={limit}");
            if let Some(subject) = subject {
                path.push_str(&format!("&subject={}", url_component(subject)));
            }
            if let Some(decision) = decision {
                path.push_str(&format!("&decision={}", url_component(decision)));
            }
            if let Some(since) = since {
                path.push_str(&format!("&since={since}"));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&client(&cli, &home)?.get(&path).await?)?
            );
        }
        Action::Dr { command } => return dr_command(command),
        Action::StateAudit {
            inventory,
            ssh,
            ssh_config,
            probe,
            output,
        } => {
            ensure!(
                ssh.is_some() != probe.is_some(),
                "state-audit takes exactly one of --ssh or --probe"
            );
            let declared = sshpool::state_audit::read_inventory(inventory)?;
            let facts = match (ssh, probe) {
                (Some(ssh), _) => {
                    sshpool::state_audit::probe(&declared, ssh, ssh_config.as_deref()).await?
                }
                (_, Some(probe)) => sshpool::state_audit::read_probe(probe)?,
                _ => unreachable!("validated above"),
            };
            let report = sshpool::state_audit::assess(&declared, &facts);
            let json = serde_json::to_vec_pretty(&report)?;
            match output {
                Some(path) => {
                    ensure!(!path.exists(), "output already exists: {}", path.display());
                    config::atomic_write(path, &json)?;
                }
                None => println!("{}", String::from_utf8(json)?),
            }
            return Ok(if report.migration_plan_approved { 0 } else { 2 });
        }
        Action::Doctor => {
            println!(
                "{}",
                serde_json::to_string_pretty(&probe::all(&config::read(&home)?.nodes).await)?
            );
        }
        Action::Status => println!(
            "{}",
            serde_json::to_string_pretty(&client(&cli, &home)?.get("/v1/status").await?)?
        ),
        Action::Jobs { command } => match command {
            None | Some(JobsAction::List) => println!(
                "{}",
                serde_json::to_string_pretty(&client(&cli, &home)?.get("/v1/jobs").await?)?
            ),
            Some(JobsAction::Inspect) => {
                let config = config::read(&home)?;
                let report = sshpool::retention::inspect(&home, &config)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.blockers.is_empty() {
                    return Ok(2);
                }
            }
            Some(JobsAction::Prune {
                older_than_days,
                keep_last,
                apply,
                purge,
            }) => {
                let config = config::read(&home)?;
                let seconds = older_than_days
                    .checked_mul(86_400)
                    .context("retention age overflows seconds")?;
                let plan = sshpool::retention::plan(
                    &home,
                    &config,
                    seconds,
                    *keep_last,
                    sshpool::model::now(),
                )?;
                // 标准输出只能有一种 JSON 文档：计划与执行结果分开打印会让脚本无法解析。
                if !apply {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                    eprintln!(
                        "dry run: {} task(s) would be archived and moved out of jobs/; pass --apply to execute",
                        plan.candidates.len()
                    );
                    return Ok(0);
                }
                let report = sshpool::retention::apply(&home, &config, &plan, *purge)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Action::Events { id } => println!(
            "{}",
            serde_json::to_string_pretty(
                &client(&cli, &home)?
                    .get(&format!("/v1/jobs/{id}/events"))
                    .await?
            )?
        ),
        Action::Run { project, command } => {
            let mut build = runner::read_build(&project.join("sshpool.toml"))?;
            if !command.is_empty() {
                build.command = command.clone();
            }
            return client(&cli, &home)?.run(project, build).await;
        }
        Action::Logs { id } => return client(&cli, &home)?.follow(*id).await,
        Action::Cancel { id } => client(&cli, &home)?.cancel(*id).await?,
        Action::Fetch { id, output } => {
            let output = output
                .clone()
                .unwrap_or_else(|| PathBuf::from(".sshpool/results").join(id.to_string()));
            println!(
                "{}",
                client(&cli, &home)?.fetch(*id, &output).await?.display()
            );
        }
        Action::ProjectInit {
            project,
            image,
            platform,
        } => {
            let path = project.join("sshpool.toml");
            ensure!(!path.exists(), "project config already exists");
            let mut build = Build::default();
            if let Some(image) = image {
                build.image = image.clone();
            }
            if let Some(platform) = platform {
                build.platform = platform.clone();
            }
            build.validate()?;
            config::atomic_write(&path, toml::to_string_pretty(&build)?.as_bytes())?;
            println!("Created {}", path.display());
        }
        Action::InstallShims => install_shims(&home)?,
        Action::Shim { tool, arguments } => return shim(&cli, &home, tool, arguments).await,
    }
    Ok(0)
}
fn credential_command(home: &std::path::Path, command: &CredentialAction) -> Result<i32> {
    use sshpool::credentials;
    match command {
        CredentialAction::Issue {
            subject,
            ttl_hours,
            scopes,
        } => {
            let ttl_secs = ttl_hours
                .checked_mul(3_600)
                .context("credential lifetime overflows seconds")?;
            let scopes = scopes
                .iter()
                .map(|word| credentials::Scope::parse(word))
                .collect::<Result<Vec<_>>>()?;
            let (summary, token) =
                credentials::issue(home, subject, &scopes, ttl_secs, sshpool::model::now())?;
            // 标准输出只有一份 JSON：脚本要能直接取 token，人类会在提示里看到一次性说明。
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": summary.id,
                    "subject": summary.subject,
                    "scopes": summary.scopes,
                    "created_at": summary.created_at,
                    "expires_at": summary.expires_at,
                    "token": token,
                }))?
            );
            eprintln!(
                "This token is shown only once. Store it in a file with mode 0600; \
                 `sshpool credential revoke {}` disables it immediately.",
                summary.id
            );
        }
        CredentialAction::Revoke { id } => {
            let summary = credentials::revoke(home, *id, sshpool::model::now())?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        CredentialAction::List => {
            let at = sshpool::model::now();
            let listed = credentials::list(home)?
                .iter()
                .map(|credential| {
                    serde_json::json!({
                        "id": credential.id,
                        "subject": credential.subject,
                        "scopes": credential.scopes,
                        "created_at": credential.created_at,
                        "expires_at": credential.expires_at,
                        "revoked_at": credential.revoked_at,
                        "active": credential.active(at),
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&listed)?);
        }
        CredentialAction::Prune { apply } => {
            let removed = credentials::prune(home, sshpool::model::now(), *apply)?;
            if !*apply {
                eprintln!(
                    "dry run: {} expired-and-revoked record(s) would be dropped; pass --apply to execute",
                    removed.len()
                );
            }
            println!("{}", serde_json::to_string_pretty(&removed)?);
        }
    }
    Ok(0)
}
/// 查询参数的百分号编码：主体名来自人名或工作台名，可能带空格与中文。
fn url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn dr_command(command: &DrAction) -> Result<i32> {
    match command {
        DrAction::Verify { archive, checksum } => {
            let report = sshpool::dr::verify_archive(archive, checksum)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DrAction::SqlCounts { input, output } => {
            let counts = if input == "-" {
                sshpool::dr::parse_sql_counts(std::io::stdin().lock())?
            } else {
                let file = fs::File::open(input)?;
                sshpool::dr::parse_sql_counts(std::io::BufReader::new(file))?
            };
            let json = serde_json::to_vec_pretty(&counts)?;
            if let Some(output) = output {
                ensure!(
                    !output.exists(),
                    "output already exists: {}",
                    output.display()
                );
                config::atomic_write(output, &json)?;
            } else {
                println!("{}", String::from_utf8(json)?);
            }
        }
    }
    Ok(0)
}
async fn replica_command(home: &std::path::Path, command: &ReplicaAction) -> Result<()> {
    let mut config = config::read(home)?;
    match command {
        ReplicaAction::Add {
            name,
            ssh,
            namespace,
            failure_domain,
            ssh_config,
        } => {
            ensure!(
                !config.replicas.iter().any(|replica| replica.name == *name),
                "replica already exists"
            );
            let expected_host_id_sha256 =
                sshpool::mirror::prepare(ssh, ssh_config.as_deref(), namespace).await?;
            let replica = Replica {
                name: name.clone(),
                ssh: ssh.clone(),
                namespace: namespace.clone(),
                failure_domain: failure_domain.clone(),
                expected_host_id_sha256,
                ssh_config: ssh_config.clone(),
                enabled: true,
            };
            config::validate_replica(&replica)?;
            config.replicas.push(replica);
            if config.replica_min_ack == 0 {
                // 默认承诺“本地加任意一个远端”；更高 quorum 必须由用户显式设置。
                config.replica_min_ack = 2;
            }
            config::validate(&config)?;
            config::save(home, &config)?;
            println!("Replica added. Restart the controller to load configuration changes.");
        }
        ReplicaAction::Remove { name } => {
            let before = config.replicas.len();
            config.replicas.retain(|replica| replica.name != *name);
            ensure!(config.replicas.len() < before, "unknown replica");
            if config.replicas.is_empty() {
                config.replica_min_ack = 0;
            } else {
                config.replica_min_ack = config.replica_min_ack.min(config.replicas.len() + 1);
            }
            if !config.replicas.is_empty() && config.replica_min_ack < 2 {
                config.replica_min_ack = 2;
            }
            config::save(home, &config)?;
            println!("Replica removed; remote immutable objects were not deleted.");
        }
        ReplicaAction::List => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "replica_min_ack": config.replica_min_ack,
                "replicas": config.replicas
            }))?
        ),
        ReplicaAction::Quorum { minimum } => {
            ensure!(
                *minimum <= config.replicas.len() + 1,
                "quorum exceeds local plus configured replica count"
            );
            ensure!(
                *minimum >= 2 || config.replicas.is_empty(),
                "configured replicas require local plus at least one remote acknowledgement"
            );
            config.replica_min_ack = *minimum;
            config::validate(&config)?;
            config::save(home, &config)?;
            println!("Replica quorum set to {minimum}.");
        }
        ReplicaAction::Check => {
            let health = sshpool::mirror::health(&config).await;
            // 本地控制目录在检查期间可读且已获得控制锁，因此计为一个故障域。
            let healthy = health.iter().filter(|replica| replica.healthy).count() + 1;
            println!("{}", serde_json::to_string_pretty(&health)?);
            ensure!(
                healthy >= config.replica_min_ack,
                "replica quorum not met: {healthy} live fault domains/{} required",
                config.replica_min_ack
            );
        }
        ReplicaAction::Sync { id } => {
            let replicas = sshpool::mirror::sync_job(&config, home, *id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job": id,
                    "acknowledged": replicas
                }))?
            );
        }
        ReplicaAction::Restore { id, from } => {
            let replica = config
                .replicas
                .iter()
                .find(|replica| replica.name == *from)
                .context("unknown replica")?;
            let path = sshpool::mirror::restore_from(&config, home, replica, *id).await?;
            println!("{}", path.display());
        }
        ReplicaAction::Adopt { id } => {
            let job = sshpool::mirror::adopt_legacy_job(&config, home, *id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job": id,
                    "revision": job.revision,
                    "source_sha256": job.source_sha256
                }))?
            );
        }
    }
    Ok(())
}
async fn node_command(cli: &Cli, home: &std::path::Path, command: &NodeAction) -> Result<()> {
    match command {
        NodeAction::Enable { name } => {
            client(cli, home)?.set_node_enabled(name, true).await?;
            println!("Node enabled: {name}");
            return Ok(());
        }
        NodeAction::Disable { name } => {
            client(cli, home)?.set_node_enabled(name, false).await?;
            println!("Node disabled: {name}");
            return Ok(());
        }
        NodeAction::Reconcile { name } => {
            let report = client(cli, home)?.reconcile_node(name.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        NodeAction::Prepare { name, image } => {
            // 镜像名校验两边都要做：本地拒绝能省一次网络往返，服务端拒绝才是权威。
            sshpool::config::validate_image(image)?;
            // 控制面在跑就走 API，让授权对下一次派发立即生效、并复用它的在线一致性检查
            // （重读 config.toml 比对内存）。控制面没在跑时才走离线路径：先用
            // `controller.lock` 证明「确实没有控制面」，否则两处会各自持有一份节点视图。
            if let Some(lock) = offline_controller_home(home)? {
                let config = config::read(home)?;
                let state = State::load(home.to_path_buf(), config)?;
                let (_, pulled) = state.prepare_node(name, image).await?;
                drop(lock);
                if pulled {
                    println!("Image {image} pulled on {name} and approved for this worker.");
                } else {
                    println!("Image {image} was already approved for {name}; nothing pulled.");
                }
                return Ok(());
            }
            let applied = client(cli, home)?.prepare_node(name, image).await?;
            let pulled = applied["pulled"].as_bool().unwrap_or(false);
            if pulled {
                println!("Image {image} pulled on {name} and approved for this worker.");
            } else {
                println!("Image {image} was already approved for {name}; nothing pulled.");
            }
            return Ok(());
        }
        NodeAction::Revoke { name, image } => {
            // 与 prepare 一致：本地先拒绝一次明显非法的名字，服务端才是权威。
            sshpool::config::validate_image(image)?;
            // 撤销同样分两条路。离线时直接改配置是安全的：没有控制面就没有需要
            // 同步的内存视图；`controller.lock` 独占成功才说明确实没有。
            if let Some(lock) = offline_controller_home(home)? {
                let config = config::read(home)?;
                let state = State::load(home.to_path_buf(), config)?;
                let (_, revoked) = state.revoke_node_image(name, image).await?;
                drop(lock);
                if revoked {
                    println!("Image {image} is no longer approved for {name}.");
                } else {
                    println!("Image {image} was not approved for {name}; nothing changed.");
                }
                return Ok(());
            }
            let applied = client(cli, home)?.revoke_node_image(name, image).await?;
            let revoked = applied["revoked"].as_bool().unwrap_or(false);
            if revoked {
                println!("Image {image} is no longer approved for {name}.");
            } else {
                println!("Image {image} was not approved for {name}; nothing changed.");
            }
            return Ok(());
        }
        NodeAction::Update {
            name,
            max_jobs,
            reserve_memory_mib,
            reserve_disk_mib,
            max_load_per_cpu,
            priority,
            max_swap_used_mib,
            max_memory_pressure_percent,
            max_io_pressure_percent,
            clear_slo,
        } => {
            let patch = sshpool::config::NodePatch {
                max_jobs: *max_jobs,
                reserve_memory_mib: *reserve_memory_mib,
                reserve_disk_mib: *reserve_disk_mib,
                max_load_per_cpu: *max_load_per_cpu,
                priority: *priority,
                slo: sshpool::config::SloPatch {
                    max_swap_used_mib: *max_swap_used_mib,
                    max_memory_pressure_percent: *max_memory_pressure_percent,
                    max_io_pressure_percent: *max_io_pressure_percent,
                    clear: clear_slo.clone(),
                },
                ..Default::default()
            };
            // 空补丁在本地就拒绝：不让一次「什么都没改」的请求进审计与配置文件。
            ensure!(
                !patch.is_empty(),
                "give at least one setting to change (or --clear-slo)"
            );
            let applied = client(cli, home)?.update_node(name, &patch).await?;
            for change in applied["changes"].as_array().into_iter().flatten() {
                println!("Node {name} {}", change.as_str().unwrap_or_default());
            }
            return Ok(());
        }
        _ => {}
    }
    let mut config = config::read(home)?;
    match command {
        NodeAction::Add {
            name,
            ssh,
            ssh_config,
            reserve_memory_mib,
            reserve_disk_mib,
            max_load_per_cpu,
            max_jobs,
            priority,
            max_swap_used_mib,
            max_memory_pressure_percent,
            max_io_pressure_percent,
        } => {
            ensure!(
                !config.nodes.iter().any(|node| node.name == *name),
                "node already exists"
            );
            let node = Node {
                name: name.clone(),
                ssh: ssh.clone(),
                images: Vec::new(),
                ssh_config: ssh_config.clone(),
                enabled: true,
                max_jobs: *max_jobs,
                reserve_memory_mib: *reserve_memory_mib,
                reserve_disk_mib: *reserve_disk_mib,
                max_load_per_cpu: *max_load_per_cpu,
                priority: *priority,
                slo: sshpool::config::Slo {
                    max_swap_used_mib: *max_swap_used_mib,
                    max_memory_pressure_percent: *max_memory_pressure_percent,
                    max_io_pressure_percent: *max_io_pressure_percent,
                },
            };
            config::validate_node(&node)?;
            config.nodes.push(node);
            config::save(home, &config)?;
            println!("Node added. Restart the controller to load configuration changes.");
        }
        NodeAction::List => println!("{}", toml::to_string_pretty(&config)?),
        NodeAction::Enable { .. }
        | NodeAction::Disable { .. }
        | NodeAction::Reconcile { .. }
        | NodeAction::Update { .. }
        | NodeAction::Prepare { .. }
        | NodeAction::Revoke { .. } => {
            anyhow::bail!("node online command was not dispatched")
        }
    }
    Ok(())
}
/// 控制面没在跑时返回这把独占锁（调用方持有到动作结束），在跑时返回 `None`。
///
/// `serve` 用同一把锁声明「这个 home 归我」；因此能锁上就等于「此刻没有控制面」，
/// 离线改配置不会与内存视图分叉。锁拿不到也可能是权限或文件系统问题，那种情况
/// 一律按「有控制面」处理（走 API），不让一次失败的探测变成写配置的许可。
fn offline_controller_home(home: &std::path::Path) -> Result<Option<fs::File>> {
    use fs2::FileExt;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.join("controller.lock"))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(_) => Ok(None),
    }
}

async fn serve(home: PathBuf) -> Result<()> {
    use fs2::FileExt;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.join("controller.lock"))?;
    lock.try_lock_exclusive()
        .context("another controller owns this home")?;
    let config = config::read(&home)?;
    let restored = sshpool::mirror::restore_missing(&config, &home).await?;
    if !restored.is_empty() {
        eprintln!(
            "SSHPool restored {} job records from replicas",
            restored.len()
        );
    }
    // 证书与私钥在绑定端口之前解析：配置错误不应先占端口再失败。
    let tls_config = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(sshpool::tls::server_config(cert, key)?),
        (None, None) => None,
        _ => anyhow::bail!("tls_cert and tls_key must be configured together"),
    };
    // 指标端点手写 HTTP/1.1 解析器，因此单独要一份只宣告 http/1.1 的 ALPN，
    // 否则 Prometheus（Go）会协商 h2，握手成功但抓取一直失败。
    let metrics_tls = match (&config.tls_cert, &config.tls_key, config.metrics_listen) {
        (Some(cert), Some(key), Some(_)) => Some(sshpool::tls::server_config_http1(cert, key)?),
        _ => None,
    };
    let tls = tls_config.clone();
    let api = tokio::net::TcpListener::bind(config.api_listen).await?;
    let ssh = tokio::net::TcpListener::bind(config.ssh_listen).await?;
    // 指标端口单独绑定：端口被占用时应该在服务开始前失败，而不是运行到第一次抓取。
    let metrics = match config.metrics_listen {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    let backend = config.ssh_backend;
    let state = State::load(home, config)?;
    runner::recover(&state).await?;
    eprintln!(
        "SSHPool API={} ({}) SSH={} backend={backend} metrics={}",
        state.config.api_listen,
        if tls.is_some() { "https" } else { "http" },
        state.config.ssh_listen,
        state
            .config
            .metrics_listen
            .map(|address| address.to_string())
            .unwrap_or_else(|| "off".into())
    );
    let routes = sshpool::api::routes(state.clone());
    // 两种监听器类型不同，各自走一遍 `axum::serve`；分支在外面写清楚，
    // 免得在 select! 里塞类型擦除或动态分发。
    let serve_api = async {
        match tls {
            Some(config) => axum::serve(sshpool::tls::TlsListener::new(api, config), routes).await,
            None => axum::serve(api, routes).await,
        }
    };
    let scrape = async {
        match metrics {
            // 指标端口与控制面共用同一份 TLS 配置：抓取要带根 token，
            // 不能让 token 以明文跨网络。
            Some(listener) => metrics::serve(listener, state.clone(), metrics_tls.clone()).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result = serve_api => result?,
        result = gateway::serve(ssh, backend) => result?,
        result = scrape => result?,
        result = shutdown_signal() => { result?; shutdown_jobs(&state).await?; }
    }
    Ok(())
}
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
async fn shutdown_jobs(state: &Arc<State>) -> Result<()> {
    {
        let mut jobs = state.jobs.lock().await;
        for job in jobs.values_mut().filter(|job| !job.phase.terminal()) {
            job.cancel_requested = true;
            state.persist(job)?;
        }
    }
    state.wake_queue();
    for _ in 0..25 {
        if state
            .jobs
            .lock()
            .await
            .values()
            .all(|job| job.phase.terminal())
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    eprintln!("Some tasks need reconciliation on restart; remote lifetime limits remain active.");
    Ok(())
}
fn install_shims(home: &std::path::Path) -> Result<()> {
    let directory = home.join("bin");
    fs::create_dir_all(&directory)?;
    let binary = std::env::current_exe()?;
    for tool in sshpool::shim::TOOLS {
        let path = directory.join(tool);
        ensure!(!path.exists(), "shim already exists: {}", path.display());
        let script = format!(
            "#!/bin/sh\nexec {} shim {} -- \"$@\"\n",
            sshpool::transport::quote(&binary.to_string_lossy()),
            tool
        );
        fs::write(&path, script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        }
    }
    println!("Add this directory to PATH: {}", directory.display());
    Ok(())
}
async fn shim(cli: &Cli, home: &std::path::Path, tool: &str, arguments: &[String]) -> Result<i32> {
    // 路由决策在 `shim::route` 里，纯函数、可单测；这里只负责执行。
    let cwd = std::env::current_dir()?;
    if let sshpool::shim::Route::Remote { root, build } =
        sshpool::shim::route(&cwd, tool, arguments)?
    {
        return client(cli, home)?.run(&root, build).await;
    }
    let path = std::env::var_os("PATH").context("PATH is missing")?;
    // shim 目录必须排除：否则 install-shims 之后 shim 会无限递归 exec 自己。
    let shims = home.join("bin");
    let binary = sshpool::shim::local_binary(tool, &path, &shims)
        .with_context(|| format!("no local {tool} found outside sshpool shims"))?;
    let status = tokio::process::Command::new(binary)
        .args(arguments)
        .status()
        .await?;
    Ok(status.code().unwrap_or(1))
}
#[tokio::main]
async fn main() {
    match dispatch(Cli::parse()).await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("sshpool: {error:#}");
            std::process::exit(1);
        }
    }
}
