use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sshpool::{
    client::Client,
    config::{self, Build, Node},
    gateway, probe, runner,
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
    /// 只读探测已登记节点。
    Doctor,
    /// 探测两个 SSH 目标的 SSI 原生 TSC 频率与接口；不安装软件或加入集群。
    SsiPreflight {
        #[arg(required = true, num_args = 2)]
        ssh: Vec<String>,
        #[arg(long)]
        ssh_config: Option<PathBuf>,
    },
    /// 从运行中的控制面读取节点状态。
    Status,
    /// 列出持久化任务记录。
    Jobs,
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
    /// 显式准备容器镜像；此命令会增加节点镜像存储。
    Prepare {
        name: String,
        image: String,
    },
}
fn client(cli: &Cli, home: &std::path::Path) -> Result<Client> {
    let endpoint = cli
        .endpoint
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8877".into());
    let token = cli.token_file.clone().unwrap_or_else(|| home.join("token"));
    Client::new(endpoint, &token)
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
        Action::SsiPreflight { ssh, ssh_config } => {
            let report = sshpool::ssi::preflight(ssh, ssh_config.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(if report.native_tsc_precheck_passed {
                0
            } else {
                2
            });
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
        Action::Jobs => println!(
            "{}",
            serde_json::to_string_pretty(&client(&cli, &home)?.get("/v1/jobs").await?)?
        ),
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
            };
            config::validate_node(&node)?;
            config.nodes.push(node);
            config::save(home, &config)?;
            println!("Node added. Restart the controller to load configuration changes.");
        }
        NodeAction::List => println!("{}", toml::to_string_pretty(&config)?),
        NodeAction::Prepare { name, image } => {
            let build = Build {
                image: image.clone(),
                ..Build::default()
            };
            build.validate()?;
            let node = config
                .nodes
                .iter()
                .find(|node| node.name == *name)
                .context("unknown node")?;
            let output = sshpool::transport::checked(
                node,
                &format!("docker pull {}", sshpool::transport::quote(image)),
                300,
            )
            .await?;
            print!("{}", String::from_utf8_lossy(&output));
            let node = config
                .nodes
                .iter_mut()
                .find(|node| node.name == *name)
                .context("unknown node")?;
            if !node.images.contains(image) {
                node.images.push(image.clone());
            }
            config::save(home, &config)?;
            println!("Image approved for this worker. Restart the controller to apply.");
        }
        NodeAction::Enable { .. } | NodeAction::Disable { .. } => {
            anyhow::bail!("node state command was not dispatched")
        }
    }
    Ok(())
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
    let api = tokio::net::TcpListener::bind(config.api_listen).await?;
    let ssh = tokio::net::TcpListener::bind(config.ssh_listen).await?;
    let backend = config.ssh_backend;
    let state = State::load(home, config)?;
    runner::recover(&state).await?;
    eprintln!(
        "SSHPool API={} SSH={} backend={backend}",
        state.config.api_listen, state.config.ssh_listen
    );
    tokio::select! {
        result = axum::serve(api, sshpool::api::routes(state.clone())) => result?,
        result = gateway::serve(ssh, backend) => result?,
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
    for tool in ["cargo", "gradle", "make"] {
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
    ensure!(
        ["cargo", "gradle", "make"].contains(&tool),
        "unsupported shim"
    );
    let cwd = std::env::current_dir()?;
    let build_command = match tool {
        "cargo" => arguments
            .first()
            .is_some_and(|arg| ["build", "test", "check", "clippy"].contains(&arg.as_str())),
        _ => !arguments
            .iter()
            .any(|arg| ["--version", "-v", "--help", "-h"].contains(&arg.as_str())),
    };
    let project = cwd
        .ancestors()
        .find(|path| path.join("sshpool.toml").is_file());
    if let Some(project) = project.filter(|_| build_command) {
        ensure!(
            project == cwd,
            "run distributed builds from project root: {}",
            project.display()
        );
        let mut build = runner::read_build(&project.join("sshpool.toml"))?;
        build.command = std::iter::once(tool.to_string())
            .chain(arguments.iter().cloned())
            .collect();
        return client(cli, home)?.run(project, build).await;
    }
    let path = std::env::var_os("PATH").context("PATH is missing")?;
    let shims = home.join("bin").canonicalize()?;
    for directory in std::env::split_paths(&path) {
        if directory.canonicalize().ok().as_ref() == Some(&shims) {
            continue;
        }
        let binary = directory.join(tool);
        if !binary.is_file() {
            continue;
        }
        let status = tokio::process::Command::new(binary)
            .args(arguments)
            .status()
            .await?;
        return Ok(status.code().unwrap_or(1));
    }
    anyhow::bail!("no local {tool} found outside sshpool shims")
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
