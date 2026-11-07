# 部署

## 稳定宿主：macOS + Lima

```sh
brew install lima
./scripts/create-workspace.sh
cargo build --release --locked
./target/release/sshpool init
```

Lima 工作台配置：4 vCPU、6 GiB 内存、40 GiB 虚拟磁盘，无宿主目录挂载，SSH 绑定宿主 `127.0.0.1:2223`。磁盘上限不是预分配；宿主仍应保留足够空间。

用 `limactl shell sshpool` 进入 Linux。安装工作台需要的工具和 Rust 客户端；Rust 版本至少 1.89。可在 Linux 内从仓库构建：

```sh
git clone https://github.com/zjarlin/sshpool
cd sshpool
cargo install --path . --locked
```

不要把宿主私钥复制到 VM。仅向工作台配置 `SSHPOOL_ENDPOINT=http://host.lima.internal:8877` 和私有 token 文件（`0600`）。token 从宿主 `~/.sshpool/token` 通过已验证的 SSH 连接传入，避免打印到终端或写进公开文档。

### SSH 主机校验

通过 `limactl shell sshpool -- cat /etc/ssh/ssh_host_ed25519_key.pub` 读取 VM 的公钥，并为统一入口固定到专用 known_hosts。不要使用 `StrictHostKeyChecking=no`。

客户端 SSH 配置示例：

```sshconfig
Host sshpool
    HostName 127.0.0.1
    Port 2222
    User your-linux-user
    IdentityFile ~/.lima/_config/user
    HostKeyAlias sshpool-linux
    UserKnownHostsFile ~/.sshpool/known_hosts
    StrictHostKeyChecking yes
    IdentitiesOnly yes
```

`known_hosts` 中对应行是 `sshpool-linux <VM 的 ed25519 公钥>`。通过独立控制通道确认后再保存。IDE/AI 客户端选择这个 SSH 别名即可。

### 登录后自动启动

```sh
python3 scripts/install-launch-agent.py --binary target/release/sshpool
```

专用 LaunchAgent 在用户登录后启动 Lima 和控制面。它不会保证 Mac 休眠或未登录时持续服务。只在需要让其他设备访问时调整 `ssh_listen`；API 应保留回环绑定，或配上 `tls_cert`/`tls_key` 直接提供 HTTPS（私钥必须 `0600`、路径为绝对路径、两者必须成对），也可以放在可信 SSH 隧道后。跨主机借用控制面时用 `sshpool credential issue --subject <name> --ttl-hours N [--scope read|submit|cancel|admin]...` 发短期凭据，不要复制根 token；不写 `--scope` 只有 `read`，撤销即刻生效；凭据默认只能看到并取消自己提交的任务，越过属主边界需要 `admin`（等同运维权限，不要随手借出），`root` 是保留主体名不能签发。Prometheus 抓指标**不要用根 token**，签发一把 `--scope scrape` 的凭据即可（它打不开任何 `/v1/...` 路由，撤销后下一次抓取即 401）；反过来带 API 权限的凭据也抓不到指标。客户端用 `--ca-file`（或 `SSHPOOL_CA_FILE`）信任自建 CA，没有跳过证书校验的开关。

## Worker

SSH 登录后必须能运行 Python 3 和 Docker CLI。macOS 需要 Docker Desktop 等 Linux 引擎，WSL2 需要从 SSH 直接进入 Linux。原生 macOS 程序、Windows 程序和 GPU 尚未实现。

```sh
sshpool node add worker --ssh existing-alias --reserve-memory-mib 8192 --reserve-disk-mib 51200
sshpool doctor
sshpool node prepare worker alpine:3.22
```

镜像来源由部署者选择并核实。网络受限时可以在节点上显式使用可信镜像仓库，项目配置填写相应完整镜像名。生产建议锁定 digest；普通构建不会拉取镜像。

Worker 运维账号需要管理自己使用的容器引擎。这是有权限的控制通道，不应交给构建进程。优先专用计算 VM 和 rootless Docker；在现有公司主机上不能给容器挂载宿主目录或 socket。

每个节点至少预留足够的业务内存、磁盘和负载余量。`memory_mib` 包含 `/work`、`/tmp`、进程与缓存开销，`scratch_mib` 必须小于它。系统无法替业务预测突发需求。

## 升级与恢复

暂停提交，向控制面发送 SIGTERM；它会请求取消活跃任务并等待清理。替换二进制后重启。若被强制终止，下次启动会检查遗留任务；清理无法确认的节点会被隔离。

### 解除 Worker 隔离

隔离不需要重启控制面：

```sh
sshpool node reconcile          # 核对所有节点
sshpool node reconcile <name>   # 只核对一台
```

核对只依据三类证据：容器已不存在、容器已停止，或 SSH 不可达但容器自带租约已过期。仍在运行的容器绝不会被放行，即使记录里的租约时间已经过去。证据成立后会尽力删除容器、写入 `cleanup_proof` 并解除隔离；只有幂等、禁网、未被取消且仍有重试额度的任务会重新排队，且已执行过的 Worker 不会被再次选中（判据是该 Worker 出现过 attempt，包括控制面崩溃时留下的 `outcome: null`）。

核对会跳过仍在 `running` 的任务：它们的容器由执行者自己清理，此时可能还没创建，`docker inspect` 的 absent 不能当作终止证明。

容器入口是 `sleep timeout_secs + 180`，所以最长等待时间就是任务超时加 180 秒（再加 60 秒时钟偏差上界）。更早的恢复只能靠 SSH 重新可达后确认容器状态。

不自动修改 Worker 的已有服务，不执行 `docker system prune`，不自动删除公司目录。持久任务归档在控制面专用 `jobs` 目录；当前没有自动保留期清理，需自行安排备份和保留策略。

### 任务状态副本

副本只使用已有 SSH 别名与主机密钥，不向 Worker 安装常驻 Agent。每台远端必须属于独立物理故障域；同一 ESXi 上的多个 VM 不能重复计数。

```sh
sshpool replica add linux-replica --ssh existing-linux --namespace prod --failure-domain physical-linux
sshpool replica add second-replica --ssh existing-mac --namespace prod --failure-domain physical-mac
sshpool replica quorum 2
sshpool replica check
```

升级已存在的本地任务时，先停机，再逐条执行 `sshpool replica adopt <job-id>`。如果本地任务没有远端历史，带副本配置的启动会失败关闭并要求显式纳管。不要直接删除 `replica-receipts` 或远端 `~/.sshpool-replica`。

### 控制面主机恢复

1. 确认原控制器已停止，避免两个写入方同时启动。
2. 在恢复机安装相同或更新的二进制，从独立的秘密备份恢复 `config.toml`、`token`、SSH 配置、known_hosts 和所需私钥。
3. 用同一 `replica_min_ack` 启动。控制面从仍可达的物理故障域恢复缺失任务；未达到 quorum 时拒绝启动。
4. 检查 `jobs`、事件、源码摘要和产物，再恢复入口端口或 DNS。

远端状态副本不包含控制器 token、SSH 私钥和工作区磁盘。它们必须单独备份；只备份任务目录不能完成控制面主机恢复。

### 业务数据库边界

`sub2api + PostgreSQL + Redis` 不在此机制内自动高可用。PostgreSQL 需要一致性基础备份与持续 WAL，Redis 需要核对 AOF/RDB 与复制，应用可变目录也需要一致快照。恢复时必须先隔离旧写入方，再让新实例接写。日常运维可按 [failure-modes.md](failure-modes.md) 的矩阵验收。
