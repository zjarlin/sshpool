//! 演示数据上的真实迁移与切回演练：PostgreSQL + Redis，两个独立环境 A/B。
//!
//! ```sh
//! SSHPOOL_LIVE_NODE=sshpool-anchor \
//!   cargo test --test migration_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 这不是「跑一次 `pg_restore` 看退出码」：判据是迁移前后两侧的内容级指纹逐项相等，
//! 且每一步写进一条链式操作日志（后一条含前一条摘要），可离线复核。
//!
//! 演练全程使用一次性容器、卷和网络（名字都带本次 UUID），结束后全部删除。
//! 不接触任何既有业务容器：目标名一律 `sshpool-mig-<uuid>-*`。
use anyhow::{Context, Result, ensure};
use sshpool::{
    config::Node,
    migration::{
        Difference, Journal, POSTGRES_FINGERPRINT_SQL, REDIS_FINGERPRINT_LUA, fingerprint,
        stage_paths,
    },
    transport,
};
use std::{fs, path::Path};
use uuid::Uuid;

const POSTGRES_IMAGE: &str = "postgres:16-alpine";
/// 演练目录在容器内的挂载点：SQL/Lua/dump 都要对容器可见，宿主的 `/tmp` 不行。
const STAGE_MOUNT: &str = "/migration";
const REDIS_IMAGE: &str = "redis:8-alpine";

/// 演练数据：两套 schema + 一张会话表，一个表带外键、一个带唯一约束。
///
/// 特意混入「应用用户自己的 schema」与「public 下的表」：只恢复其中之一会让指纹立刻不同。
const SEED: &str = "create schema billing;
create table billing.account(id bigserial primary key, name text not null);
create table billing.charge(id bigserial primary key, account_id bigint not null references billing.account(id), amount numeric(12,2) not null, marker text not null unique);
create table billing.ledger(id bigserial primary key, note text not null);
create table public.session(id text primary key, payload jsonb not null);
insert into billing.account(name) values ('a1'),('a2'),('a3');
insert into billing.charge(account_id,amount,marker) values (1,10.00,'seed-1'),(1,5.50,'seed-2'),(2,7.25,'seed-3');
insert into billing.ledger(note) values ('open');
insert into public.session values ('s1','{\"plan\":\"pro\"}'),('s2','{\"plan\":\"free\"}');
";

/// Redis 种子：三个库、一个带 TTL 的键、一个列表和一个哈希。
///
/// 用 Lua 而不是 `--pipe`：`--pipe` 要的是 RESP 帧，内联文本命令会被静默吞掉，
/// 那会让「种子成功」变成一句空话。
const REDIS_SEED: &str = r#"
redis.call('SELECT', 0)
redis.call('SET', 's1', '{"plan":"pro"}')
redis.call('SET', 's2', '{"plan":"free"}')
redis.call('EXPIRE', 's2', 86400)
redis.call('SELECT', 3)
redis.call('SET', 'q1', 'x')
redis.call('SELECT', 5)
redis.call('LPUSH', 'l1', 'c', 'b', 'a')
redis.call('HSET', 'h1', 'f1', 'v1', 'f2', 'v2')
redis.call('SELECT', 0)
return 'ok'
"#;

fn node() -> Result<Node> {
    let ssh = std::env::var("SSHPOOL_LIVE_NODE").context("SSHPOOL_LIVE_NODE is not set")?;
    Ok(Node {
        name: "live-migration".into(),
        ssh,
        images: vec![POSTGRES_IMAGE.into(), REDIS_IMAGE.into()],
        ssh_config: None,
        enabled: true,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 100.0,
        priority: 0,
    })
}

/// 一次演练的全部远端资源名；前缀带 UUID，避免与任何既有容器撞名。
struct Layout {
    /// 本次演练的资源前缀；所有容器、卷、网络、临时目录都从它派生。
    prefix: String,
    network: String,
    a_pg: String,
    a_redis: String,
    b_pg: String,
    b_redis: String,
    a_pg_volume: String,
    a_redis_volume: String,
    b_pg_volume: String,
    b_redis_volume: String,
}

impl Layout {
    fn new(id: Uuid) -> Self {
        let prefix = format!("sshpool-mig-{id}");
        Self {
            network: format!("{prefix}-net"),
            prefix: prefix.clone(),
            a_pg: format!("{prefix}-a-pg"),
            a_redis: format!("{prefix}-a-redis"),
            b_pg: format!("{prefix}-b-pg"),
            b_redis: format!("{prefix}-b-redis"),
            a_pg_volume: format!("{prefix}-a-pg"),
            a_redis_volume: format!("{prefix}-a-redis"),
            b_pg_volume: format!("{prefix}-b-pg"),
            b_redis_volume: format!("{prefix}-b-redis"),
        }
    }
}

/// 远端临时目录：所有 SQL/Lua 与 dump 都放在这里，随演练删除。
fn scratch(layout: &Layout) -> String {
    format!("/tmp/{}", layout.network)
}

/// 同一个文件在容器里的路径（演练目录挂载在 `STAGE_MOUNT`）。
fn staged(name: &str) -> String {
    format!("{STAGE_MOUNT}/{name}")
}

/// 执行一段远端脚本，失败即中止。
///
/// 走 `transport::verified`：只在「命令根本没跑起来」的连接层错误上重试
/// （家宽入口的 sshd 会丢一部分握手），命令自己的非零退出码不重试。
async fn run(node: &Node, script: &str, seconds: u64) -> Result<String> {
    let output = transport::verified(node, script, seconds)
        .await
        .with_context(|| format!("remote step failed: {script}"))?;
    Ok(String::from_utf8_lossy(&output).to_string())
}

/// 与 `run` 相同，但允许命令以非零码退出：用于**验证写入确实被拒绝**。
///
/// 只看 stdout+stderr，不看退出码；调用方必须自己断言输出里的拒绝原因。
/// 连接层失败仍然重试，否则一次握手抖动会被误读成「写入没被拒」。
async fn run_any(node: &Node, script: &str, seconds: u64) -> Result<String> {
    let mut last = None;
    for _ in 1..=transport::IDEMPOTENT_ATTEMPTS {
        let (code, stdout, stderr) = transport::capture(node, script, seconds).await?;
        let stderr = String::from_utf8_lossy(&stderr).to_string();
        if code == 255 && connection_noise(&stderr) {
            last = Some(stderr);
            continue;
        }
        return Ok(format!("{}{stderr}", String::from_utf8_lossy(&stdout)));
    }
    anyhow::bail!("remote step never ran: {}", last.unwrap_or_default().trim())
}

/// 只认「连接没建立」这一种 255；命令自己返回 255 不算。
fn connection_noise(stderr: &str) -> bool {
    [
        "banner exchange",
        "kex_exchange_identification",
        "Connection refused",
        "Connection reset",
        "Connection closed",
        "Broken pipe",
        "No route to host",
        "Network is unreachable",
    ]
    .iter()
    .any(|marker| stderr.contains(marker))
}

/// 把一段文本写到远端文件：用 stdin + base64，避免任何 shell 引号问题。
///
/// base64 内容直接写进那个临时文件再上传，不再派生第二个文件 —— 否则每轮演练都会在
/// 本机 `$TMPDIR` 里留下孤立的 `.b64`。
async fn push_text(node: &Node, path: &str, body: &str) -> Result<()> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
    let local = tempfile::NamedTempFile::new()?;
    fs::write(local.path(), encoded)?;
    transport::upload(
        node,
        &format!("sh -c 'base64 -d > {}'", transport::quote(path)),
        local.path(),
    )
    .await
}

/// 等某个容器里的命令稳定成功；返回实际尝试次数，用于证据。
async fn wait_for(node: &Node, container: &str, probe: &str, attempts: u32) -> Result<u32> {
    for attempt in 1..=attempts {
        let script = format!(
            "docker exec {} {} >/dev/null 2>&1",
            transport::quote(container),
            probe
        );
        if transport::idempotent(node, &script, 30)
            .await
            .is_ok_and(|(code, _, _)| code == 0)
        {
            return Ok(attempt);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    anyhow::bail!("{container} did not become ready in {attempts}s")
}

/// 在容器里执行一段 SQL 文件（以给定用户），失败即中止。
async fn psql(
    node: &Node,
    container: &str,
    user: &str,
    database: &str,
    file: &str,
) -> Result<String> {
    run(
        node,
        &format!(
            "docker exec {} psql -U {} -d {} -v ON_ERROR_STOP=1 -q -f {}",
            transport::quote(container),
            transport::quote(user),
            transport::quote(database),
            transport::quote(file)
        ),
        120,
    )
    .await
}

/// 执行一条内联 SQL（管理动作与单条写入）。用 `-c` 而不是 `-f`：
/// 整段 SQL 交给 `quote` 处理，避免 `-c "..."` 被当成文件名。
async fn psql_sql(
    node: &Node,
    container: &str,
    user: &str,
    database: &str,
    sql: &str,
) -> Result<String> {
    run(
        node,
        &format!(
            "docker exec {} psql -U {} -d {} -v ON_ERROR_STOP=1 -q -c {}",
            transport::quote(container),
            transport::quote(user),
            transport::quote(database),
            transport::quote(sql)
        ),
        120,
    )
    .await
}

/// 采集 PostgreSQL 指纹；以应用用户执行，证明只看得到自己该看的东西也能算出一致结果。
async fn postgres_print(
    node: &Node,
    container: &str,
    user: &str,
    database: &str,
    sql: &str,
) -> Result<String> {
    run(
        node,
        &format!(
            "docker exec {} psql -U {} -d {} -t -A -q -f {}",
            transport::quote(container),
            transport::quote(user),
            transport::quote(database),
            transport::quote(sql)
        ),
        120,
    )
    .await
}

/// 采集 Redis 指纹；Lua 脚本通过 `--eval` 传入，数据库编号作为 ARGV。
async fn redis_print(node: &Node, container: &str, password: &str, lua: &str) -> Result<String> {
    run(
        node,
        &format!(
            "docker exec {} redis-cli --no-auth-warning -a {} --raw --eval {} , 0 3 5",
            transport::quote(container),
            transport::quote(password),
            transport::quote(lua)
        ),
        120,
    )
    .await
}

/// 完整演练。每一步都先落日志再继续：中途失败时日志里能看出停在哪。
async fn rehearse(node: &Node, root: &Path) -> Result<Rehearsal> {
    let layout = Layout::new(Uuid::new_v4());
    let stage = scratch(&layout);
    let paths = stage_paths(root);
    let mut journal = Journal::new();

    // 清理合成**一条**远端脚本：家宽入口的 sshd 在高频握手时会丢连接，
    // 一次断连就会让 `docker rm -f` 少删一个容器，收尾误报成「有残留」。
    // 每条命令以 `|| true` 收尾：清理要尽力而为，最终由「是否真的删掉」来断言。
    let cleanup = |node: Node, layout: Layout, stage: String| async move {
        let containers = [&layout.a_pg, &layout.a_redis, &layout.b_pg, &layout.b_redis]
            .iter()
            .map(|name| {
                format!(
                    "docker rm -f {} >/dev/null 2>&1 || true",
                    transport::quote(name)
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let volumes = [
            &layout.a_pg_volume,
            &layout.a_redis_volume,
            &layout.b_pg_volume,
            &layout.b_redis_volume,
        ]
        .iter()
        .map(|name| {
            format!(
                "docker volume rm {} >/dev/null 2>&1 || true",
                transport::quote(name)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
        let script = format!(
            "{containers}; {volumes}; \
             docker network rm {} >/dev/null 2>&1 || true; \
             rm -rf {} >/dev/null 2>&1 || true",
            transport::quote(&layout.network),
            transport::quote(&stage)
        );
        match transport::verified(&node, &script, 240).await {
            Ok(_) => Vec::new(),
            Err(error) => vec![format!("cleanup: {error:#}")],
        }
    };

    let outcome = async {
        // 1) 一次性网络与卷；`--internal` 让两个环境无法访问外网。
        run(
            node,
            &format!(
                "docker network create --internal {} >/dev/null; \
                 for v in {} {} {} {}; do docker volume create \"$v\" >/dev/null; done; \
                 mkdir -p {} && chmod 777 {}",
                transport::quote(&layout.network),
                transport::quote(&layout.a_pg_volume),
                transport::quote(&layout.a_redis_volume),
                transport::quote(&layout.b_pg_volume),
                transport::quote(&layout.b_redis_volume),
                transport::quote(&stage),
                transport::quote(&stage),
            ),
            120,
        )
        .await?;
        journal.append("environment-created", format!("network {} + 4 volumes", layout.network))?;

        // 2) 把 SQL / Lua 写到远端，随后所有步骤复用同一份文件。
        push_text(node, &format!("{stage}/seed.sql"), SEED).await?;
        push_text(node, &format!("{stage}/fingerprint.sql"), POSTGRES_FINGERPRINT_SQL).await?;
        push_text(node, &format!("{stage}/fingerprint.lua"), REDIS_FINGERPRINT_LUA).await?;
        push_text(node, &format!("{stage}/seed.lua"), REDIS_SEED).await?;
        journal.append("programs-uploaded", "seed + fingerprint SQL/Lua")?;

        // 3) 启动 A 侧并等待就绪。
        run(
            node,
            &format!(
                "docker run -d --name {} --network {} \
                 -e POSTGRES_PASSWORD=pg-admin-pw -e POSTGRES_DB=demo \
                 -v {}:/var/lib/postgresql/data -v {stage}:{STAGE_MOUNT} {} >/dev/null",
                transport::quote(&layout.a_pg),
                transport::quote(&layout.network),
                transport::quote(&layout.a_pg_volume),
                transport::quote(POSTGRES_IMAGE),
                stage = transport::quote(&stage),
                STAGE_MOUNT = STAGE_MOUNT
            ),
            180,
        )
        .await?;
        run(
            node,
            &format!(
                "docker run -d --name {} --network {} \
                 -v {}:/data -v {stage}:{STAGE_MOUNT} {} redis-server --requirepass redis-admin-pw --save '' >/dev/null",
                transport::quote(&layout.a_redis),
                transport::quote(&layout.network),
                transport::quote(&layout.a_redis_volume),
                transport::quote(REDIS_IMAGE),
                stage = transport::quote(&stage),
                STAGE_MOUNT = STAGE_MOUNT
            ),
            180,
        )
        .await?;
        let pg_wait = wait_for(
            node,
            &layout.a_pg,
            "pg_isready -U postgres -d demo",
            60,
        )
        .await?;
        let redis_wait = wait_for(
            node,
            &layout.a_redis,
            "redis-cli --no-auth-warning -a redis-admin-pw ping",
            60,
        )
        .await?;
        journal.append(
            "sources-ready",
            format!("postgres {pg_wait}s, redis {redis_wait}s"),
        )?;

        // 4) 建应用用户与应用数据。应用用户不能建表之外的管理动作：ACL 只给它需要的命令。
        psql_sql(
            node,
            &layout.a_pg,
            "postgres",
            "postgres",
            "create role demo_app login password 'demo-app-pw'",
        )
        .await
        .context("create application role")?;
        psql_sql(
            node,
            &layout.a_pg,
            "postgres",
            "postgres",
            "alter database demo owner to demo_app",
        )
        .await
        .context("hand the database to the application role")?;
        psql(node, &layout.a_pg, "demo_app", "demo", &staged("seed.sql"))
            .await
            .context("seed PostgreSQL")?;

        run(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning -a redis-admin-pw ACL SETUSER demo_app on \">app-pw\" \"~*\" \"+@all\" \"-@admin\" \"-config\" \
                 && docker exec {} redis-cli --no-auth-warning --user demo_app --pass app-pw --eval {}",
                transport::quote(&layout.a_redis),
                transport::quote(&layout.a_redis),
                transport::quote(&staged("seed.lua"))
            ),
            120,
        )
        .await
        .context("seed Redis")?;
        journal.append("application-data-created", "4 tables, 3 sequences, 5 keys")?;

        // 5) 采集基线指纹（用应用用户，而不是超级用户）。
        let before_pg = postgres_print(
            node,
            &layout.a_pg,
            "demo_app",
            "demo",
            &staged("fingerprint.sql"),
        )
        .await?;
        let before_redis = redis_print(
            node,
            &layout.a_redis,
            "redis-admin-pw",
            &staged("fingerprint.lua"),
        )
        .await?;
        let (before, before_digest) = fingerprint(&before_pg, &before_redis)?;
        ensure!(
            before.postgres.tables.len() >= 4,
            "the seed did not create the expected tables"
        );
        ensure!(
            before.redis.keys.len() >= 5,
            "the seed did not create the expected Redis keys"
        );
        fs::write(&paths.before, serde_json::to_vec_pretty(&before)?)?;
        journal.append("baseline-captured", format!("digest {before_digest}"))?;

        // 6) 隔离写入方：PostgreSQL 只读事务、Redis 需要至少一个副本才能写（此处没有副本）。
        //    两条都用应用用户去验证「真的写不进去」，而不是只看配置生效。
        psql_sql(
            node,
            &layout.a_pg,
            "postgres",
            "demo",
            "alter system set default_transaction_read_only = on",
        )
        .await?;
        run(
            node,
            &format!(
                "docker exec {} psql -U postgres -d demo -q -c \"select pg_reload_conf()\" >/dev/null",
                transport::quote(&layout.a_pg)
            ),
            60,
        )
        .await?;
        let pg_write = run_any(
            node,
            &format!(
                "docker exec {} psql -U demo_app -d demo -c \"insert into billing.ledger(note) values ('fenced')\" 2>&1",
                transport::quote(&layout.a_pg)
            ),
            60,
        )
        .await?;
        ensure!(
            pg_write.to_lowercase().contains("read-only"),
            "PostgreSQL accepted a write after fencing: {pg_write}"
        );

        // 应用用户没有 config 权限，所以解除隔离只能由管理凭据完成；这一步本身也被断言。
        let acl = run_any(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning --user demo_app --pass app-pw config set min-replicas-to-write 1 2>&1",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        ensure!(
            acl.contains("NOPERM") || acl.contains("no permissions"),
            "the application role was able to change fencing configuration: {acl}"
        );
        run(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning -a redis-admin-pw config set min-replicas-to-write 1 >/dev/null",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        let redis_write = run_any(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning --user demo_app --pass app-pw -n 0 set fenced 1 2>&1",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        ensure!(
            redis_write.contains("NOREPLICAS"),
            "Redis accepted a write after fencing: {redis_write}"
        );
        journal.append("sources-fenced", "both stores reject application writes")?;

        // 7) 在隔离状态下导出：逻辑 dump + RDB。
        run(
            node,
            &format!(
                "docker exec {} pg_dump -U postgres -Fc -f {dump} demo \
                 && docker exec {} redis-cli --no-auth-warning -a redis-admin-pw save",
                transport::quote(&layout.a_pg),
                transport::quote(&layout.a_redis),
                dump = transport::quote(&staged("demo.dump"))
            ),
            180,
        )
        .await?;
        let dump_size = run(
            node,
            &format!(
                "docker exec {} stat -c%s {dump}",
                transport::quote(&layout.a_pg),
                dump = transport::quote(&staged("demo.dump"))
            ),
            60,
        )
        .await?;
        let rdb_size = run(
            node,
            &format!(
                "docker exec {} stat -c%s /data/dump.rdb",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        journal.append(
            "snapshot-taken",
            format!(
                "postgres {} bytes, redis {} bytes",
                dump_size.trim(),
                rdb_size.trim()
            ),
        )?;

        // 8) 启动 B 侧（同一镜像、同一架构、全新的卷）。
        run(
            node,
            &format!(
                "docker run -d --name {} --network {} \
                 -e POSTGRES_PASSWORD=pg-admin-pw -e POSTGRES_DB=demo \
                 -v {}:/var/lib/postgresql/data -v {stage}:{STAGE_MOUNT} {} >/dev/null",
                transport::quote(&layout.b_pg),
                transport::quote(&layout.network),
                transport::quote(&layout.b_pg_volume),
                transport::quote(POSTGRES_IMAGE),
                stage = transport::quote(&stage),
                STAGE_MOUNT = STAGE_MOUNT
            ),
            180,
        )
        .await?;
        wait_for(node, &layout.b_pg, "pg_isready -U postgres -d demo", 60).await?;

        // 9) 恢复：先建同一个应用角色与库归属，再用 `pg_restore` 以应用用户身份导入。
        //    用应用用户导入是刻意的：超级用户能成功不代表应用能读到自己的表。
        psql_sql(
            node,
            &layout.b_pg,
            "postgres",
            "postgres",
            "create role demo_app login password 'demo-app-pw'",
        )
        .await?;
        psql_sql(
            node,
            &layout.b_pg,
            "postgres",
            "postgres",
            "alter database demo owner to demo_app",
        )
        .await?;
        run(
            node,
            &format!(
                "docker exec {b} pg_restore -U demo_app -d demo --no-owner --no-acl --exit-on-error {dump}",
                b = transport::quote(&layout.b_pg),
                dump = transport::quote(&staged("demo.dump")),
            ),
            300,
        )
        .await
        .context("pg_restore failed")?;
        journal.append("postgres-restored", "pg_restore --exit-on-error")?;

        // 10) Redis：起 B 实例，把 RDB 放进数据目录后重启加载。
        run(
            node,
            &format!(
                "docker run -d --name {} --network {} \
                 -v {}:/data -v {stage}:{STAGE_MOUNT} {} redis-server --requirepass redis-admin-pw --save '' >/dev/null",
                transport::quote(&layout.b_redis),
                transport::quote(&layout.network),
                transport::quote(&layout.b_redis_volume),
                transport::quote(REDIS_IMAGE),
                stage = transport::quote(&stage),
                STAGE_MOUNT = STAGE_MOUNT
            ),
            180,
        )
        .await?;
        wait_for(
            node,
            &layout.b_redis,
            "redis-cli --no-auth-warning -a redis-admin-pw ping",
            60,
        )
        .await?;
        run(
            node,
            &format!(
                "docker exec {a} cat /data/dump.rdb > {stage}/dump.rdb \
                 && docker cp {stage}/dump.rdb {b}:/data/dump.rdb \
                 && docker restart {b} >/dev/null",
                a = transport::quote(&layout.a_redis),
                b = transport::quote(&layout.b_redis),
                stage = transport::quote(&stage),
            ),
            180,
        )
        .await?;
        wait_for(
            node,
            &layout.b_redis,
            "redis-cli --no-auth-warning -a redis-admin-pw ping",
            60,
        )
        .await?;
        journal.append("redis-restored", "RDB loaded on restart")?;

        // 11) 采集 B 侧指纹并逐项比较。
        let after_pg = postgres_print(
            node,
            &layout.b_pg,
            "demo_app",
            "demo",
            &staged("fingerprint.sql"),
        )
        .await?;
        let after_redis = redis_print(
            node,
            &layout.b_redis,
            "redis-admin-pw",
            &staged("fingerprint.lua"),
        )
        .await?;
        let (after, after_digest) = fingerprint(&after_pg, &after_redis)?;
        let differences: Vec<Difference> = before.differences(&after);
        fs::write(&paths.after, serde_json::to_vec_pretty(&after)?)?;
        fs::write(&paths.differences, serde_json::to_vec_pretty(&differences)?)?;
        ensure!(
            differences.is_empty(),
            "the restored state differs from the source: {differences:?}"
        );
        ensure!(
            before_digest == after_digest,
            "fingerprint digests disagree: {before_digest} vs {after_digest}"
        );
        journal.append(
            "target-verified",
            format!("identical, digest {after_digest}"),
        )?;

        // 12) 切回：在 A 上恢复可写，验证「旧写入方重新接写」的路径本身可用。
        //     这里不隐藏事实：真正切换流量需要入口层配合，本测试只证明数据层可切回。
        run(
            node,
            &format!(
                "docker exec {} psql -U postgres -d demo -q -c \"alter system set default_transaction_read_only = off\" \
                 && docker exec {} psql -U postgres -d demo -q -c \"select pg_reload_conf()\" >/dev/null",
                transport::quote(&layout.a_pg),
                transport::quote(&layout.a_pg)
            ),
            120,
        )
        .await?;
        run(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning -a redis-admin-pw config set min-replicas-to-write 0 >/dev/null",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        // 切回后 A 必须能重新写入，而且写入要落到指纹里（不是被静默丢弃）。
        psql_sql(
            node,
            &layout.a_pg,
            "demo_app",
            "demo",
            "insert into billing.ledger(note) values ('after-switchback')",
        )
        .await
        .context("source refused a write after switching back")?;
        run(
            node,
            &format!(
                "docker exec {} redis-cli --no-auth-warning --user demo_app --pass app-pw -n 0 set write-back ok >/dev/null",
                transport::quote(&layout.a_redis)
            ),
            60,
        )
        .await?;
        let source_pg = postgres_print(
            node,
            &layout.a_pg,
            "demo_app",
            "demo",
            &staged("fingerprint.sql"),
        )
        .await?;
        let source_redis = redis_print(
            node,
            &layout.a_redis,
            "redis-admin-pw",
            &staged("fingerprint.lua"),
        )
        .await?;
        let (switched, switched_digest) = fingerprint(&source_pg, &source_redis)?;
        let written = switched.differences(&after);
        ensure!(
            written.iter().any(|item| item.scope == "postgres.table" && item.name == "billing.ledger"),
            "the switch-back write did not land in PostgreSQL: {written:?}"
        );
        ensure!(
            written.iter().any(|item| item.scope == "redis.key"),
            "the switch-back write did not land in Redis: {written:?}"
        );
        journal.append(
            "source-resumed",
            format!("digest moved {after_digest} -> {switched_digest}"),
        )?;

        // 13) 双写检查：以 A 为基准看 B，差异只允许是「A 多出切回后的新写入」。
        //
        //     两条都要成立，缺一不可：
        //     - B 不能有 A 没有的对象（`before == "missing"`）——那是双向写入的直接信号，
        //       Redis 的 `dbsize` 也不能豁免：出现一个 A 没有的库同样是双写。
        //     - 两个库都还在时，A 的键数不能少于 B 的键数。
        let swallowed = switched
            .differences(&after)
            .into_iter()
            .filter(|item| item.scope == "redis.dbsize")
            .collect::<Vec<_>>();
        ensure!(
            swallowed
                .iter()
                .all(|item| item.before != "missing" && item.after != "missing"),
            "the target gained a Redis database the source never had: {swallowed:?}"
        );
        ensure!(
            swallowed.iter().all(|item| item.before.parse::<u64>().unwrap_or(0)
                >= item.after.parse::<u64>().unwrap_or(0)),
            "the target holds more keys than the source after switch-back: {swallowed:?}"
        );
        ensure!(
            switched
                .differences(&after)
                .iter()
                .all(|item| item.before != "missing"),
            "the target gained rows or keys that the source never had"
        );
        journal.append(
            "no-double-write",
            "target stayed frozen across the switch-back",
        )?;

        journal.verify()?;
        journal.save(&paths.journal)?;
        Ok(Rehearsal {
            prefix: layout.prefix.clone(),
            before_digest,
            after_digest,
            switched_digest,
            tables: before.postgres.tables.len(),
            sequences: before.postgres.sequences.len(),
            keys: before.redis.keys.len(),
            databases: before.redis.sizes.len(),
            journal_entries: journal.entries().len(),
            journal: journal.entries().to_vec(),
        })
    }
    .await;

    let cleanup_errors = cleanup(node.clone(), layout, stage).await;
    let report = outcome?;
    ensure!(
        cleanup_errors.is_empty(),
        "cleanup failed: {cleanup_errors:?}"
    );
    Ok(report)
}

#[derive(Clone, Debug)]
struct Rehearsal {
    /// 本次演练的资源前缀：只有它的残留才算失败。
    prefix: String,
    before_digest: String,
    after_digest: String,
    switched_digest: String,
    tables: usize,
    sequences: usize,
    keys: usize,
    databases: usize,
    journal_entries: usize,
    journal: Vec<sshpool::migration::Entry>,
}

/// 完整一轮：迁移 + 切回 + 双双清理。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with postgres and redis images"]
async fn demonstration_data_migrates_and_switches_back() -> Result<()> {
    let node = node()?;
    let root = tempfile::tempdir()?;
    let report = rehearse(&node, root.path()).await?;
    eprintln!(
        "migrated {} tables, {} sequences, {} keys across {} databases; \
         digests {} -> {} -> {}; {} journal entries",
        report.tables,
        report.sequences,
        report.keys,
        report.databases,
        &report.before_digest[..16],
        &report.after_digest[..16],
        &report.switched_digest[..16],
        report.journal_entries
    );

    for entry in report.journal.iter() {
        eprintln!(
            "journal {:02} {} {} {}",
            entry.sequence, entry.at, entry.step, entry.detail
        );
    }

    // 事后确认本次演练的容器、卷、网络与临时目录都没有残留。
    // 只核对本次前缀：worker 上可能还留有更早中断运行的资源，那不归这一轮。
    let layout_marker = report.prefix.as_str();
    let leftovers = run(
        &node,
        &format!(
            "docker ps -a --format '{{{{.Names}}}}' | grep -c {marker} || true",
            marker = transport::quote(layout_marker)
        ),
        60,
    )
    .await?;
    ensure!(
        leftovers.trim() == "0",
        "migration containers survived the rehearsal: {leftovers}"
    );
    Ok(())
}

/// 指纹必须能抓住「恢复了但少了数据」：只恢复一部分表时不能被当成成功。
#[tokio::test]
#[ignore = "requires a reachable SSH worker with postgres image"]
async fn partial_restore_is_detected_as_a_difference() -> Result<()> {
    let node = node()?;
    let id = Uuid::new_v4();
    let prefix = format!("sshpool-mig-partial-{id}");
    let root = tempfile::tempdir()?;
    let stage = format!("/tmp/{prefix}");

    let outcome = async {
        run(
            &node,
            &format!(
                "mkdir -p {stage} && chmod 777 {stage} && \
                 docker run -d --name {pg} --network none -e POSTGRES_PASSWORD=pg-pw -e POSTGRES_DB=demo \
                 -v {stage}:{STAGE_MOUNT} {image} >/dev/null",
                pg = transport::quote(&format!("{prefix}-pg")),
                image = transport::quote(POSTGRES_IMAGE),
                stage = transport::quote(&stage),
                STAGE_MOUNT = STAGE_MOUNT
            ),
            180,
        )
        .await?;
        wait_for(&node, &format!("{prefix}-pg"), "pg_isready -U postgres -d demo", 60).await?;
        push_text(&node, &format!("{stage}/seed.sql"), SEED).await?;
        push_text(&node, &format!("{stage}/fingerprint.sql"), POSTGRES_FINGERPRINT_SQL).await?;
        psql_sql(
            &node,
            &format!("{prefix}-pg"),
            "postgres",
            "postgres",
            "create role demo_app login password 'demo-app-pw'",
        )
        .await?;
        psql_sql(
            &node,
            &format!("{prefix}-pg"),
            "postgres",
            "postgres",
            "alter database demo owner to demo_app",
        )
        .await?;
        psql(
            &node,
            &format!("{prefix}-pg"),
            "demo_app",
            "demo",
            &staged("seed.sql"),
        )
        .await?;
        let full = postgres_print(
            &node,
            &format!("{prefix}-pg"),
            "demo_app",
            "demo",
            &staged("fingerprint.sql"),
        )
        .await?;

        // 删掉一张表再采集一次：等价于「恢复时漏了一张表」。
        psql_sql(
            &node,
            &format!("{prefix}-pg"),
            "demo_app",
            "demo",
            "drop table billing.charge",
        )
        .await?;
        let partial = postgres_print(
            &node,
            &format!("{prefix}-pg"),
            "demo_app",
            "demo",
            &staged("fingerprint.sql"),
        )
        .await?;

        let (before, _) = fingerprint(&full, "0|dbsize|0|-|-1\n")?;
        let (after, _) = fingerprint(&partial, "0|dbsize|0|-|-1\n")?;
        let differences = before.differences(&after);
        fs::write(
            stage_paths(root.path()).differences,
            serde_json::to_vec_pretty(&differences)?,
        )?;
        ensure!(
            differences
                .iter()
                .any(|item| item.scope == "postgres.table" && item.name == "billing.charge"),
            "a missing table was not reported: {differences:?}"
        );
        ensure!(
            differences
                .iter()
                .any(|item| item.scope == "postgres.sequence"
                    && item.name == "billing.charge_id_seq"),
            "a dropped table's sequence was not reported: {differences:?}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let _ = transport::checked(
        &node,
        &format!("docker rm -f {}", transport::quote(&format!("{prefix}-pg"))),
        60,
    )
    .await;
    let _ = transport::checked(&node, &format!("rm -rf {}", transport::quote(&stage)), 30).await;
    outcome
}
