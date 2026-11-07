//! 状态迁移演练的可复用部分：内容级指纹、差异报告与链式操作日志。
//!
//! 「恢复成功」不能只看 `pg_restore` 的退出码：一个空的、错的或者只恢复了一半的库
//! 同样会退出 0。这里把「迁移前后是不是同一份数据」变成可比对的指纹，并且要求每一步
//! 迁移动作都写进一条链式日志（后一条包含前一条的摘要），以此证明操作顺序没有被
//! 事后编辑。
//!
//! 这里只做判定与记录，真正的容器编排在 `tests/migration_live.rs` 里；两者共用同一份
//! SQL 与 Lua，避免「测试用它、文档写另一个」。
use crate::{archive, config};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// PostgreSQL 指纹查询：每张用户表的行数与内容摘要，加上每个序列的 last_value。
///
/// 摘要按行计算再对排序后的行摘要做一次总摘要，所以它同时是「内容」和「多重集」的
/// 指纹：行顺序变了不影响结论，行内容变了立刻不同。只读，且只读 `pg_catalog` 与用户表。
pub const POSTGRES_FINGERPRINT_SQL: &str = r#"
with tables as (
  select n.nspname::text as sch, c.relname::text as tbl
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'r' and n.nspname not in ('pg_catalog', 'information_schema')
), agg as (
  select t.sch, t.tbl,
    format('select count(*) as n, coalesce(md5(string_agg(md5(t::text), %L order by md5(t::text))), %L) as h from %I.%I t', '', '-', t.sch, t.tbl) as q
  from tables t
), digest as (
  select a.sch, a.tbl,
    (xpath('/row/n/text()', query_to_xml(a.q, false, true, '')))[1]::text::bigint as n,
    (xpath('/row/h/text()', query_to_xml(a.q, false, true, '')))[1]::text as h
  from agg a
)
select 'table|' || sch || '.' || tbl || '|' || n || '|' || h from digest
union all
select 'sequence|' || schemaname || '.' || sequencename || '|' || coalesce(last_value::text, '-')
from pg_sequences where schemaname not in ('pg_catalog', 'information_schema')
order by 1;
"#;

/// Redis 指纹：在服务端按 DB 枚举键，输出键名、值摘要与过期时间桶。
///
/// 键名与值都可能含任意二进制（包括换行与 `|`），所以两侧都取 SHA-1 而不是原样输出；
/// 这样输出永远是可解析的 ASCII，不会因为一个键名就把整份报告拆错。
pub const REDIS_FINGERPRINT_LUA: &str = r#"
local dbs = {}
for _, value in ipairs(ARGV) do
  dbs[#dbs + 1] = tonumber(value)
end
local limit = 20000
local total = 0
local lines = {}
for _, db in ipairs(dbs) do
  redis.call('SELECT', db)
  local cursor = '0'
  local count = 0
  repeat
    local reply = redis.call('SCAN', cursor, 'COUNT', 500)
    cursor = reply[1]
    for _, key in ipairs(reply[2]) do
      count = count + 1
      total = total + 1
      if total > limit then
        return redis.error_reply('fingerprint exceeds ' .. limit .. ' keys')
      end
      local kind = redis.call('TYPE', key)['ok']
      local payload
      if kind == 'string' then
        payload = redis.call('GET', key)
      elseif kind == 'list' then
        payload = redis.call('LRANGE', key, 0, -1)
      elseif kind == 'set' then
        payload = redis.call('SMEMBERS', key)
      elseif kind == 'hash' then
        payload = redis.call('HGETALL', key)
      elseif kind == 'zset' then
        payload = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
      elseif kind == 'stream' then
        payload = redis.call('XRANGE', key, '-', '+')
      else
        return redis.error_reply('unsupported type ' .. kind)
      end
      local parts = {kind}
      if type(payload) == 'string' then
        parts[#parts + 1] = payload
      else
        for _, item in ipairs(payload) do
          if type(item) == 'table' then
            for _, field in ipairs(item) do
              parts[#parts + 1] = tostring(field)
            end
          else
            parts[#parts + 1] = tostring(item)
          end
        end
      end
      local blob = table.concat(parts, '\0')
      -- 过期时间按分钟取桶：一次真实迁移在分钟量级完成，绝对毫秒会因观测时刻不同
      -- 而永远不相等，那会把「数据一致」误判成「不一致」。
      local expiry = redis.call('PEXPIRETIME', key)
      local bucket = '-1'
      if expiry >= 0 then
        bucket = tostring(math.floor(expiry / 60000))
      end
      lines[#lines + 1] = table.concat({
        tostring(db), kind, redis.sha1hex(key), redis.sha1hex(blob), bucket
      }, '|')
    end
  until cursor == '0'
  lines[#lines + 1] = table.concat({tostring(db), 'dbsize', tostring(count), '-', '-1'}, '|')
end
table.sort(lines)
return lines
"#;

/// 一张表或一个序列的指纹。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TablePrint {
    pub name: String,
    /// 表是行数，序列是 `last_value`。
    pub rows: u64,
    /// 表是内容摘要，序列是 `-`（序列只有当前值有意义）。
    pub digest: String,
}

/// PostgreSQL 侧的完整指纹，按名字排序，便于逐项比较。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresPrint {
    pub tables: Vec<TablePrint>,
    pub sequences: Vec<TablePrint>,
}

/// 一个 Redis 键的指纹；键名只保留 SHA-1，报告本身不含真实键名。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPrint {
    pub database: u32,
    pub kind: String,
    pub key_sha1: String,
    pub value_sha1: String,
    /// `-1` 表示永不过期，否则是过期时刻的分钟桶。
    pub expiry_bucket: i64,
}

/// Redis 侧指纹；`sizes` 记录每个库的键数，用来发现「键集合少了一半」这类差异。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPrint {
    pub keys: Vec<KeyPrint>,
    pub sizes: BTreeMap<u32, u64>,
}

/// 两侧共用的比较入口：桌面端与演练都拿这两个值判断「是不是同一份状态」。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub postgres: PostgresPrint,
    pub redis: RedisPrint,
}

/// 一处具体差异；报告里逐条列出而不是只说「不一致」。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    /// `postgres.table` / `postgres.sequence` / `redis.key` / `redis.dbsize`。
    pub scope: String,
    /// 对象名；Redis 键在这里是 `db:sha1`，不含明文键名。
    pub name: String,
    pub before: String,
    pub after: String,
}

/// 解析 PostgreSQL 指纹输出。任何一行不符合约定都失败关闭。
pub fn parse_postgres(source: &str) -> Result<PostgresPrint> {
    let mut tables = Vec::new();
    let mut sequences = Vec::new();
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split('|').collect::<Vec<_>>();
        match fields[0] {
            // 表是 `table|schema.table|行数|内容摘要`。
            "table" => {
                ensure!(
                    fields.len() == 4,
                    "unexpected PostgreSQL fingerprint line: {line}"
                );
                let (schema, table) = split_qualified(fields[1])?;
                ensure!(valid_identifier(schema), "invalid table schema name");
                ensure!(valid_identifier(table), "invalid table name");
                tables.push(TablePrint {
                    name: format!("{schema}.{table}"),
                    rows: fields[2]
                        .parse()
                        .with_context(|| format!("invalid row count for {line}"))?,
                    digest: digest_field(fields[3])?,
                });
            }
            // 序列是 `sequence|schema.name|last_value`：序列没有内容摘要。
            "sequence" => {
                ensure!(
                    fields.len() == 3,
                    "unexpected PostgreSQL fingerprint line: {line}"
                );
                let (schema, sequence) = split_qualified(fields[1])?;
                ensure!(valid_identifier(schema), "invalid sequence schema name");
                ensure!(valid_identifier(sequence), "invalid sequence name");
                let last = fields[2];
                ensure!(
                    last == "-" || last.parse::<i64>().is_ok(),
                    "invalid sequence value for {line}"
                );
                sequences.push(TablePrint {
                    name: format!("{schema}.{sequence}"),
                    rows: if last == "-" {
                        0
                    } else {
                        last.parse::<u64>()
                            .with_context(|| format!("invalid sequence value for {line}"))?
                    },
                    digest: "-".into(),
                });
            }
            other => anyhow::bail!("unexpected PostgreSQL fingerprint kind: {other}"),
        }
    }
    ensure!(!tables.is_empty(), "PostgreSQL fingerprint has no tables");
    tables.sort_by(|left, right| left.name.cmp(&right.name));
    sequences.sort_by(|left, right| left.name.cmp(&right.name));
    ensure_unique(
        &tables
            .iter()
            .map(|item| item.name.clone())
            .collect::<Vec<_>>(),
    )?;
    ensure_unique(
        &sequences
            .iter()
            .map(|item| item.name.clone())
            .collect::<Vec<_>>(),
    )?;
    Ok(PostgresPrint { tables, sequences })
}

/// 解析 Redis 指纹输出；键名不可解析（只会是 40 位 SHA-1）。
pub fn parse_redis(source: &str) -> Result<RedisPrint> {
    let mut keys = Vec::new();
    let mut sizes = BTreeMap::new();
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split('|').collect::<Vec<_>>();
        ensure!(
            fields.len() == 5,
            "unexpected Redis fingerprint line: {line}"
        );
        let database: u32 = fields[0]
            .parse()
            .with_context(|| format!("invalid Redis database in {line}"))?;
        ensure!(database < 1024, "Redis database number out of range");
        if fields[1] == "dbsize" {
            let count: u64 = fields[2]
                .parse()
                .with_context(|| format!("invalid Redis dbsize in {line}"))?;
            ensure!(
                sizes.insert(database, count).is_none(),
                "duplicate Redis dbsize for db{database}"
            );
            continue;
        }
        ensure!(!fields[1].is_empty(), "missing Redis key type");
        keys.push(KeyPrint {
            database,
            kind: fields[1].to_owned(),
            key_sha1: sha1_field(fields[2], "key")?,
            value_sha1: sha1_field(fields[3], "value")?,
            expiry_bucket: fields[4]
                .parse()
                .with_context(|| format!("invalid Redis expiry in {line}"))?,
        });
    }
    keys.sort_by(|left, right| {
        (left.database, &left.key_sha1).cmp(&(right.database, &right.key_sha1))
    });
    ensure_unique(
        &keys
            .iter()
            .map(|item| format!("{}:{}", item.database, item.key_sha1))
            .collect::<Vec<_>>(),
    )?;
    // 每个出现过的库都必须有且只有一个 dbsize 行，否则「键全部丢失」会被读成「空库」。
    for database in keys.iter().map(|key| key.database) {
        ensure!(
            sizes.contains_key(&database),
            "Redis fingerprint is missing dbsize for db{database}"
        );
    }
    for (database, size) in &sizes {
        let actual = keys.iter().filter(|key| key.database == *database).count() as u64;
        ensure!(
            actual == *size,
            "Redis fingerprint claims {size} keys in db{database} but lists {actual}"
        );
    }
    Ok(RedisPrint { keys, sizes })
}

/// 组合两侧指纹，并计算出「同一份状态」的单一字符串，便于写进日志与证据。
pub fn fingerprint(postgres: &str, redis: &str) -> Result<(Fingerprint, String)> {
    let print = Fingerprint {
        postgres: parse_postgres(postgres)?,
        redis: parse_redis(redis)?,
    };
    let digest = print.digest()?;
    Ok((print, digest))
}

impl Fingerprint {
    /// 逐项差异；空表示一致。顺序稳定，输出可直接比较。
    pub fn differences(&self, other: &Fingerprint) -> Vec<Difference> {
        let mut out = Vec::new();
        diff_tables(
            "postgres.table",
            &self.postgres.tables,
            &other.postgres.tables,
            &mut out,
        );
        diff_tables(
            "postgres.sequence",
            &self.postgres.sequences,
            &other.postgres.sequences,
            &mut out,
        );

        let before = self
            .redis
            .keys
            .iter()
            .map(|key| (format!("{}:{}", key.database, key.key_sha1), key))
            .collect::<BTreeMap<_, _>>();
        let after = other
            .redis
            .keys
            .iter()
            .map(|key| (format!("{}:{}", key.database, key.key_sha1), key))
            .collect::<BTreeMap<_, _>>();
        // 用集合并集去重：直接 chain 两边会让「两边都有但不同」的名字出现两次。
        let names = before
            .keys()
            .chain(after.keys())
            .collect::<std::collections::BTreeSet<_>>();
        for name in names {
            match (before.get(name), after.get(name)) {
                (Some(left), Some(right)) if left == right => {}
                (Some(left), Some(right)) => out.push(Difference {
                    scope: "redis.key".into(),
                    name: name.clone(),
                    before: format!("{}:{}:{}", left.kind, left.value_sha1, left.expiry_bucket),
                    after: format!(
                        "{}:{}:{}",
                        right.kind, right.value_sha1, right.expiry_bucket
                    ),
                }),
                (Some(left), None) => out.push(Difference {
                    scope: "redis.key".into(),
                    name: name.clone(),
                    before: format!("{}:{}:{}", left.kind, left.value_sha1, left.expiry_bucket),
                    after: "missing".into(),
                }),
                (None, Some(right)) => out.push(Difference {
                    scope: "redis.key".into(),
                    name: name.clone(),
                    before: "missing".into(),
                    after: format!(
                        "{}:{}:{}",
                        right.kind, right.value_sha1, right.expiry_bucket
                    ),
                }),
                (None, None) => {}
            }
        }
        for database in self
            .redis
            .sizes
            .keys()
            .chain(other.redis.sizes.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let left = self.redis.sizes.get(database).copied();
            let right = other.redis.sizes.get(database).copied();
            if left != right {
                out.push(Difference {
                    scope: "redis.dbsize".into(),
                    name: format!("db{database}"),
                    before: left.map_or_else(|| "missing".into(), |v| v.to_string()),
                    after: right.map_or_else(|| "missing".into(), |v| v.to_string()),
                });
            }
        }
        out
    }

    /// 整个指纹的单一摘要，写进日志与证据；两侧都被覆盖。
    pub fn digest(&self) -> Result<String> {
        Ok(archive::sha256_bytes(
            &serde_json::to_vec(self).context("cannot serialize fingerprint")?,
        ))
    }
}

/// 表与序列共用同一套比较逻辑，只是 `scope` 不同。
fn diff_tables(
    scope: &str,
    before: &[TablePrint],
    after: &[TablePrint],
    out: &mut Vec<Difference>,
) {
    let before = before
        .iter()
        .map(|item| (item.name.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .iter()
        .map(|item| (item.name.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let names = before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>();
    for name in names {
        match (before.get(name), after.get(name)) {
            (Some(left), Some(right)) if left == right => {}
            (Some(left), Some(right)) => out.push(Difference {
                scope: scope.to_owned(),
                name: (*name).to_owned(),
                before: format!("{}:{}", left.rows, left.digest),
                after: format!("{}:{}", right.rows, right.digest),
            }),
            (Some(left), None) => out.push(Difference {
                scope: scope.to_owned(),
                name: (*name).to_owned(),
                before: format!("{}:{}", left.rows, left.digest),
                after: "missing".into(),
            }),
            (None, Some(right)) => out.push(Difference {
                scope: scope.to_owned(),
                name: (*name).to_owned(),
                before: "missing".into(),
                after: format!("{}:{}", right.rows, right.digest),
            }),
            (None, None) => {}
        }
    }
}

/// 链式操作日志的一条记录。
///
/// `hash` 覆盖 `previous` 与自身全部字段，所以删掉中间一条、改一条、或者调换顺序，
/// 都会让后续某一条的链断开。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub sequence: u64,
    pub at: u64,
    pub step: String,
    pub detail: String,
    pub previous: String,
    pub hash: String,
}

/// 迁移操作日志：只追加，每条都绑定前一条。
///
/// 「保留原数据与可恢复的操作记录」这句要求的就是它：日志本身可离线校验，
/// 不依赖迁移过程还活着。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    entries: Vec<Entry>,
}

impl Journal {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 从磁盘读回并立即校验链；损坏的日志不能被当作「没有迁移过」。
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("cannot read journal {}", path.display()))?;
        let mut entries = Vec::new();
        for (index, line) in source.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: Entry = serde_json::from_str(line)
                .with_context(|| format!("invalid journal line {}", index + 1))?;
            entries.push(entry);
        }
        let journal = Self { entries };
        journal.verify()?;
        Ok(journal)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// 追加一条记录；`step` 与 `detail` 必须是调用方写死的常量与可核对的结果。
    pub fn append(&mut self, step: &str, detail: impl Into<String>) -> Result<&Entry> {
        ensure!(!step.trim().is_empty(), "journal step cannot be empty");
        let sequence = self.entries.len() as u64;
        let previous = self
            .entries
            .last()
            .map_or_else(|| "genesis".to_string(), |entry| entry.hash.clone());
        let at = crate::model::now();
        let detail = detail.into();
        let hash = hash_entry(sequence, at, step, &detail, &previous)?;
        self.entries.push(Entry {
            sequence,
            at,
            step: step.to_owned(),
            detail,
            previous,
            hash,
        });
        self.entries.last().context("entry disappeared")
    }

    /// 校验整条链：序号连续、`previous` 指向前一条的 `hash`、`hash` 可复算。
    pub fn verify(&self) -> Result<()> {
        let mut previous = "genesis".to_string();
        for (index, entry) in self.entries.iter().enumerate() {
            ensure!(
                entry.sequence == index as u64,
                "journal sequence is not contiguous at {index}"
            );
            ensure!(
                entry.previous == previous,
                "journal chain is broken at {index}"
            );
            let expected = hash_entry(
                entry.sequence,
                entry.at,
                &entry.step,
                &entry.detail,
                &entry.previous,
            )?;
            ensure!(entry.hash == expected, "journal entry {index} was edited");
            previous = entry.hash.clone();
        }
        Ok(())
    }

    /// 写入磁盘；已存在的日志不覆盖，避免两轮演练互相覆盖证据。
    pub fn save(&self, path: &Path) -> Result<()> {
        self.verify()?;
        ensure!(!path.exists(), "journal already exists: {}", path.display());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut text = String::new();
        for entry in &self.entries {
            text.push_str(&serde_json::to_string(entry)?);
            text.push('\n');
        }
        config::atomic_write(path, text.as_bytes())
    }

    /// 单独写一条到磁盘的追加式日志（崩溃后仍可读到最后一条完整记录）。
    pub fn append_to(path: &Path, step: &str, detail: impl Into<String>) -> Result<Entry> {
        let mut journal = if path.exists() {
            Self::load(path)?
        } else {
            Self::new()
        };
        let entry = journal.append(step, detail)?.clone();
        let json = serde_json::to_string(&entry)?;
        use std::io::Write;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{json}")?;
        file.sync_all()?;
        Ok(entry)
    }
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_entry(sequence: u64, at: u64, step: &str, detail: &str, previous: &str) -> Result<String> {
    let material = serde_json::json!({
        "sequence": sequence,
        "at": at,
        "step": step,
        "detail": detail,
        "previous": previous,
    });
    Ok(archive::sha256_bytes(&serde_json::to_vec(&material)?))
}

fn split_qualified(value: &str) -> Result<(&str, &str)> {
    let (schema, table) = value
        .split_once('.')
        .with_context(|| format!("expected schema-qualified name: {value}"))?;
    ensure!(
        !schema.is_empty() && !table.is_empty() && !table.contains('.'),
        "invalid qualified name: {value}"
    );
    Ok((schema, table))
}

fn digest_field(value: &str) -> Result<String> {
    ensure!(value != "-", "table digest is missing");
    ensure!(
        value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid table digest: {value}"
    );
    Ok(value.to_ascii_lowercase())
}

fn sha1_field(value: &str, what: &str) -> Result<String> {
    ensure!(
        value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid Redis {what} digest: {value}"
    );
    Ok(value.to_ascii_lowercase())
}

fn ensure_unique(values: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        ensure!(seen.insert(value.clone()), "duplicate entry: {value}");
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// 演练产物路径：日志、两侧指纹与差异报告放在同一个目录，便于整包留档。
pub fn stage_paths(root: &Path) -> StagePaths {
    StagePaths {
        journal: root.join("migration-journal.jsonl"),
        before: root.join("fingerprint-before.json"),
        after: root.join("fingerprint-after.json"),
        differences: root.join("differences.json"),
    }
}

/// 一次演练在磁盘上的固定位置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagePaths {
    pub journal: PathBuf,
    pub before: PathBuf,
    pub after: PathBuf,
    pub differences: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::{
        Difference, Fingerprint, Journal, POSTGRES_FINGERPRINT_SQL, REDIS_FINGERPRINT_LUA,
        parse_postgres, parse_redis, stage_paths,
    };

    const POSTGRES: &str = "sequence|billing.charge_id_seq|3\n\
        table|billing.account|3|c19369add11373fb9910a51df429e1c8\n\
        table|billing.charge|3|ee34e4a956b0effdb81bc6568136da3e\n\
        table|public.session|2|517b282f3e1f5e94560185d59c0713f5\n";

    const REDIS: &str = "0|dbsize|2|-|-1\n\
        0|string|65e00fff84d2d7e34c703efc2d2f20c106039bf7|809690d94bbb98cbfdc63b0a10e9ea3d3857868e|-1\n\
        0|string|d94d2e2f9b50c5a2c1d2e0c8b3f2a10b1f9c3e57|37f1d6b5b1f3c04a0d5a2f7e6c1b9a8d4e2f0c13|-1\n\
        3|dbsize|1|-|-1\n\
        3|string|5d66c1800bab669516cd78c12aaebbf83266cb6e|5d66c1800bab669516cd78c12aaebbf83266cb6e|-1\n";

    fn print() -> Fingerprint {
        Fingerprint {
            postgres: parse_postgres(POSTGRES).expect("postgres print"),
            redis: parse_redis(REDIS).expect("redis print"),
        }
    }

    /// 指纹要能把「表还在但内容变了」和「序列值回退」都识别出来。
    #[test]
    fn postgres_fingerprint_reports_row_and_sequence_changes() {
        let before = print();
        let mut after = before.clone();
        after.postgres.tables[0].digest = "0".repeat(32);
        after.postgres.tables[1].rows = 4;
        after.postgres.sequences[0].rows = 99;
        let differences = before.differences(&after);
        let scopes = differences
            .iter()
            .map(|item| (item.scope.as_str(), item.name.as_str()))
            .collect::<Vec<_>>();
        assert!(
            scopes.contains(&("postgres.table", "billing.account")),
            "{scopes:?}"
        );
        assert!(
            scopes.contains(&("postgres.table", "billing.charge")),
            "{scopes:?}"
        );
        assert!(
            scopes.contains(&("postgres.sequence", "billing.charge_id_seq")),
            "{scopes:?}"
        );
        assert_eq!(
            before.differences(&before.clone()),
            Vec::<Difference>::new()
        );
    }

    /// Redis 侧：键丢失、值变化、库大小变化都要单独报出来。
    #[test]
    fn redis_fingerprint_reports_missing_keys_and_resized_databases() {
        let before = print();
        let mut after = print();
        let removed = after
            .redis
            .keys
            .iter()
            .position(|key| key.key_sha1.starts_with("65e0"))
            .expect("seeded key");
        after.redis.keys.remove(removed);
        let changed = after
            .redis
            .keys
            .iter_mut()
            .find(|key| key.database == 3)
            .expect("db3 key");
        changed.value_sha1 = "f".repeat(40);
        after.redis.sizes.insert(0, 1);
        let differences = before.differences(&after);
        let scope = |name: &str| {
            differences
                .iter()
                .any(|item| item.scope == "redis.key" && item.name == name)
        };
        assert!(
            scope("0:65e00fff84d2d7e34c703efc2d2f20c106039bf7"),
            "{differences:?}"
        );
        assert!(
            scope("3:5d66c1800bab669516cd78c12aaebbf83266cb6e"),
            "{differences:?}"
        );
        // 没动过的键不能出现在差异里。
        assert!(
            !scope("0:d94d2e2f9b50c5a2c1d2e0c8b3f2a10b1f9c3e57"),
            "{differences:?}"
        );
        assert!(
            differences
                .iter()
                .any(|item| item.scope == "redis.dbsize" && item.name == "db0"),
            "{differences:?}"
        );
    }

    /// 过期时间只在同一个分钟桶里才算一致；跨桶就是真的不同。
    #[test]
    fn redis_expiry_is_compared_at_minute_granularity() {
        let mut before = print();
        let mut after = print();
        before.redis.keys[0].expiry_bucket = 29_901_245;
        after.redis.keys[0].expiry_bucket = 29_901_245;
        assert!(before.differences(&after).is_empty());
        after.redis.keys[0].expiry_bucket = 29_901_246;
        assert!(!before.differences(&after).is_empty());
    }

    /// 解析必须失败关闭：字段数、摘要形状、重复对象、缺失 dbsize 都不能猜。
    #[test]
    fn fingerprint_parsing_refuses_malformed_input() {
        for bad in [
            "",
            "table|billing.account|3\n",
            "table|billing.account|three|ab\n",
            "table|billing|3|c19369add11373fb9910a51df429e1c8\n",
            "view|billing.account|3|c19369add11373fb9910a51df429e1c8\n",
            "table|billing.account|3|c19369add11373fb9910a51df429e1c8\n\
             table|billing.account|3|c19369add11373fb9910a51df429e1c8\n",
            "table|billing.account|3|zzz\n",
        ] {
            assert!(parse_postgres(bad).is_err(), "{bad:?}");
        }
        for bad in [
            "0|dbsize|1|-|-1\n",
            "0|string|short|809690d94bbb98cbfdc63b0a10e9ea3d3857868e|-1\n",
            "0|string|65e00fff84d2d7e34c703efc2d2f20c106039bf7|x|-1\n",
            "0|mystery|65e00fff84d2d7e34c703efc2d2f20c106039bf7|809690d94bbb98cbfdc63b0a10e9ea3d3857868e|-1\n",
            "0|string|65e00fff84d2d7e34c703efc2d2f20c106039bf7|809690d94bbb98cbfdc63b0a10e9ea3d3857868e\n",
        ] {
            assert!(parse_redis(bad).is_err(), "{bad:?}");
        }
        // dbsize 与实际列出的键数不符时不能只信 dbsize。
        assert!(
            parse_redis(
                "0|dbsize|2|-|-1\n\
                 0|string|65e00fff84d2d7e34c703efc2d2f20c106039bf7|809690d94bbb98cbfdc63b0a10e9ea3d3857868e|-1\n"
            )
            .is_err()
        );
    }

    /// 链式日志：改一条、删一条、换顺序都必须被发现。
    #[test]
    fn journal_chain_detects_edits_and_reordering() -> anyhow::Result<()> {
        let mut journal = Journal::new();
        journal.append("fence", "source is read-only")?;
        journal.append("dump", "8264 bytes")?;
        journal.append("restore", "exit 0")?;
        journal.verify()?;

        let mut edited = journal.clone();
        edited.entries[1].detail = "0 bytes".into();
        assert!(edited.verify().is_err());

        let mut removed = journal.clone();
        removed.entries.remove(1);
        assert!(removed.verify().is_err());

        let mut reordered = journal.clone();
        reordered.entries.swap(1, 2);
        assert!(reordered.verify().is_err());

        // 序号也要连续，不能靠「链对得上」掩盖丢了一条。
        let mut skipped = journal.clone();
        skipped.entries[2].sequence = 7;
        assert!(skipped.verify().is_err());
        Ok(())
    }

    /// 日志不能覆盖已有文件：两轮演练要能各自留证。
    #[test]
    fn journal_refuses_to_overwrite_an_existing_file() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let paths = stage_paths(root.path());
        let mut journal = Journal::new();
        journal.append("seed", "3 accounts")?;
        journal.save(&paths.journal)?;
        assert!(journal.save(&paths.journal).is_err());

        // 读回后链仍然完整，并且能继续追加。
        let mut loaded = Journal::load(&paths.journal)?;
        assert_eq!(loaded.entries().len(), 1);
        Journal::append_to(&paths.journal, "fence", "read-only")?;
        Journal::append_to(&paths.journal, "dump", "8264 bytes")?;
        loaded = Journal::load(&paths.journal)?;
        assert_eq!(loaded.entries().len(), 3);
        loaded.verify()?;
        Ok(())
    }

    /// 指纹的单一摘要要覆盖两侧：任何一侧变化都要改变它。
    #[test]
    fn fingerprint_digest_covers_both_stores() -> anyhow::Result<()> {
        let base = print();
        let digest = base.digest()?;
        assert_eq!(digest.len(), 64);

        let mut postgres = base.clone();
        postgres.postgres.tables[0].rows += 1;
        assert_ne!(digest, postgres.digest()?);

        let mut redis = base.clone();
        redis.redis.sizes.insert(9, 1);
        assert_ne!(digest, redis.digest()?);
        Ok(())
    }

    /// SQL 与 Lua 是演练的唯一来源，必须能在真实引擎里执行；这里先看形状。
    #[test]
    fn fingerprint_programs_are_self_contained() {
        assert!(POSTGRES_FINGERPRINT_SQL.contains("pg_sequences"));
        assert!(POSTGRES_FINGERPRINT_SQL.contains("query_to_xml"));
        assert!(!POSTGRES_FINGERPRINT_SQL.to_lowercase().contains("insert "));
        assert!(REDIS_FINGERPRINT_LUA.contains("SCAN"));
        assert!(REDIS_FINGERPRINT_LUA.contains("PEXPIRETIME"));
        assert!(REDIS_FINGERPRINT_LUA.contains("redis.sha1hex"));
    }
}
