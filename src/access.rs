//! 控制面的访问审计：谁以什么身份访问了哪个接口、被允许还是拒绝。
//!
//! 每条请求写一行 JSON 到 `home/access.jsonl`。日志里只有主体名、凭据标识、
//! 目标路由与结论 —— **从不会有 token、请求正文或环境值**：本模块的写入函数
//! 只接受已经脱敏的字段，调用方没有把原始请求塞进来的途径。
//!
//! 有界：单文件 4 MiB，保留当前与两个滚动代，合计上限 12 MiB。达到上限就滚动，
//! 从不清空 —— 清空会让「审计突然变空」看起来像没有访问。
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// 单行格式版本；只增不改，便于脚本消费。
pub const SCHEMA: u32 = 1;
/// 单个文件的上限；与 `GENERATIONS` 相乘就是磁盘占用的硬上限。
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// 当前文件加两个滚动代。
pub const GENERATIONS: usize = 3;
/// 单次查询返回的上限；再大会把一次 HTTP 响应变成整份日志。
pub const MAX_LIMIT: usize = 5_000;
pub const DEFAULT_LIMIT: usize = 200;

/// 一次请求的审计记录。
///
/// `deny_unknown_fields` 是读取侧的 fail-closed：字段被外部改写会让整次查询报错，
/// 而不是悄悄忽略一段看不懂的内容。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub schema: u32,
    pub time: u64,
    /// 客户端提供的请求标识（`x-request-id`）或服务端生成的一次性标识。
    pub request: String,
    /// 主体名；匿名请求为空字符串而不是省略，便于按列过滤。
    pub subject: String,
    /// 身份来源：`root`、`credential` 或 `anonymous`。
    pub kind: String,
    /// 短期凭据的标识；根 token 与匿名请求为空。
    #[serde(default)]
    pub credential: Option<String>,
    /// `allowed` 或 `denied`。
    pub decision: String,
    /// 判定理由：`root-token`、`credential`、`missing-token`、`unknown-token`、
    /// `store-unusable`。它只进日志，不进响应体。
    pub reason: String,
    pub method: String,
    /// 命中的路由模板（如 `/v1/jobs/{id}`）；未命中任何路由时为 `unmatched`。
    /// 刻意不记原始路径：路径里可能被塞进被误当成 URL 的凭据。
    pub route: String,
    /// 路径中的任务标识（仅当该段是规范 UUID 时记录）。
    #[serde(default)]
    pub job: Option<String>,
    pub status: u16,
}

/// 查询过滤条件；所有字段都是可选的，默认按时间倒序取最近的记录。
#[derive(Clone, Debug)]
pub struct Filter {
    pub subject: Option<String>,
    pub decision: Option<String>,
    /// 只返回 `time >= since` 的记录。
    pub since: Option<u64>,
    pub limit: usize,
}

impl Default for Filter {
    fn default() -> Self {
        // 不能派生成 `limit: 0`：那会让「默认查询」被夹成 1 条，
        // 看起来像日志丢了，而不是调用方没设上限。
        Self {
            subject: None,
            decision: None,
            since: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

pub fn path(home: &Path) -> PathBuf {
    home.join("access.jsonl")
}

/// 滚动代路径：`access.jsonl.1`、`access.jsonl.2`。0 表示当前文件。
fn generation_path(home: &Path, generation: usize) -> PathBuf {
    match generation {
        0 => path(home),
        generation => PathBuf::from(format!("{}.{generation}", path(home).display())),
    }
}

/// 打开并确认可写。控制面在**执行有副作用请求之前**调用它：
/// 审计写不进去时拒绝提交，而不是先执行再补一条可能失败记录。
pub fn ensure_writable(home: &Path) -> Result<()> {
    // 打开（含 0600 的 chmod）本身就是判据：只读挂载、目录占位、权限不足都在这里失败。
    // `File::flush` 对无缓冲文件是 no-op，不能当成写入探测。
    let _file = open_append(home)?;
    Ok(())
}

fn open_append(home: &Path) -> Result<File> {
    let path = path(home);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("cannot open access log {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("cannot restrict access log permissions")?;
    }
    Ok(file)
}

/// 追加一条记录。调用方必须持有 `State::access` 锁，避免滚动与写入交错。
pub fn append(home: &Path, entry: &Entry) -> Result<()> {
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    ensure!(
        line.len() as u64 <= MAX_FILE_BYTES,
        "access entry is larger than a whole log file"
    );
    // 先把崩溃留下的半行切掉：否则新记录会接在它后面，把它变成「中间行」，
    // 之后整份日志都会 fail-closed 到不可读。
    trim_torn_tail(home)?;
    rotate_if_needed(home, line.len() as u64)?;
    let mut file = open_append(home)?;
    file.write_all(&line)?;
    // 审计记录必须真的落盘：崩溃后丢掉的访问记录等于没有审计。
    file.sync_data()?;
    Ok(())
}

/// 当前文件末尾若没有换行，就截断到最后一条完整记录。
///
/// 只处理当前文件：滚动代在写满时才产生，那时末尾一定是完整的（每次追加都成对写入
/// 一行加换行，`sync_data` 之后才算成功）。
fn trim_torn_tail(home: &Path) -> Result<()> {
    let current = path(home);
    let file = match OpenOptions::new().read(true).write(true).open(&current) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(());
    }
    // 只看尾部一段：半行不可能比一整条记录更长，而记录本身受 MAX_FILE_BYTES 约束。
    const TAIL: u64 = 64 * 1024;
    let start = size.saturating_sub(TAIL);
    let mut tail = Vec::new();
    use std::io::{Read, Seek, SeekFrom};
    (&file).seek(SeekFrom::Start(start))?;
    (&file).take(TAIL).read_to_end(&mut tail)?;
    let complete = match tail.iter().rposition(|byte| *byte == b'\n') {
        // 末尾本来就是换行：不需要动。
        Some(index) if start + index as u64 + 1 == size => return Ok(()),
        Some(index) => start + index as u64 + 1,
        // 整段都没有换行：这条记录从文件开头就是残缺的。
        None => 0,
    };
    eprintln!(
        "sshpool: dropping {} bytes of a truncated access record in {}",
        size - complete,
        current.display()
    );
    file.set_len(complete)
        .with_context(|| format!("cannot trim {} to {}", current.display(), complete))?;
    file.sync_all()?;
    Ok(())
}

fn rotate_if_needed(home: &Path, incoming: u64) -> Result<()> {
    let current = path(home);
    let size = match fs::metadata(&current) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if size + incoming <= MAX_FILE_BYTES {
        return Ok(());
    }
    // 代次是 0（当前）+ 1..GENERATIONS-1；先丢最老的一代，再从旧往新搬。
    let oldest = generation_path(home, GENERATIONS - 1);
    if oldest.exists() {
        fs::remove_file(&oldest).with_context(|| format!("cannot drop {}", oldest.display()))?;
    }
    for generation in (1..GENERATIONS - 1).rev() {
        let from = generation_path(home, generation);
        if !from.exists() {
            continue;
        }
        let to = generation_path(home, generation + 1);
        fs::rename(&from, &to)
            .with_context(|| format!("cannot roll {} to {}", from.display(), to.display()))?;
    }
    fs::rename(&current, generation_path(home, 1))
        .with_context(|| format!("cannot roll {} aside", current.display()))?;
    Ok(())
}

/// 读完整个日志并返回命中的记录，时间倒序。
///
/// 解析失败即报错（fail-closed）：看不懂的审计行不能被静默跳过。
/// 唯一例外是**最新文件的最后一行** —— 崩溃可能留下半行，把它当成损坏会让
/// 整份日志永久不可读。
pub fn read(home: &Path, filter: &Filter) -> Result<Vec<Entry>> {
    let limit = filter.limit.clamp(1, MAX_LIMIT);
    let mut entries = Vec::new();
    for generation in (0..GENERATIONS).rev() {
        let path = generation_path(home, generation);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            // 这一代还没滚动出来是正常状态；读不了但存在则是故障，不能静默少读一段历史。
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let last_index = text.lines().count().saturating_sub(1);
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed = serde_json::from_str::<Entry>(line);
            let entry = match parsed {
                Ok(entry) => entry,
                Err(error) if generation == 0 && index == last_index => {
                    // 崩溃留下的半行：它不完整，也不该让历史记录一起不可读。
                    eprintln!(
                        "sshpool: ignoring a truncated final access record in {}: {error}",
                        path.display()
                    );
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "malformed access record at {}:{}",
                            path.display(),
                            index + 1
                        )
                    });
                }
            };
            ensure!(
                entry.schema == SCHEMA,
                "unsupported access record schema {} at {}:{}",
                entry.schema,
                path.display(),
                index + 1
            );
            if let Some(subject) = &filter.subject
                && &entry.subject != subject
            {
                continue;
            }
            if let Some(decision) = &filter.decision
                && &entry.decision != decision
            {
                continue;
            }
            if let Some(since) = filter.since
                && entry.time < since
            {
                continue;
            }
            entries.push(entry);
        }
    }
    // 同一秒内多条记录按文件顺序倒序，保证“最近的在前”稳定。
    entries.reverse();
    entries.truncate(limit);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(time: u64, subject: &str, decision: &str) -> Entry {
        Entry {
            schema: SCHEMA,
            time,
            request: format!("req-{time}"),
            subject: subject.into(),
            kind: "credential".into(),
            credential: Some("00000000-0000-4000-8000-000000000000".into()),
            decision: decision.into(),
            reason: "credential".into(),
            method: "GET".into(),
            route: "/v1/status".into(),
            job: None,
            status: if decision == "allowed" { 200 } else { 401 },
        }
    }

    #[test]
    fn records_round_trip_and_filter_by_subject_and_decision() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        append(home, &entry(10, "workbench", "allowed")).unwrap();
        append(home, &entry(11, "intruder", "denied")).unwrap();
        append(home, &entry(12, "workbench", "allowed")).unwrap();

        let all = read(home, &Filter::default()).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].time, 12, "newest first");

        let only_workbench = read(
            home,
            &Filter {
                subject: Some("workbench".into()),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(only_workbench.len(), 2);
        assert!(only_workbench.iter().all(|e| e.subject == "workbench"));

        let only_denied = read(
            home,
            &Filter {
                decision: Some("denied".into()),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(only_denied.len(), 1);
        assert_eq!(only_denied[0].status, 401);

        let recent = read(
            home,
            &Filter {
                since: Some(11),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn the_log_rolls_and_stays_bounded() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        // 直接把当前文件撑到接近上限，再写一条触发滚动。
        let mut big = entry(1, "workbench", "allowed");
        big.reason = "x".repeat(64 * 1024);
        // 填到「再写一条样本就会越过上限」为止，然后写那一条触发滚动。
        let sample = 64 * 1024 + 1024;
        while path(home).metadata().map(|m| m.len()).unwrap_or(0) + sample <= MAX_FILE_BYTES {
            append(home, &big).unwrap();
        }
        let before = path(home).metadata().unwrap().len();
        assert!(
            before + sample > MAX_FILE_BYTES,
            "test setup did not reach the limit"
        );
        append(home, &big).unwrap();
        assert!(
            generation_path(home, 1).exists(),
            "the previous file was rolled"
        );
        let total: u64 = (0..GENERATIONS)
            .map(|g| {
                generation_path(home, g)
                    .metadata()
                    .map(|m| m.len())
                    .unwrap_or(0)
            })
            .sum();
        assert!(
            total <= MAX_FILE_BYTES * GENERATIONS as u64,
            "total {total} exceeds the bounded budget"
        );
    }

    #[test]
    fn newest_generation_is_readable_and_a_torn_tail_does_not_hide_history() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        append(home, &entry(1, "workbench", "allowed")).unwrap();
        append(home, &entry(2, "workbench", "allowed")).unwrap();
        // 模拟崩溃留下的半行。
        let mut file = OpenOptions::new().append(true).open(path(home)).unwrap();
        file.write_all(br#"{"schema":1,"time":3"#).unwrap();
        drop(file);
        let entries = read(home, &Filter::default()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].time, 2);
    }

    #[test]
    fn a_torn_tail_is_dropped_before_the_next_append() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        append(home, &entry(1, "workbench", "allowed")).unwrap();
        let mut file = OpenOptions::new().append(true).open(path(home)).unwrap();
        file.write_all(br#"{"schema":1,"time":2"#).unwrap();
        drop(file);
        // 崩溃恢复后的第一条新记录必须让日志重新完整：半行被切掉，而不是被夹在中间。
        append(home, &entry(3, "workbench", "allowed")).unwrap();
        let entries = read(home, &Filter::default()).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].time, 3);
        assert_eq!(entries[1].time, 1);
        // 再追加一条，确认尾部继续完整。
        append(home, &entry(4, "workbench", "allowed")).unwrap();
        assert_eq!(read(home, &Filter::default()).unwrap().len(), 3);
    }

    #[test]
    fn a_corrupt_middle_record_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        append(home, &entry(1, "workbench", "allowed")).unwrap();
        append(home, &entry(2, "workbench", "allowed")).unwrap();
        let text = fs::read_to_string(path(home)).unwrap();
        let mut lines = text.lines().map(str::to_string).collect::<Vec<_>>();
        lines[0] = r#"{"schema":1,"time":"not a number"}"#.into();
        fs::write(path(home), lines.join("\n") + "\n").unwrap();
        let error = read(home, &Filter::default()).unwrap_err().to_string();
        assert!(error.contains("malformed access record"), "{error}");
    }

    #[test]
    fn limits_are_clamped_to_a_single_response_budget() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        for time in 0..10 {
            append(home, &entry(time, "workbench", "allowed")).unwrap();
        }
        let entries = read(
            home,
            &Filter {
                limit: 4,
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].time, 9);
        // 零也被夹到 1，而不是返回空表。
        let one = read(
            home,
            &Filter {
                limit: 0,
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn a_missing_log_reads_as_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(read(root.path(), &Filter::default()).unwrap().is_empty());
    }
}
