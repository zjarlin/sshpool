//! 外部灾备包的离线验证与数据库行数证据生成。
use crate::archive;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

const MANIFEST_FORMAT: &str = "sshpool-dr-v1";
type PayloadChecksums = BTreeMap<String, String>;
const REQUIRED_FILES: [&str; 14] = [
    "MANIFEST",
    "SHA256SUMS",
    "containers-before.json",
    "images.json",
    "postgres-globals.sql",
    "postgres-state.txt",
    "sub2api-postgres.dump",
    "postgres-archive-list.txt",
    "redis-dump.rdb",
    "redis-state.txt",
    "redis-check.txt",
    "application-config-and-volumes.tar",
    "application-archive-list.txt",
    "images.tar",
];

/// 灾备清单只包含恢复判断需要的摘要和计数，不输出数据库口令或应用凭据。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub run_id: String,
    pub created_at: String,
    pub format: String,
    pub postgres_database: String,
    pub table_data_entries: u64,
    pub redis_dbsize: u64,
    pub payload_sha256: String,
}

/// 验证报告供自动化门禁使用；布尔值只有实际校验完成后才为真。
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Verification {
    pub run_id: String,
    pub files_checked: usize,
    pub archive_sha256: String,
    pub manifest: Manifest,
    pub archive_valid: bool,
}

/// 逐表计数以 `schema.table` 为键；缺失和重复表名均失败关闭。
pub type RowCounts = BTreeMap<String, u64>;

/// 读取恢复包旁的外部摘要，并要求它只描述当前归档。
pub fn verify_archive(path: &Path, checksum_file: &Path) -> Result<Verification> {
    ensure!(path.is_file(), "recovery archive is missing");
    let expected_archive = checksum_for(checksum_file, path)?;
    let actual_archive = archive::sha256_file(path)?;
    ensure!(
        actual_archive == expected_archive,
        "recovery archive checksum mismatch"
    );
    let run_id = archive_name(path)?;
    let staging = tempfile::Builder::new()
        .prefix("sshpool-dr-verify-")
        .tempdir()?;
    let output = std::process::Command::new("tar")
        .args(["--zstd", "-xf"])
        .arg(path)
        .args(["-C"])
        .arg(staging.path())
        .status()
        .context("failed to start tar")?;
    ensure!(
        output.success(),
        "outer recovery archive cannot be extracted"
    );
    let stage = staging.path().join("stage");
    ensure!(stage.is_dir(), "recovery archive has no stage directory");
    let checked = verify_stage(&stage)?;
    ensure!(
        checked.run_id == run_id,
        "archive filename and run ID disagree"
    );
    Ok(Verification {
        run_id: checked.run_id.clone(),
        files_checked: checked.files_checked,
        archive_sha256: actual_archive,
        manifest: checked.manifest,
        archive_valid: true,
    })
}

/// 恢复包内部校验必须在解包后重新计算每个文件摘要，清单不能自证。
pub fn verify_stage(stage: &Path) -> Result<Verification> {
    for name in REQUIRED_FILES {
        let path = stage.join(name);
        ensure!(path.is_file(), "recovery payload is missing: {name}");
        ensure!(
            fs::metadata(path)?.len() > 0,
            "recovery payload is empty: {name}"
        );
    }
    let manifest = parse_manifest(&fs::read_to_string(stage.join("MANIFEST"))?)?;
    ensure!(
        manifest.format == MANIFEST_FORMAT,
        "unsupported recovery manifest format"
    );
    ensure!(
        manifest.postgres_database == "sub2api",
        "unexpected PostgreSQL database"
    );
    ensure!(
        manifest.table_data_entries > 0,
        "PostgreSQL snapshot has no table data"
    );
    let checksums = verify_checksums(stage)?;
    let canonical = payload_sha256(&checksums, &["sub2api-postgres.dump", "redis-dump.rdb"])?;
    // 2026-11-07 的旧脚本用绝对路径生成总摘要；保留只读兼容以救回已完成的包。
    let legacy_paths = [
        format!(
            "/root/.sshpool-dr/runs/{0}/stage/sub2api-postgres.dump",
            manifest.run_id
        ),
        format!(
            "/root/.sshpool-dr/runs/{0}/stage/redis-dump.rdb",
            manifest.run_id
        ),
    ];
    let legacy = payload_sha256(
        &checksums,
        &[legacy_paths[0].as_str(), legacy_paths[1].as_str()],
    )?;
    ensure!(
        manifest.payload_sha256 == canonical || manifest.payload_sha256 == legacy,
        "PostgreSQL or Redis payload checksum mismatch"
    );
    let checked = checksums.len();
    verify_postgres_list(
        stage.join("postgres-archive-list.txt"),
        manifest.table_data_entries,
    )?;
    verify_redis_check(stage.join("redis-check.txt"))?;
    archive::validate(
        &stage.join("application-config-and-volumes.tar"),
        u64::MAX,
        None,
    )?;
    let archive_sha256 = archive::sha256_file(&stage.join("sub2api-postgres.dump"))?;
    Ok(Verification {
        run_id: manifest.run_id.clone(),
        files_checked: checked,
        archive_sha256,
        manifest,
        archive_valid: true,
    })
}

/// 解析 PostgreSQL `COPY schema.table TO stdout` 的 CSV；只接受不带表头的一列计数。
pub fn parse_sql_counts(source: impl BufRead) -> Result<RowCounts> {
    let mut counts = BTreeMap::new();
    for line in source.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split(',').collect::<Vec<_>>();
        ensure!(
            fields.len() == 3,
            "row count must contain schema, table and count"
        );
        let schema = fields[0].trim();
        let table = fields[1].trim();
        ensure!(valid_sql_identifier(schema), "invalid schema name");
        ensure!(valid_sql_identifier(table), "invalid table name");
        let count = fields[2]
            .trim()
            .parse::<u64>()
            .with_context(|| format!("invalid row count for {schema}.{table}"))?;
        let key = format!("{schema}.{table}");
        ensure!(
            counts.insert(key.clone(), count).is_none(),
            "duplicate table: {key}"
        );
    }
    ensure!(!counts.is_empty(), "row count input is empty");
    Ok(counts)
}

/// 比较两次恢复前后的计数，并报告每个缺失、新增和数值差异。
pub fn compare_counts(expected: &RowCounts, actual: &RowCounts) -> Result<()> {
    ensure!(
        !expected.is_empty() && !actual.is_empty(),
        "row counts cannot be empty"
    );
    let expected_keys = expected.keys().collect::<Vec<_>>();
    let actual_keys = actual.keys().collect::<Vec<_>>();
    ensure!(
        expected_keys == actual_keys,
        "table sets differ: expected={expected_keys:?}, actual={actual_keys:?}"
    );
    for (table, expected_count) in expected {
        let actual_count = actual.get(table).context("table disappeared")?;
        ensure!(
            expected_count == actual_count,
            "row count mismatch for {table}: expected={expected_count}, actual={actual_count}"
        );
    }
    Ok(())
}

fn checksum_for(checksum_file: &Path, archive_path: &Path) -> Result<String> {
    let source = fs::read_to_string(checksum_file)?;
    let mut lines = source.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().context("checksum file is empty")?;
    ensure!(
        lines.next().is_none(),
        "checksum file must contain one entry"
    );
    let (digest, named_path) = line
        .split_once(char::is_whitespace)
        .context("invalid checksum line")?;
    ensure!(valid_sha256(digest), "invalid archive checksum");
    let named_path = Path::new(named_path.trim_start());
    ensure!(
        named_path.file_name() == archive_path.file_name(),
        "checksum file names a different archive"
    );
    Ok(digest.to_ascii_lowercase())
}

fn archive_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("archive has no UTF-8 filename")?;
    let run_id = name
        .strip_suffix(".tar.zst")
        .context("archive filename must end in .tar.zst")?;
    ensure!(valid_run_id(run_id), "invalid archive run ID");
    Ok(run_id.to_owned())
}

fn parse_manifest(source: &str) -> Result<Manifest> {
    let mut values = BTreeMap::new();
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line.split_once('=').context("invalid manifest line")?;
        ensure!(
            !key.is_empty() && !value.is_empty(),
            "manifest value is empty"
        );
        ensure!(
            values.insert(key, value).is_none(),
            "duplicate manifest key"
        );
    }
    let required = [
        "run_id",
        "created_at",
        "format",
        "postgres_database",
        "table_data_entries",
        "redis_dbsize",
        "payload_sha256",
    ];
    ensure!(values.len() == required.len(), "manifest has unknown keys");
    for key in required {
        ensure!(values.contains_key(key), "manifest key is missing: {key}");
    }
    Ok(Manifest {
        run_id: values["run_id"].into(),
        created_at: values["created_at"].into(),
        format: values["format"].into(),
        postgres_database: values["postgres_database"].into(),
        table_data_entries: values["table_data_entries"].parse()?,
        redis_dbsize: values["redis_dbsize"].parse()?,
        payload_sha256: values["payload_sha256"].into(),
    })
}

fn verify_checksums(stage: &Path) -> Result<PayloadChecksums> {
    let source = fs::read_to_string(stage.join("SHA256SUMS"))?;
    let mut checksums = PayloadChecksums::new();
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let Some((digest, name)) = line.split_once(char::is_whitespace) else {
            anyhow::bail!("invalid SHA256SUMS line");
        };
        let name = name.trim_start();
        ensure!(!name.contains(['/', '\\']), "invalid checksum path");
        ensure!(valid_sha256(digest), "invalid SHA256SUMS digest");
        if name == "SHA256SUMS" {
            // 历史包留下一条生成时的自引用摘要；它无法自证，也不参与载荷汇总。
            ensure!(
                !checksums.contains_key(name),
                "duplicate checksum entry: {name}"
            );
            continue;
        }
        let digest = original_digest(digest);
        let path = stage.join(name);
        ensure!(path.is_file(), "checksum references a missing file: {name}");
        ensure!(
            archive::sha256_file(&path)? == digest,
            "recovery payload checksum mismatch: {name}"
        );
        ensure!(
            checksums.insert(name.to_owned(), digest).is_none(),
            "duplicate checksum entry"
        );
    }

    let required: Vec<_> = REQUIRED_FILES
        .iter()
        .copied()
        .filter(|name| *name != "SHA256SUMS")
        .collect();
    for name in &required {
        ensure!(
            checksums.contains_key(*name),
            "checksum entry is missing: {name}"
        );
    }
    ensure!(
        checksums.len() == required.len(),
        "SHA256SUMS contains unexpected entries"
    );
    Ok(checksums)
}

fn payload_sha256(checksums: &PayloadChecksums, labels: &[&str; 2]) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut combined = Sha256::new();
    for (source, label) in ["sub2api-postgres.dump", "redis-dump.rdb"]
        .into_iter()
        .zip(labels)
    {
        let digest = checksums
            .get(source)
            .with_context(|| format!("payload checksum is missing: {source}"))?;
        combined.update(format!("{digest}  {label}\n").as_bytes());
    }
    Ok(encode_hex(&combined.finalize()))
}

fn original_digest(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn verify_postgres_list(path: PathBuf, expected: u64) -> Result<()> {
    let file = File::open(path)?;
    let mut actual = 0_u64;
    for line in BufReader::new(file).lines() {
        // 读错误不能像 EOF 一样静默截断，否则损坏的清单可能被误判为通过。
        if line?.contains("TABLE DATA") {
            actual += 1;
        }
    }
    ensure!(actual == expected, "PostgreSQL archive list count mismatch");
    Ok(())
}

fn verify_redis_check(path: PathBuf) -> Result<()> {
    let source = fs::read_to_string(path)?;
    ensure!(
        source.contains("RDB looks OK"),
        "Redis RDB check did not pass"
    );
    Ok(())
}

fn valid_run_id(value: &str) -> bool {
    value.len() >= 20
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || byte.is_ascii_alphabetic()
                || byte == b'T'
                || byte == b'Z'
                || byte == b'-'
        })
}

fn valid_sql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{compare_counts, parse_sql_counts, payload_sha256, valid_run_id};
    use std::{collections::BTreeMap, io::Cursor};

    #[test]
    fn payload_checksum_format_matches_producer_and_keeps_legacy_compatible() {
        let checksums = BTreeMap::from([
            ("sub2api-postgres.dump".to_owned(), "a".repeat(64)),
            ("redis-dump.rdb".to_owned(), "b".repeat(64)),
        ]);
        let canonical = payload_sha256(&checksums, &["sub2api-postgres.dump", "redis-dump.rdb"])
            .expect("canonical digest");
        let legacy = payload_sha256(
            &checksums,
            &[
                "/root/.sshpool-dr/runs/run/stage/sub2api-postgres.dump",
                "/root/.sshpool-dr/runs/run/stage/redis-dump.rdb",
            ],
        )
        .expect("legacy digest");
        assert_ne!(canonical, legacy);
        assert_eq!(canonical.len(), 64);
    }

    #[test]
    fn run_id_accepts_lowercase_hex_suffix_and_rejects_path_text() {
        assert!(valid_run_id("20261107T042859Z-10bb568b"));
        assert!(!valid_run_id("20261107T042859Z-../escape"));
    }

    #[test]
    fn sql_counts_reject_duplicates_and_invalid_names() {
        assert!(parse_sql_counts(Cursor::new("public,jobs,2\npublic,jobs,2\n")).is_err());
        assert!(parse_sql_counts(Cursor::new("public,jobs;drop,2\n")).is_err());
    }

    #[test]
    fn count_comparison_requires_exact_table_sets_and_values() {
        let expected = parse_sql_counts(Cursor::new("public,jobs,2\n")).expect("counts");
        let actual = parse_sql_counts(Cursor::new("public,jobs,2\n")).expect("counts");
        compare_counts(&expected, &actual).expect("same counts");
        let less = parse_sql_counts(Cursor::new("public,jobs,1\n")).expect("counts");
        assert!(compare_counts(&expected, &less).is_err());
        let extra =
            parse_sql_counts(Cursor::new("public,jobs,2\npublic,users,1\n")).expect("counts");
        assert!(compare_counts(&expected, &extra).is_err());
    }
}
