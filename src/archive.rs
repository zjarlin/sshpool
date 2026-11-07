use anyhow::{Context, Result, ensure};
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

/// 快照结果同时提供归档内源码字节数和归档 SHA-256，供任务记录与传输双方核对。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestEntry {
    path: String,
    sha256: [u8; 32],
    executable: bool,
}

/// 拒绝绝对路径、上跳路径与不可表达的文件名，输入和产物使用相同边界。
pub fn relative_path(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty() && path.to_str().is_some(),
        "empty or non-UTF8 path"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_))),
        "path must be relative without '.' or '..': {}",
        path.display()
    );
    ensure!(
        !path.to_string_lossy().contains(['\0', '\n', '\r', '\\']),
        "unsupported path: {}",
        path.display()
    );
    Ok(())
}
fn excluded(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".ssh" | ".sshpool" | "target" | "node_modules" | ".gradle" | ".env"
    ) || name.starts_with(".env.")
        || name.ends_with(".pem")
        || name.ends_with(".key")
}
/// 只打包明确选中的项目，遵循忽略规则并拒绝符号链接。
pub fn snapshot(root: &Path, destination: &Path, max_bytes: u64) -> Result<Snapshot> {
    snapshot_inner(root, destination, max_bytes, || {})
}

fn normalized_root(root: &Path) -> Result<std::path::PathBuf> {
    let root = root.canonicalize().context("project does not exist")?;
    ensure!(root.is_dir(), "project must be a directory");
    ensure!(
        root.parent().is_some(),
        "refusing filesystem root as project"
    );
    if let Some(home) = std::env::var_os("HOME") {
        ensure!(
            root != Path::new(&home),
            "refusing entire home directory as project"
        );
    }
    Ok(root)
}

fn file_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .sort_by_file_name(|left, right| left.cmp(right))
        .filter_entry(|entry| entry.depth() == 0 || !excluded(&entry.file_name().to_string_lossy()))
        .build();
    let mut paths = Vec::new();
    for entry in walker {
        let entry = entry?;
        if entry.depth() == 0 || entry.file_type().is_some_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        relative_path(relative)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "only regular source files are allowed: {}",
            relative.display()
        );
        paths.push(relative.to_path_buf());
    }
    ensure!(paths.len() <= 100_000, "too many source files");
    paths.sort_by(|left, right| left.as_os_str().cmp(right.as_os_str()));
    Ok(paths)
}

fn executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.is_file()
            && right.is_file()
            && left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
    }
}

fn hash_file(path: &Path, remaining: u64) -> Result<([u8; 32], bool)> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "source entry is not a regular file");
    ensure!(before.len() <= remaining, "source exceeds upload limit");
    let mut hasher = Sha256::new();
    let copied = hash_reader(&mut (&mut file).take(before.len() + 1), &mut hasher)?;
    ensure!(
        copied == before.len(),
        "source changed size while being read: {}",
        path.display()
    );
    let after = file.metadata()?;
    ensure!(
        same_identity(&before, &after),
        "source changed while being read: {}",
        path.display()
    );
    let on_disk = fs::symlink_metadata(path)?;
    ensure!(
        same_identity(&before, &on_disk),
        "source path changed while being read: {}",
        path.display()
    );
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((digest, executable(&before)))
}

fn manifest(root: &Path, max_bytes: u64) -> Result<Vec<ManifestEntry>> {
    let paths = file_paths(root)?;
    let mut bytes = 0_u64;
    let mut entries = Vec::with_capacity(paths.len());
    for relative in paths {
        let remaining = max_bytes.saturating_sub(bytes);
        let (sha256, executable) = hash_file(&root.join(&relative), remaining)?;
        let size = fs::metadata(root.join(&relative))?.len();
        bytes = bytes.checked_add(size).context("source size overflow")?;
        let path = relative
            .to_str()
            .context("non-UTF8 source path")?
            .to_string();
        entries.push(ManifestEntry {
            path,
            sha256,
            executable,
        });
    }
    Ok(entries)
}

fn write_archive(root: &Path, destination: &Path, max_bytes: u64) -> Result<u64> {
    let paths = file_paths(root)?;
    let file = File::create(destination)?;
    let mut builder = tar::Builder::new(file);
    let mut bytes = 0_u64;
    for relative in paths {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "source changed to a link or special file while archiving: {}",
            relative.display()
        );
        bytes = bytes
            .checked_add(metadata.len())
            .context("source size overflow")?;
        ensure!(bytes <= max_bytes, "source exceeds upload limit");
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(if executable(&metadata) { 0o755 } else { 0o644 });
        header.set_mtime(0);
        header.set_cksum();
        let file = File::open(&path)?;
        let before = file.metadata()?;
        let mut reader = file;
        builder.append_data(&mut header, &relative, &mut reader)?;
        ensure!(
            same_identity(&before, &reader.metadata()?),
            "source changed while archiving: {}",
            relative.display()
        );
        let current = fs::symlink_metadata(root.join(&relative))?;
        ensure!(
            same_identity(&before, &current),
            "source path changed while archiving: {}",
            relative.display()
        );
    }
    builder.finish()?;
    ensure!(
        fs::metadata(destination)?.len() <= max_bytes,
        "source archive exceeds upload limit including metadata"
    );
    Ok(bytes)
}

/// 完成后再次计算内容清单；可见的并发新增、删除或修改会使快照失败。
fn snapshot_inner(
    root: &Path,
    destination: &Path,
    max_bytes: u64,
    after_capture: impl FnOnce(),
) -> Result<Snapshot> {
    let root = normalized_root(root)?;
    let before = manifest(&root, max_bytes)?;
    let bytes = write_archive(&root, destination, max_bytes)?;
    after_capture();
    let current = manifest(&root, max_bytes)?;
    ensure!(
        before == current,
        "project changed while taking a consistent snapshot; retry after writes settle"
    );
    Ok(Snapshot {
        bytes,
        sha256: sha256_file(destination)?,
    })
}

/// 流式计算文件 SHA-256，不把整个归档载入内存。
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let copied = hash_reader(&mut reader, &mut hasher)?;
    ensure!(
        copied == fs::metadata(path)?.len(),
        "file changed while hashing: {}",
        path.display()
    );
    Ok(hex_digest(&hasher.finalize()))
}

fn hash_reader(reader: &mut impl Read, hasher: &mut Sha256) -> std::io::Result<u64> {
    let mut buffer = [0_u8; 65536];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(total);
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
}

fn hex_digest(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
/// 上传和下载都先完整验证 tar，再交给容器或本地解包。
pub fn validate(path: &Path, limit: u64, outputs: Option<&[String]>) -> Result<()> {
    ensure!(
        fs::metadata(path)?.len() <= limit,
        "archive exceeds byte limit"
    );
    let mut archive = tar::Archive::new(File::open(path)?);
    let mut seen = HashSet::new();
    let mut bytes = 0_u64;
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.into_owned();
        relative_path(&path)?;
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "links and special files are forbidden: {}",
            path.display()
        );
        ensure!(
            seen.insert(path.clone()),
            "duplicate archive entry: {}",
            path.display()
        );
        ensure!(seen.len() <= 100_000, "too many archive entries");
        ensure!(
            entry.header().mode()? & 0o6000 == 0,
            "setuid/setgid files are forbidden"
        );
        bytes = bytes
            .checked_add(entry.size())
            .context("archive size overflow")?;
        ensure!(bytes <= limit, "archive expands beyond byte limit");
        if let Some(outputs) = outputs {
            ensure!(
                outputs.iter().any(|output| path.starts_with(output)),
                "undeclared output: {}",
                path.display()
            );
        }
    }
    Ok(())
}
pub fn unpack_new(archive: &Path, destination: &Path, limit: u64) -> Result<()> {
    validate(archive, limit, None)?;
    fs::create_dir(destination).context("output directory must not already exist")?;
    tar::Archive::new(File::open(archive)?).unpack(destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::snapshot_inner;
    use anyhow::{Context, Result};
    use std::fs;

    #[test]
    fn source_snapshot_rejects_visible_concurrent_changes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("main.rs");
        fs::write(&source, "fn main() {}")?;
        let output = tempfile::NamedTempFile::new()?;
        let mut edit = None;
        let result = snapshot_inner(root.path(), output.path(), 1048576, || {
            edit = Some(fs::write(&source, "fn main() { changed(); }"));
        });
        edit.context("snapshot hook did not run")??;
        anyhow::ensure!(result.is_err(), "snapshot accepted a changed project");
        let error = result.err().context("snapshot unexpectedly succeeded")?;
        anyhow::ensure!(
            format!("{error:#}").contains("changed while taking"),
            "unexpected snapshot error: {error:#}"
        );
        Ok(())
    }
}
