use anyhow::{Context, Result, ensure};
use ignore::WalkBuilder;
use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Component, Path},
};

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
pub fn snapshot(root: &Path, destination: &Path, max_bytes: u64) -> Result<u64> {
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
    let walker = WalkBuilder::new(&root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .filter_entry(|entry| entry.depth() == 0 || !excluded(&entry.file_name().to_string_lossy()))
        .build();
    let file = File::create(destination)?;
    let mut builder = tar::Builder::new(file);
    let mut bytes = 0_u64;
    let mut count = 0;
    for entry in walker {
        let entry = entry?;
        if entry.depth() == 0 || entry.file_type().is_some_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry.path();
        let relative = path.strip_prefix(&root)?;
        relative_path(relative)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "only regular source files are allowed: {}",
            relative.display()
        );
        count += 1;
        ensure!(count <= 100_000, "too many source files");
        bytes = bytes
            .checked_add(metadata.len())
            .context("source size overflow")?;
        ensure!(bytes <= max_bytes, "source exceeds upload limit");
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        header.set_mode(if executable { 0o755 } else { 0o644 });
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, relative, File::open(path)?)?;
    }
    builder.finish()?;
    ensure!(
        fs::metadata(destination)?.len() <= max_bytes,
        "source archive exceeds upload limit including metadata"
    );
    Ok(bytes)
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
