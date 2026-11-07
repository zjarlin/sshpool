//! 发布产物的校验契约：校验和、包布局、目标平台不能靠肉眼确认。
//!
//! 这里跑真实的 `scripts/package-release.sh` 与 `scripts/check-release-assets.sh`，
//! 用本机构建出来的二进制当样本，证明「合规包能过、被篡改或缺项一律失败」。
use anyhow::{Context, Result, ensure};
use sshpool::archive::sha256_bytes;
use std::{fs, path::Path, process::Command};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn tag() -> String {
    format!("v{}", version())
}

fn host_target() -> Result<String> {
    let output = Command::new("sh")
        .arg(repo().join("scripts/release-host-target.sh"))
        .output()?;
    ensure!(output.status.success(), "host target discovery failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn run(script: &str, arguments: &[&std::ffi::OsStr]) -> Result<std::process::Output> {
    Ok(Command::new("sh")
        .arg(repo().join(script))
        .args(arguments)
        .output()?)
}

fn check(dir: &Path, all: bool) -> Result<(bool, String)> {
    let tag = tag();
    let mut arguments: Vec<&std::ffi::OsStr> = vec![dir.as_os_str(), tag.as_ref()];
    if all {
        arguments.push("--all".as_ref());
    }
    let output = run("scripts/check-release-assets.sh", &arguments)?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((output.status.success(), text))
}

fn package(dir: &Path, target: &str, binary: &Path) -> Result<()> {
    let output = run(
        "scripts/package-release.sh",
        &[target.as_ref(), dir.as_os_str(), binary.as_os_str()],
    )?;
    ensure!(
        output.status.success(),
        "packaging failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// 把某个目标的摘要写进 SHA256SUMS，格式与 CI 汇总出来的一致。
fn write_sums(dir: &Path, entries: &[(&str, &str)]) -> Result<()> {
    let mut text = String::new();
    for (hash, name) in entries {
        text.push_str(&format!("{hash}  {name}\n"));
    }
    fs::write(dir.join("SHA256SUMS"), text)?;
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String> {
    Ok(sha256_bytes(&fs::read(path)?))
}

#[test]
fn a_single_platform_bundle_passes_but_is_not_a_complete_release() -> Result<()> {
    let target = host_target()?;
    let dir = tempfile::tempdir()?;
    package(
        dir.path(),
        &target,
        Path::new(env!("CARGO_BIN_EXE_sshpool")),
    )?;

    let archive = format!("sshpool-{}-{target}.tar.gz", tag());
    let hash = sha256_of(&dir.path().join(&archive))?;
    write_sums(dir.path(), &[(&hash, &archive)])?;

    let (ok, text) = check(dir.path(), false)?;
    ensure!(ok, "合规的单平台产物应当通过：{text}");
    ensure!(
        text.contains(&format!("本机运行 sshpool {}", version())),
        "应当在本机架构上真的跑一遍：{text}"
    );
    ensure!(text.contains("magic"), "应当报告平台格式：{text}");

    // 少两个目标就不能冒充完整发布。
    let (ok, text) = check(dir.path(), true)?;
    ensure!(!ok, "--all 应当拒绝缺目标的目录：{text}");
    ensure!(text.contains("缺少目标"), "{text}");
    Ok(())
}

#[test]
fn a_tampered_archive_or_a_malformed_line_is_refused() -> Result<()> {
    let target = host_target()?;
    let dir = tempfile::tempdir()?;
    package(
        dir.path(),
        &target,
        Path::new(env!("CARGO_BIN_EXE_sshpool")),
    )?;
    let archive = format!("sshpool-{}-{target}.tar.gz", tag());
    let path = dir.path().join(&archive);
    let hash = sha256_of(&path)?;
    write_sums(dir.path(), &[(&hash, &archive)])?;
    ensure!(check(dir.path(), false)?.0, "前置条件：原包应通过");

    // 只改一个字节也必须被发现。
    let original = fs::read(&path)?;
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    fs::write(&path, &tampered)?;
    let (ok, text) = check(dir.path(), false)?;
    ensure!(!ok, "被篡改的压缩包应当失败：{text}");
    ensure!(
        text.contains("FAILED") || text.contains("did NOT match"),
        "{text}"
    );

    // 摘要对了但行格式坏掉不能静默跳过 —— `sha256sum -c` 自己只给 warning 并返回 0。
    fs::write(&path, &original)?;
    let good = sha256_of(&path)?;
    ensure!(good == hash, "样本应当是原包");
    write_sums(dir.path(), &[(&good, &archive)])?;
    ensure!(check(dir.path(), false)?.0, "恢复原包后应通过");

    fs::write(
        dir.path().join("SHA256SUMS"),
        format!("{good}  {archive}\ndeadbee  {archive}\n"),
    )?;
    let (ok, text) = check(dir.path(), false)?;
    ensure!(!ok, "格式错误的摘要行应当失败：{text}");
    ensure!(text.contains("格式不符"), "{text}");

    // 大写摘要不是声明格式。
    fs::write(
        dir.path().join("SHA256SUMS"),
        format!("{}  {archive}\n", good.to_uppercase()),
    )?;
    ensure!(!check(dir.path(), false)?.0, "大写摘要应当失败");
    Ok(())
}

#[test]
fn undeclared_names_and_unsafe_archive_layouts_are_refused() -> Result<()> {
    let target = host_target()?;
    let dir = tempfile::tempdir()?;
    package(
        dir.path(),
        &target,
        Path::new(env!("CARGO_BIN_EXE_sshpool")),
    )?;
    let archive = format!("sshpool-{}-{target}.tar.gz", tag());
    let hash = sha256_of(&dir.path().join(&archive))?;

    // 名字里混进第四个目标，不是声明平台。
    let stray = format!("sshpool-{}-riscv64gc-unknown-linux-gnu.tar.gz", tag());
    let somewhere = tempfile::tempdir()?;
    fs::write(somewhere.path().join(&stray), b"not a real bundle")?;
    fs::copy(somewhere.path().join(&stray), dir.path().join(&stray))?;
    let stray_hash = sha256_of(&dir.path().join(&stray))?;
    write_sums(dir.path(), &[(&hash, &archive), (&stray_hash, &stray)])?;
    let (ok, text) = check(dir.path(), false)?;
    ensure!(!ok, "未声明的目标应当失败：{text}");
    ensure!(text.contains("不属于声明目标"), "{text}");
    fs::remove_file(dir.path().join(&stray))?;

    // 包内出现绝对路径或 `..` 一律拒绝。用 python 的 tarfile 精确造出这两种成员。
    let bundle = format!("sshpool-{}-{target}", tag());
    let binary = fs::read(env!("CARGO_BIN_EXE_sshpool"))?;
    for member in [format!("/{bundle}/sshpool"), format!("../{bundle}/sshpool")] {
        let staging = tempfile::tempdir()?;
        let script = staging.path().join("make_tar.py");
        let archive_path = staging.path().join(&archive);
        fs::write(staging.path().join("payload"), &binary)?;
        fs::write(
            &script,
            format!(
                "import tarfile\n\
                 with tarfile.open({archive:?}, 'w:gz') as tar:\n\
                 \x20   info = tar.gettarinfo({payload:?})\n\
                 \x20   info.name = {member:?}\n\
                 \x20   info.mode = 0o755\n\
                 \x20   with open({payload:?}, 'rb') as handle:\n\
                 \x20       tar.addfile(info, handle)\n\
                 \x20   tar.add({license:?}, arcname={license_name:?})\n",
                archive = archive_path.to_str().context("path is not utf-8")?,
                payload = staging.path().join("payload").display().to_string(),
                member = member,
                license = repo().join("LICENSE").display().to_string(),
                license_name = format!("/{bundle}/LICENSE"),
            ),
        )?;
        let built = Command::new("python3").arg(&script).output()?;
        ensure!(built.status.success(), "构造测试压缩包失败");
        let evil_hash = sha256_of(&archive_path)?;
        fs::copy(&archive_path, dir.path().join(&archive))?;
        write_sums(dir.path(), &[(&evil_hash, &archive)])?;
        let (ok, text) = check(dir.path(), false)?;
        ensure!(!ok, "含 {member} 的压缩包应当失败：{text}");
        ensure!(
            text.contains("可疑路径"),
            "应当因为路径逃逸被拒绝，而不是别的理由：{text}"
        );
    }
    Ok(())
}

#[test]
fn packaging_refuses_a_binary_that_is_not_there() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let output = run(
        "scripts/package-release.sh",
        &[
            "x86_64-unknown-linux-gnu".as_ref(),
            dir.path().as_os_str(),
            dir.path().join("missing").as_os_str(),
        ],
    )?;
    ensure!(!output.status.success(), "缺少二进制时打包应当失败");
    let text = String::from_utf8_lossy(&output.stderr);
    ensure!(text.contains("缺少"), "错误信息应当是中文可读的：{text}");
    ensure!(
        fs::read_dir(dir.path())?.next().is_none(),
        "失败时不留半成品"
    );
    Ok(())
}

#[test]
fn the_baseline_gate_reports_the_real_baseline_and_refuses_foreign_files() -> Result<()> {
    let target = host_target()?;
    let output = run(
        "scripts/release-baseline.sh",
        &[env!("CARGO_BIN_EXE_sshpool").as_ref(), target.as_ref()],
    )?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match output.status.code() {
        // 本机构建机等于或老于承诺的系统版本：闸门通过。
        Some(0) => ensure!(text.contains("baseline"), "应当打印观测到的基线：{text}"),
        // 构建机比承诺的新（例如在 glibc 2.39 的 runner 上构建 Linux 目标）：
        // 闸门必须用退出码 2 明确拒绝，而不是放过一个跑不起来的产物。
        Some(2) => ensure!(
            text.contains("基线不成立"),
            "退出码 2 必须说明是基线不成立：{text}"
        ),
        other => panic!("基线闸门的退出码只能是 0 或 2，实际 {other:?}：{text}"),
    }

    // 目标与文件格式不符必须失败，而不是把别的格式当成"基线通过"。
    let dir = tempfile::tempdir()?;
    let garbage = dir.path().join("not-a-binary");
    fs::write(&garbage, b"definitely not an ELF or Mach-O file")?;
    let foreign = if target.contains("linux") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let output = run(
        "scripts/release-baseline.sh",
        &[garbage.as_os_str(), foreign.as_ref()],
    )?;
    ensure!(
        !output.status.success(),
        "非本平台格式的文件不应通过基线闸门"
    );
    ensure!(
        output.status.code() == Some(2),
        "基线不成立应当用退出码 2 表达：{:?}",
        output.status
    );
    Ok(())
}

#[test]
fn tag_checking_agrees_with_cargo_and_refuses_mismatches() -> Result<()> {
    let expected = format!("v{}", version());

    // 1. 无输入：演练，标签由 Cargo.toml 推导，且如实标出"标签不存在"。
    let output = run("scripts/release-check-tag.sh", &[])?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(output.status.success(), "演练应当继续：{text}");
    ensure!(text.contains(&format!("version={}", version())), "{text}");
    ensure!(text.contains(&format!("tag={expected}")), "{text}");
    if output_text_has_no_tag(&expected) {
        ensure!(
            text.contains("rehearsal=true"),
            "标签不存在时必须是演练：{text}"
        );
        ensure!(text.contains("不存在"), "应当明说不存在：{text}");
    }

    // 2. 版本号对不上：直接拒绝（退出码 2），不能"尽力而为"地发布。
    let output = Command::new("sh")
        .arg(repo().join("scripts/release-check-tag.sh"))
        .env("TAG_INPUT", "v99.0.0")
        .output()?;
    ensure!(!output.status.success(), "版本不一致必须失败");
    ensure!(
        output.status.code() == Some(2),
        "应当用退出码 2：{:?}",
        output.status
    );
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains("不一致"),
        "应当说明原因"
    );

    // 3. 标签存在但指向别的提交：也要拒绝，不允许拿别的提交冒充标签。
    //    这一步用临时 git 仓库造现场，与真实仓库是否已有同名标签无关，所以无条件执行。
    {
        let dir = tempfile::tempdir()?;
        let git = |arguments: &[&str]| -> Result<std::process::Output> {
            Ok(Command::new("git")
                .args(arguments)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()?)
        };
        ensure!(
            git(&["init", "-q", "-b", "main"])?.status.success(),
            "git init 失败"
        );
        fs::write(
            dir.path().join("Cargo.toml"),
            format!("[package]\nname = \"x\"\nversion = \"{}\"\n", version()),
        )?;
        fs::create_dir_all(dir.path().join("scripts"))?;
        for script in ["release-version.sh", "release-check-tag.sh"] {
            fs::copy(
                repo().join("scripts").join(script),
                dir.path().join("scripts").join(script),
            )?;
        }
        ensure!(git(&["add", "."])?.status.success(), "git add 失败");
        ensure!(
            git(&["commit", "-qm", "one"])?.status.success(),
            "git commit 失败"
        );
        let first = String::from_utf8(git(&["rev-parse", "HEAD"])?.stdout)?
            .trim()
            .to_owned();
        ensure!(git(&["tag", &expected])?.status.success(), "打标签失败");
        fs::write(dir.path().join("extra"), b"second commit")?;
        ensure!(git(&["add", "."])?.status.success(), "git add 失败");
        ensure!(
            git(&["commit", "-qm", "two"])?.status.success(),
            "git commit 失败"
        );
        let second = String::from_utf8(git(&["rev-parse", "HEAD"])?.stdout)?
            .trim()
            .to_owned();
        ensure!(first != second, "两个提交应当不同");

        let output = Command::new("sh")
            .arg(dir.path().join("scripts/release-check-tag.sh"))
            .env("TAG_INPUT", &expected)
            .current_dir(dir.path())
            .output()?;
        ensure!(!output.status.success(), "标签指向别的提交时必须失败");
        ensure!(
            output.status.code() == Some(2),
            "应当用退出码 2：{:?}",
            output.status
        );
        let text = String::from_utf8_lossy(&output.stderr);
        ensure!(
            text.contains("不是") && text.contains("标签指向"),
            "应当指出指向差异：{text}"
        );
    }
    Ok(())
}

fn output_text_has_no_tag(tag: &str) -> bool {
    Command::new("git")
        .args(["rev-parse", "-q", "--verify", &format!("refs/tags/{tag}")])
        .current_dir(repo())
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
}
