//! 构建包装命令的路由决策。
//!
//! `cargo` / `gradle` / `make` 的 shim 只有在「这次调用确实要构建」且「当前目录属于
//! 显式加入 `sshpool.toml` 的项目」时才转交控制面；其余情况必须落回本机工具，
//! 否则 `cargo --version` 会被当成一次远程构建。
use crate::{config::Build, runner};
use anyhow::{Result, ensure};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

/// shim 只接管这三个工具；其他名字一律拒绝，避免静默转发未知命令。
pub const TOOLS: [&str; 3] = ["cargo", "gradle", "make"];

/// 这次调用是否属于「真的会构建」的那类子命令。
pub fn activates(tool: &str, arguments: &[String]) -> Result<bool> {
    ensure!(TOOLS.contains(&tool), "unsupported shim: {tool}");
    Ok(match tool {
        // `cargo run` / `cargo fmt` / `cargo --version` 都不该被转成远程构建：
        // 前三者是本地交互，后者只是查询。只有这四个子命令明确产生构建产物。
        "cargo" => arguments.first().is_some_and(|argument| {
            ["build", "test", "check", "clippy"].contains(&argument.as_str())
        }),
        // make / gradle 的查询类参数没有副作用；其余都按构建处理。
        _ => !arguments
            .iter()
            .any(|argument| ["--version", "-v", "--help", "-h"].contains(&argument.as_str())),
    })
}

/// 向上查找第一个含 `sshpool.toml` 的目录；没有则返回 `None`（走本机）。
pub fn project_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .find(|directory| directory.join("sshpool.toml").is_file())
        .map(Path::to_path_buf)
}

/// 一次 shim 调用的去向。
#[derive(Debug)]
pub enum Route {
    /// 落到本机工具：查询版本、帮助或不属于任何项目。
    Local,
    /// 转交控制面；命令行是 `tool + arguments`，用户原命令原样保留。
    Remote { root: PathBuf, build: Build },
}

/// 决定这次调用是否提交远程构建。
///
/// 项目根之外的子目录直接拒绝：在 `src/` 里跑 `cargo build` 若被悄悄提到项目根，
/// 上传的源码范围会和用户预期不同，这类「善意的猜测」必须失败关闭。
pub fn route(cwd: &Path, tool: &str, arguments: &[String]) -> Result<Route> {
    if !activates(tool, arguments)? {
        return Ok(Route::Local);
    }
    let Some(root) = project_root(cwd) else {
        return Ok(Route::Local);
    };
    ensure!(
        root == cwd,
        "run distributed builds from project root: {}",
        root.display()
    );
    let mut build = runner::read_build(&root.join("sshpool.toml"))?;
    build.command = std::iter::once(tool.to_string())
        .chain(arguments.iter().cloned())
        .collect();
    Ok(Route::Remote { root, build })
}

/// 从 `PATH` 找到第一个不在 shim 目录里的同名工具。
///
/// 必须跳过 shim 目录本身，否则 `install-shims` 后的 `PATH` 会让 shim 递归 exec 自己。
/// `shims` 允许不存在：从未执行过 `install-shims` 的用户也会走到本机回退，
/// 此时对空目录做 canonicalize 会直接报错，把「本机 cargo 跑不了」变成整个 shim 失败。
pub fn local_binary(tool: &str, path: &OsStr, shims: &Path) -> Option<PathBuf> {
    let shims = canonical_or_self(shims);
    std::env::split_paths(path)
        .filter(|directory| canonical_or_self(directory) != shims)
        .map(|directory| directory.join(tool))
        .find(|binary| binary.is_file())
}

/// 目录存在时取真实路径，不存在时用原样路径；只用于比较，不创建任何东西。
fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{Route, activates, local_binary, project_root, route};
    use anyhow::Result;
    use std::{ffi::OsString, fs};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn project(root: &std::path::Path, body: &str) -> Result<()> {
        fs::write(root.join("sshpool.toml"), body)?;
        Ok(())
    }

    /// 只有会产出构建结果的子命令才走远程；查询与交互留在本机。
    #[test]
    fn only_build_subcommands_are_intercepted() -> Result<()> {
        for command in ["build", "test", "check", "clippy"] {
            assert!(
                activates("cargo", &arguments(&[command]))?,
                "cargo {command} must be a build"
            );
        }
        for command in ["--version", "run", "fmt", "metadata"] {
            assert!(
                !activates("cargo", &arguments(&[command]))?,
                "cargo {command} must stay local"
            );
        }
        assert!(
            !activates("cargo", &arguments(&[]))?,
            "bare cargo stays local"
        );
        assert!(activates("make", &arguments(&["-j4"]))?);
        assert!(activates("gradle", &arguments(&["assemble"]))?);
        for flag in ["--version", "-v", "--help", "-h"] {
            assert!(
                !activates("make", &arguments(&[flag]))?,
                "make {flag} must stay local"
            );
            assert!(!activates("gradle", &arguments(&[flag]))?);
        }
        Ok(())
    }

    #[test]
    fn unsupported_tools_are_rejected() -> Result<()> {
        let error = activates("npm", &arguments(&["build"])).expect_err("npm must be refused");
        assert!(error.to_string().contains("unsupported shim"), "{error}");
        Ok(())
    }

    /// 项目根之外的子目录必须报错，不能悄悄提升到项目根上传。
    #[test]
    fn a_subdirectory_cannot_start_a_distributed_build() -> Result<()> {
        let root = tempfile::tempdir()?;
        project(root.path(), "image = \"alpine:3.22\"\n")?;
        let nested = root.path().join("src");
        fs::create_dir(&nested)?;
        let error = route(&nested, "cargo", &arguments(&["build"]))
            .expect_err("a nested build must be refused");
        assert!(
            error.to_string().contains("project root"),
            "the error must point at the project root: {error}"
        );
        Ok(())
    }

    /// 已加入的项目：原命令逐字保留，不做任何重写。
    #[test]
    fn the_original_command_is_preserved_verbatim() -> Result<()> {
        let root = tempfile::tempdir()?;
        project(
            root.path(),
            "image = \"alpine:3.22\"\nplatform = \"linux/amd64\"\n",
        )?;
        let flags = arguments(&["build", "--release", "--offline"]);
        let Route::Remote { root: found, build } = route(root.path(), "cargo", &flags)? else {
            panic!("the project must be routed to the controller");
        };
        assert_eq!(found, root.path());
        assert_eq!(
            build.command,
            arguments(&["cargo", "build", "--release", "--offline"])
        );
        assert_eq!(build.image, "alpine:3.22");
        // 排他：参数里的 `--offline` 是用户意图，不是 shim 添加的。
        assert!(
            build
                .command
                .iter()
                .filter(|arg| *arg == "--offline")
                .count()
                == 1
        );
        Ok(())
    }

    /// 没有项目配置时绝不能拦截；普通 shell 里的构建仍在本机跑。
    #[test]
    fn a_directory_without_configuration_stays_local() -> Result<()> {
        let root = tempfile::tempdir()?;
        assert!(project_root(root.path()).is_none());
        assert!(matches!(
            route(root.path(), "make", &arguments(&[]))?,
            Route::Local
        ));
        Ok(())
    }

    /// 无效的项目配置必须报错，而不是退化成「本机执行」的静默降级。
    ///
    /// 缺省字段会取安全默认值（例如省略 `image` 用 `alpine:3.22`），这不算无效配置；
    /// 真正越界的是显式写死的非法平台、超限内存等。
    #[test]
    fn an_invalid_project_is_reported_not_downgraded() -> Result<()> {
        let root = tempfile::tempdir()?;
        project(root.path(), "platform = \"linux/riscv64\"\n")?;
        let error = route(root.path(), "cargo", &arguments(&["build"]))
            .expect_err("an invalid sshpool.toml must fail loudly");
        assert!(
            error.to_string().contains("platform"),
            "the error must name the invalid field: {error}"
        );
        Ok(())
    }

    /// 省略字段走默认值是允许的；不能把「没写」当成「无效」。
    #[test]
    fn omitted_fields_fall_back_to_validated_defaults() -> Result<()> {
        let root = tempfile::tempdir()?;
        project(root.path(), "")?;
        let Route::Remote { build, .. } = route(root.path(), "cargo", &arguments(&["check"]))?
        else {
            panic!("an empty but present sshpool.toml still joins the project");
        };
        assert!(build.validate().is_ok());
        Ok(())
    }

    /// 查找本机工具时必须跳过 shim 目录，否则递归 exec 自己。
    #[test]
    fn local_binary_search_skips_the_shim_directory() -> Result<()> {
        let home = tempfile::tempdir()?;
        let shims = home.path().join("bin");
        fs::create_dir(&shims)?;
        fs::write(shims.join("make"), "#!/bin/sh\n")?;
        let real = home.path().join("real");
        fs::create_dir(&real)?;
        fs::write(real.join("make"), "#!/bin/sh\n")?;
        let path = std::env::join_paths([shims.as_path(), real.as_path()])?;
        let found = local_binary("make", &path, &shims).expect("the real tool must be found");
        assert_eq!(found, real.join("make"));
        // 只存在 shim 时必须判定「本机没有工具」，交给上层报错而不是递归。
        let only_shims = OsString::from(shims.as_os_str());
        assert!(local_binary("make", &only_shims, &shims).is_none());
        // 从未 install-shims 的用户：bin 目录不存在也必须能继续回退，而不是报错。
        let missing = home.path().join("no-such-bin");
        assert!(
            local_binary("make", &path, &missing).is_some(),
            "a missing shim directory must not break the local fallback"
        );
        Ok(())
    }
}
