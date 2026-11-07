# 版本发布

发布物是**预发布品质的二进制**，不是生产承诺。每次发布都包含：

- 三个目标平台各一个 `sshpool-v<版本>-<目标>.tar.gz`（内含 `sshpool` 与 `LICENSE`）；
- 一条汇总的 `SHA256SUMS`；
- 一段说明支持系统版本的发布说明（`docs/release-notes/<标签>.md`）。

## 目标平台与基线

| 目标三元组 | 构建环境 | 最低系统 | 说明 |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04（glibc 2.35） | glibc ≥ 2.35（Ubuntu 22.04+、Debian 12+、RHEL 9+） | 动态链接，运行时需要系统 OpenSSH |
| `aarch64-apple-darwin` | macOS runner | macOS ≥ 11.0 | Apple Silicon 原生 |
| `x86_64-apple-darwin` | macOS runner | macOS ≥ 10.12 | Intel 与 Rosetta |

基线不是口头声明：CI 里跑 `scripts/release-baseline.sh` 读真实产物——Linux 用 `readelf --dyn-syms` 取 `GLIBC_*` 符号版本上限，macOS 用 `otool -l` 取 `LC_BUILD_VERSION/minos`（老式目标回落到 `LC_VERSION_MIN_MACOSX/version`）。超出基线就以退出码 2 失败，不发布。

Linux 之所以固定在 22.04 上构建：链接器只会引用**构建机已有的** glibc 符号。在 24.04 上构建出来的产物会带 `GLIBC_2.39`（实测 `pidfd_getpid`、`pidfd_spawnp`），在 22.04 上直接跑不起来。这不是「建议」，是实测拦下来的。

## 发行流程

```sh
# 1. 版本号只改 Cargo.toml，标签必须完全一致
cargo set-version 0.2.0     # 或手工改 Cargo.toml
git commit -am 'chore: bump to 0.2.0'
git push

# 2. 写发布说明（可选；没有则用 GitHub 自动生成的变更列表）
${EDITOR} docs/release-notes/v0.2.0.md
git commit -am 'docs: release notes for v0.2.0' && git push

# 3. 打标签即发布
git tag v0.2.0
git push origin v0.2.0
```

推 `v*` 标签会触发 `.github/workflows/release.yml`：三个平台各建一次、过基线闸门、打包、算校验和；最后一个 job 汇总 `SHA256SUMS`、用 `scripts/check-release-assets.sh --all` 复核，然后创建 GitHub Release。

## 演练

不想为了验证流水线就造一个真标签，用 `workflow_dispatch`：

```sh
gh workflow run release.yml                        # 演练：按当前 main 构建，只留工作流产物
gh workflow run release.yml -f publish=true        # 核对无误后再建 Release
```

演练与正式发布走**同一套**构建、基线闸门和校验，区别只有两处：

- 标签不存在时，job 在日志里写「标签 vX.Y.Z 不存在：按提交 abc1234 演练」，并把 `rehearsal=true` 传下去；
- `rehearsal=true` 时最后一步「发布」被跳过，产物留在 Actions 的 `sshpool-release-assets` artifact 里。

标签**存在**时则相反：必须 `git rev-parse <tag>^{commit}` 等于检出提交，否则直接失败——不允许拿别的提交冒充某个标签。

## 本地复现与校验

三个目标都能在本机复现；Linux 那个必须在 glibc 2.35 的环境里构建，否则基线闸门会失败——这正是它的用途。

```sh
# macOS 两个目标
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --locked --target aarch64-apple-darwin
cargo build --release --locked --target x86_64-apple-darwin
sh scripts/release-baseline.sh target/aarch64-apple-darwin/release/sshpool aarch64-apple-darwin

# Linux 目标：在 22.04 容器里构建，避免把构建机的 glibc 带进产物
docker run --rm -v "$PWD:/src" -w /src ubuntu:22.04 bash -c '
  apt-get update -qq && apt-get install -y -qq build-essential curl ca-certificates &&
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.94.0 &&
  . "$HOME/.cargo/env" && cargo build --release --locked --target x86_64-unknown-linux-gnu'

# 打包 + 汇总校验和
sh scripts/package-release.sh aarch64-apple-darwin dist
sh scripts/package-release.sh x86_64-apple-darwin dist
sh scripts/package-release.sh x86_64-unknown-linux-gnu dist target/x86_64-unknown-linux-gnu/release/sshpool
(cd dist && cat ./*.tar.gz.sha256 > SHA256SUMS && rm ./*.tar.gz.sha256)
sh scripts/check-release-assets.sh dist v0.1.0 --all
```

下载别人的产物时，同一份脚本就是验收工具：

```sh
mkdir -p /tmp/sshpool-v0.1.0 && cd /tmp/sshpool-v0.1.0
gh release download v0.1.0 -R zjarlin/sshpool
sh /path/to/sshpool/scripts/check-release-assets.sh . v0.1.0 --all
```

它校验的是：每条摘要格式合法（64 位小写十六进制 + 两个空格 + 声明目标的文件名）、`sha256sum -c` 全部通过、压缩包只有一个顶层目录且不含绝对路径/`..`/链接、可执行位存在、文件头与本机能否运行。

发布脚本各自只做一件事，都能单独跑：

| 脚本 | 作用 | 失败时的行为 |
| --- | --- | --- |
| `scripts/release-version.sh` | 打印 `Cargo.toml` 的版本 | — |
| `scripts/release-host-target.sh` | 打印本机目标三元组（可用 `SSHPOOL_RELEASE_HOST_TARGET` 覆盖） | 未支持平台报告 unsupported |
| `scripts/release-check-tag.sh` | 核对标签与版本、标签指向；输出 `version`/`tag`/`rehearsal` | 不一致或指向别的提交时退出码 2 |
| `scripts/release-baseline.sh` | 量产物真实平台基线并与承诺比较 | 超出基线退出码 2 |
| `scripts/glibc-symbol-version.py` | 只读 `.gnu.version_r`，在没有 `readelf` 的机器上也能量 glibc | 非 ELF / 无版本需求时退出码 2 |
| `scripts/package-release.sh` | 打包成 `<bundle>/sshpool` + `LICENSE` 并算 sha256 | 缺可执行二进制时不产出半成品 |
| `scripts/check-release-assets.sh` | 校验和 + 布局 + 格式 + 版本 | 任何一项不符非零退出 |
| `scripts/rehearse-release.sh` | 本地按 CI 顺序全流程演练 | 同上游脚本 |


## 已知限制

- **没有代码签名也没有公证**：macOS 产物是 ad-hoc 签名，`spctl` 不认；首次运行需要 `xattr -d com.apple.quarantine` 或自己重新签名。Linux 产物只有 sha256，没有 GPG 签名或透明日志。
- **Linux 产物是动态链接**：没有静态 musl 变体，所以 Alpine 之类不跑。需要 musl 版本就得另加一个目标和一套构建环境。
- **只发三个目标**：没有 Linux aarch64、没有 Windows 原生（WSL2 用 Linux 产物）。`scripts/release-host-target.sh` 也只认同这三个，别的平台会明确报 unsupported。
- **校验和防的是传输损坏，不是篡改**：`SHA256SUMS` 和压缩包放在同一个 Release 里，能改 Release 的人也能改校验和。需要更强保证时用提交里签出的脚本自行复算，或后续加 GPG 签名。
- 版本号仍是 `0.x`，发布标记为 prerelease。二进制能跑通 `--version` 只说明打包正确，不代表 `docs/validation.md` 里的场景都通过。
