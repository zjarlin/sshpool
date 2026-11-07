#!/usr/bin/env bash
# 为一个真实工作台准备当前源码构建出的 Linux 客户端二进制。
#
# `tests/hardware_live.rs` 需要工作台侧运行**当前源码**的 sshpool 客户端：
# 客户端要发 `x-sshpool-source-sha256` 并走与测试内控制面一致的协议，
# 因此不能复用工作台上任意历史安装版。本脚本只做两件事：同步源码、构建。
#
#   scripts/prepare-live-workbench.sh sshpool-anchor
#   # 输出远端二进制路径，供 SSHPOOL_LIVE_WORKBENCH_BIN 使用
set -euo pipefail
target=${1:?usage: prepare-live-workbench.sh <ssh-alias> [remote-dir]}
dir=${2:-/tmp/sshpool-src}
root=$(cd "$(dirname "$0")/.." && pwd)
# 只同步源码与 lock 文件：不带 target（数十 GB）和 .git（工作台未必有远端凭据）。
tar -c -C "$root" --exclude .git --exclude target . \
  | ssh "$target" "mkdir -p '$dir' && tar -x -C '$dir'"
ssh "$target" "cd '$dir' && cargo build --release --locked 1>&2 && echo '$dir/target/release/sshpool'"
