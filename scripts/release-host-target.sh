#!/bin/sh
# 打印本机的 Rust 目标三元组（只覆盖已发布的平台），用于判断产物能否在本机冒烟。
# SSHPOOL_RELEASE_HOST_TARGET 可以覆盖：交叉编译的机器、或测试里需要显式跳过冒烟时用。
set -eu
if [ -n "${SSHPOOL_RELEASE_HOST_TARGET:-}" ]; then
  echo "$SSHPOOL_RELEASE_HOST_TARGET"
  exit 0
fi
os=$(uname -s)
arch=$(uname -m)
case "${os}-${arch}" in
  Linux-x86_64) echo x86_64-unknown-linux-gnu ;;
  Darwin-arm64) echo aarch64-apple-darwin ;;
  Darwin-x86_64) echo x86_64-apple-darwin ;;
  *)
    echo "unsupported host: ${os}-${arch}" >&2
    exit 1
    ;;
esac
