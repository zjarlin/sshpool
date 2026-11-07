#!/bin/sh
# 打印 Cargo.toml [package] 的版本；发布流程与本地核对共用同一份解析。
set -eu
cd "$(dirname "$0")/.."
awk '
  /^\[/ { section = $0 }
  section == "[package]" && /^version[[:space:]]*=/ {
    line = $0
    sub(/^version[[:space:]]*=[[:space:]]*"/, "", line)
    sub(/".*$/, "", line)
    print line
    exit
  }
' Cargo.toml
