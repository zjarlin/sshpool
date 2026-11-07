#!/bin/sh
# 本地演练发布：按 CI 的顺序构建、过基线闸门、打包、校验三个产物。
#
#   scripts/rehearse-release.sh <输出目录>
#
# Linux 目标需要一台 glibc 2.35 的构建机（容器即可），用 SSHPOOL_LINUX_BUILDER 指定：
#   SSHPOOL_LINUX_BUILDER='docker run --rm -v $PWD:/src -w /src ubuntu:22.04 ...' 之类由调用方决定；
# 只给本地一个目标时，最后一步要求 --all 会失败，这是有意的。
set -eu
out=${1:?用法: rehearse-release.sh <输出目录>}
cd "$(dirname "$0")/.."
mkdir -p "$out"
out=$(cd "$out" && pwd)

for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --locked --target "$target"
  sh scripts/release-baseline.sh "target/${target}/release/sshpool" "$target"
  sh scripts/package-release.sh "$target" "$out"
done

if [ -n "${SSHPOOL_LINUX_BINARY:-}" ]; then
  sh scripts/release-baseline.sh "$SSHPOOL_LINUX_BINARY" x86_64-unknown-linux-gnu
  sh scripts/package-release.sh x86_64-unknown-linux-gnu "$out" "$SSHPOOL_LINUX_BINARY"
else
  echo "未设置 SSHPOOL_LINUX_BINARY：跳过 Linux 目标，最后一步 --all 会按要求失败" >&2
fi

cd "$out"
cat ./*.tar.gz.sha256 > SHA256SUMS
rm ./*.tar.gz.sha256
cd - >/dev/null
sh scripts/check-release-assets.sh "$out" "v$(sh scripts/release-version.sh)" --all
