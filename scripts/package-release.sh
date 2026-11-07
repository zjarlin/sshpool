#!/bin/sh
# 把构建好的二进制打包成发布产物：sshpool-v<版本>-<目标>.tar.gz + .sha256。
#
#   scripts/package-release.sh <目标三元组> <输出目录> [二进制路径]
#
# 不传二进制路径时读 target/<目标>/release/sshpool。只打包与摘要，不构建。
# 版本来自 Cargo.toml，避免文件名与二进制版本不一致。
set -eu
target=${1:?用法: package-release.sh <目标> <输出目录> [二进制]}
out=${2:?用法: package-release.sh <目标> <输出目录> [二进制]}
cd "$(dirname "$0")/.."

if [ "$#" -ge 3 ]; then
  binary=$3
else
  binary="target/${target}/release/sshpool"
fi
[ -x "$binary" ] || { echo "缺少可执行的 ${binary}" >&2; exit 1; }

version=$(sh scripts/release-version.sh)
bundle="sshpool-v${version}-${target}"
mkdir -p "${out}/${bundle}"
# 统一装成 sshpool：二进制文件名不参与约定，改名后解包目录才可预测。
cp "$binary" "${out}/${bundle}/sshpool"
cp LICENSE "${out}/${bundle}/LICENSE"
tar -czf "${out}/${bundle}.tar.gz" -C "$out" "$bundle"
rm -r "${out}/${bundle}"

cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${bundle}.tar.gz" > "${bundle}.tar.gz.sha256"
else
  shasum -a 256 "${bundle}.tar.gz" > "${bundle}.tar.gz.sha256"
fi
cat "${bundle}.tar.gz.sha256"
