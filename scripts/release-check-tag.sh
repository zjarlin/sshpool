#!/bin/sh
# 核对发布标签：与 Cargo.toml 版本一致；存在时必须指向当前检出的提交。
#
#   TAG_INPUT=<标签或空> scripts/release-check-tag.sh
#
# 输出 KEY=VALUE 供 CI 写进 GITHUB_OUTPUT（version / tag / rehearsal）。
# 退出码 2 表示标签不合格（版本不符、指向别的提交），发布必须停下。
set -eu
cd "$(dirname "$0")/.."

version=$(sh scripts/release-version.sh)
# 空输入回落到 v<版本>：演练时不需要先造一个标签。
tag=${TAG_INPUT:-v$version}

[ "$tag" = "v$version" ] || {
  echo "标签 ${tag} 与 Cargo.toml 版本 v${version} 不一致" >&2
  exit 2
}

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1; then
  checked_out=$(git rev-parse HEAD)
  tagged=$(git rev-parse "${tag}^{commit}")
  [ "$checked_out" = "$tagged" ] || {
    echo "检出的提交 ${checked_out} 不是 ${tag}（标签指向 ${tagged}）" >&2
    exit 2
  }
  rehearsal=false
else
  # 标签不存在：这是演练，不是发布。允许继续，但把事实写进日志与输出。
  echo "标签 ${tag} 不存在：按提交 $(git rev-parse --short HEAD) 演练" >&2
  rehearsal=true
fi

printf 'version=%s\n' "$version"
printf 'tag=%s\n' "$tag"
printf 'rehearsal=%s\n' "$rehearsal"
