#!/bin/sh
# 校验发布产物：校验和、压缩包布局、目标平台与版本。
#
#   scripts/check-release-assets.sh <产物目录> <标签> [--all]
#
# 不加 --all 时校验目录里现有的产物，但它们必须是声明目标的一个子集
# （CI 每个平台只构建自己的目标）；加 --all 要求三个目标齐全，用于发布后复核。
# 只读；任何一项不符合就以非零退出。
set -eu

dir=${1:?用法: check-release-assets.sh <产物目录> <标签> [--all]}
tag=${2:?用法: check-release-assets.sh <产物目录> <标签> [--all]}
require_all=${3:-}
version=${tag#v}
declared='x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin'

cd "$dir"
[ -f SHA256SUMS ] || { echo '缺少 SHA256SUMS' >&2; exit 1; }

# 先自己把格式钉死：sha256sum -c 遇到「格式不对的行」只给 warning 仍然返回 0，
# 一条坏行会被静默跳过，等于检查没做。缺行、多行、大写或短摘要都必须显式失败。
bad=$(grep -cvE '^[0-9a-f]{64} [ *][^/].*\.tar\.gz$' SHA256SUMS || true)
[ "$bad" -eq 0 ] || { echo "SHA256SUMS 有 ${bad} 行格式不符" >&2; exit 1; }

listed=$(sed 's/^[0-9a-f]*[ *]*//' SHA256SUMS | sort)
count=$(printf '%s\n' "$listed" | grep -c . || true)

# 逐条核对「文件名属于声明目标」，放在摘要校验之前：名字错了是发布配置问题，
# 比"No such file"这种下游症状更好定位。
seen=''
for entry in $listed; do
  matched=''
  for target in $declared; do
    [ "$entry" = "sshpool-$tag-$target.tar.gz" ] && matched=$target
  done
  [ -n "$matched" ] || { echo "SHA256SUMS 里的 $entry 不属于声明目标" >&2; exit 1; }
  seen="$seen $matched"
done

for entry in $listed; do
  [ -f "$entry" ] || { echo "SHA256SUMS 列了 ${entry}，但目录里没有这个文件" >&2; exit 1; }
done

if [ "$require_all" = '--all' ]; then
  for target in $declared; do
    case " $seen " in
      *" $target "*) ;;
      *) echo "缺少目标 $target 的产物" >&2; exit 1 ;;
    esac
  done
  [ "$count" -eq 3 ] || { echo "应有 3 条摘要，实际 $count" >&2; exit 1; }
fi

echo "checksums: ok ($count 条)"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c --strict --quiet SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS >/dev/null
fi

host_target=$(sh "$(dirname "$0")/release-host-target.sh" 2>/dev/null || echo '')

work=$(mktemp -d)
trap 'rm -r "$work"' EXIT INT TERM

for target in $seen; do
  bundle="sshpool-$tag-$target"
  archive="$bundle.tar.gz"

  # 压缩包只能有一个顶层目录，且不得出现绝对路径、父目录穿越或链接。
  tar -tzf "$archive" > "$work/list"
  if grep -Eq '^(/|\.\.)' "$work/list" || grep -Eq '(^|/)\.\./' "$work/list"; then
    echo "$archive 含可疑路径" >&2
    exit 1
  fi
  prefixes=$(sed 's#/.*##' "$work/list" | sort -u)
  [ "$prefixes" = "$bundle" ] || {
    echo "$archive 的顶层目录应为 ${bundle}，实际: $prefixes" >&2
    exit 1
  }
  if tar -tvzf "$archive" | grep -Eq '^[lh]'; then
    echo "$archive 含符号链接或硬链接" >&2
    exit 1
  fi
  for entry in "$bundle/sshpool" "$bundle/LICENSE"; do
    grep -Fxq "$entry" "$work/list" || { echo "$archive 缺少 $entry" >&2; exit 1; }
  done

  mkdir -p "$work/$target"
  tar -xzf "$archive" -C "$work/$target"
  binary="$work/$target/$bundle/sshpool"
  [ -x "$binary" ] || { echo "$binary 没有可执行位" >&2; exit 1; }

  case "$target" in
    *-linux-gnu) want='7f454c46' ;;   # \x7fELF
    *) want='cffaedfe' ;;             # Mach-O 64 little-endian
  esac
  magic=$(od -An -tx1 -N4 "$binary" | tr -d ' \n')
  [ "$magic" = "$want" ] || { echo "$binary 的格式不符合 ${target}（magic=${magic}）" >&2; exit 1; }

  report="${target}: sha256 ok, 布局 ok, magic ${magic}"
  if [ "$target" = "$host_target" ]; then
    printed=$("$binary" --version)
    [ "$printed" = "sshpool $version" ] || { echo "$target 报告的版本是「${printed}」，不是 sshpool $version" >&2; exit 1; }
    report="$report, 本机运行 $printed"
  fi
  echo "  $report"
done

echo "release assets: ok ($tag)"
