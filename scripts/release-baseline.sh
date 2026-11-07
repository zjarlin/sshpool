#!/bin/sh
# 校验发布产物的平台基线：Linux 的 glibc 符号版本上限、macOS 的 minos。
#
#   scripts/release-baseline.sh <二进制> <目标三元组>
#
# 基线是承诺给用户的「最低系统版本」，比它新就等于骗人，因此用 exit 2 失败关闭。
set -eu
binary=${1:?用法: release-baseline.sh <二进制> <目标>}
target=${2:?用法: release-baseline.sh <二进制> <目标>}
case "${target}" in
  x86_64-unknown-linux-gnu) baseline=2.35 ;;
  aarch64-apple-darwin|x86_64-apple-darwin) baseline=11.0 ;;
  *) echo "未知目标的基线: ${target}" >&2; exit 2 ;;
esac

# BSD 与 GNU 的 sort 对 -V 支持不一致，统一用 awk 比数值段版本。
le() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, ".")
    for (i = 1; i <= na || i <= nb; i++) {
      p = (i <= na) ? x[i] + 0 : 0
      q = (i <= nb) ? y[i] + 0 : 0
      if (p < q) exit 0
      if (p > q) exit 1
    }
    exit 0
  }'
}

case "${target}" in
  *-linux-gnu)
    # 有 readelf 就用它；Mac 上也必须能查，所以退回到只读同一个 .gnu.version_r 的脚本。
    if command -v readelf >/dev/null 2>&1; then
      observed=$(readelf --dyn-syms --wide "$binary" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' \
        | awk -F. '{ key = $0; printf "%d %s\n", $1 * 1000 + $2, key }' | sort -n | tail -1 | cut -d' ' -f2)
    else
      command -v python3 >/dev/null 2>&1 || { echo "缺少 readelf 与 python3，无法读 glibc 基线" >&2; exit 2; }
      observed=$(python3 "$(dirname "$0")/glibc-symbol-version.py" "$binary") || exit 2
    fi
    kind=glibc
    ;;
  *-apple-darwin)
    command -v otool >/dev/null 2>&1 || { echo "缺少 otool（需要 macOS）" >&2; exit 2; }
    # arm64 写 LC_BUILD_VERSION/minos，老式 x86_64 目标仍只写 LC_VERSION_MIN_MACOSX/version。
    otool -l "$binary" >/dev/null 2>&1 || { echo "读不了 ${binary} 的 Mach-O 头" >&2; exit 2; }
    observed=$(otool -l "$binary" | awk '
      /LC_BUILD_VERSION/ { want = "minos"; next }
      /LC_VERSION_MIN_MACOSX/ { want = "version"; next }
      want == "minos" && $1 == "minos" { print $2; exit }
      want == "version" && $1 == "version" { print $2; exit }
    ')
    kind=macos
    ;;
esac

[ -n "${observed}" ] || { echo "无法读出 ${target} 的平台基线" >&2; exit 2; }
printf '%s: %s %s (baseline %s)\n' "${target}" "${kind}" "${observed}" "${baseline}"
le "$observed" "$baseline" || {
  echo "基线不成立：${kind} ${observed} 高于承诺的 ${baseline}" >&2
  exit 2
}
