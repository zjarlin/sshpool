#!/usr/bin/env bash
# 统一入口 vs 直连工作台：PTY / SFTP / scp / rsync / 本地端口转发 的行为一致性核验。
#
# 用法：
#   scripts/check-ssh-parity.sh <统一入口端口> <直连工作台端口> [主机] [用户]
#
# 默认 2222（sshpool 代理）对 2223（后端 OpenSSH），127.0.0.1 / $USER。
# 只写远端 /tmp 下的临时目录，结束时清理；不触碰业务目录。
# 输出 JSON，供 docs/evidence 引用；任何一项不一致即非零退出。
set -uo pipefail

entry_port="${1:-2222}"
direct_port="${2:-2223}"
host="${3:-127.0.0.1}"
user="${4:-$USER}"
identity="${SSHPOOL_PARITY_IDENTITY:-$HOME/.lima/_config/user}"
known_hosts="${SSHPOOL_PARITY_KNOWN_HOSTS:-$HOME/.sshpool/known_hosts}"
alias_name="${SSHPOOL_PARITY_HOSTKEY_ALIAS:-sshpool-linux}"

workdir="/tmp/sshpool-parity-$$"
opts=(-o BatchMode=yes -i "$identity" -o UserKnownHostsFile="$known_hosts"
      -o HostKeyAlias="$alias_name" -o StrictHostKeyChecking=yes)

fail=0
results=()
record() { # name port ok detail
  results+=("{\"check\":\"$1\",\"port\":$2,\"ok\":$3,\"detail\":\"$4\"}")
  [ "$3" = "true" ] || fail=1
}

remote() { ssh "${opts[@]}" -p "$1" "$user@$host" "$2" 2>/dev/null; }

# 准备同一份输入与远端目录。
local_src=$(mktemp -d)
printf 'sshpool parity %s\n' "$(date +%s)" > "$local_src/file.txt"
dd if=/dev/urandom of="$local_src/rand.bin" bs=1024 count=256 2>/dev/null
local_digest=$(shasum -a 256 "$local_src/rand.bin" | awk '{print $1}')
local_text=$(shasum -a 256 "$local_src/file.txt" | awk '{print $1}')

for port in "$entry_port" "$direct_port"; do
  remote "$port" "mkdir -p $workdir/$port" || { record prepare "$port" false "cannot create remote directory"; continue; }
done

for port in "$entry_port" "$direct_port"; do
  # PTY：必须拿到真正的 tty 且 stdin 是 tty。
  # 远端 shell 固化了中文 locale 但没装对应 locale 包，警告会污染 stdout；只取最后两行。
  pty=$(ssh "${opts[@]}" -tt -p "$port" "$user@$host" 'tty; test -t 0 && echo stdin-tty' 2>/dev/null \
    | tr -d '\r' | grep -Ev 'setlocale|warning:' | tail -2 | tr -d '\n')
  if printf '%s' "$pty" | grep -q '/dev/pts/[0-9]' && printf '%s' "$pty" | grep -q 'stdin-tty'; then
    record pty "$port" true "$pty"
  else
    record pty "$port" false "${pty:-no tty}"
  fi

  # scp：二进制内容摘要必须与本地一致。
  scp "${opts[@]}" -P "$port" "$local_src/rand.bin" "$user@$host:$workdir/$port/scp.bin" 2>/dev/null
  got=$(remote "$port" "shasum -a 256 $workdir/$port/scp.bin 2>/dev/null | awk '{print \$1}'")
  if [ -n "$got" ] && [ "$got" = "$local_digest" ]; then
    record scp "$port" true "sha256=$got"
  else
    record scp "$port" false "expected=$local_digest got=${got:-none}"
  fi

  # sftp：批量模式上传后校验摘要。
  printf 'put %s %s/sftp.txt\n' "$local_src/file.txt" "$workdir/$port" \
    | sftp -b - "${opts[@]}" -P "$port" "$user@$host" >/dev/null 2>&1
  got=$(remote "$port" "[ -f $workdir/$port/sftp.txt ] && echo present")
  [ "$got" = "present" ] && record sftp "$port" true "sftp.txt uploaded" \
    || record sftp "$port" false "sftp.txt missing"

  # rsync：目录同步后两端内容必须一致。
  if command -v rsync >/dev/null; then
    rsync -a -e "ssh ${opts[*]} -p $port" "$local_src/" "$user@$host:$workdir/$port/rsync/" 2>/dev/null
    got=$(remote "$port" "shasum -a 256 $workdir/$port/rsync/rand.bin 2>/dev/null | awk '{print \$1}'")
    [ -n "$got" ] && [ "$got" = "$local_digest" ] && record rsync "$port" true "sha256=$got" \
      || record rsync "$port" false "expected=$local_digest got=${got:-none}"
  fi

  # 本地端口转发：在远端起回环 HTTP 服务，再从本机经隧道取一次内容。
  rport=$((18080 + port % 1000))
  ready=$(remote "$port" "cd $workdir/$port && (nohup python3 -m http.server $rport --bind 127.0.0.1 >http.log 2>&1 &) ; sleep 1; curl -sf -o /dev/null http://127.0.0.1:$rport/ && echo up")
  if [ "$ready" = "up" ]; then
    lport=$((18000 + port % 1000))
    ssh "${opts[@]}" -N -o ExitOnForwardFailure=yes -L "127.0.0.1:$lport:127.0.0.1:$rport" -p "$port" "$user@$host" >/dev/null 2>&1 &
    tunnel=$!
    sleep 2
    body=$(curl -sf --noproxy '*' --max-time 10 "http://127.0.0.1:$lport/" 2>/dev/null | tr -d '\n')
    kill "$tunnel" 2>/dev/null; wait "$tunnel" 2>/dev/null
    # 内容也要一致：转发不能只建立连接而丢字节。
    [ -n "$body" ] && record forward "$port" true "local $lport -> remote $rport, $(printf '%s' "$body" | wc -c | tr -d ' ') bytes" \
      || record forward "$port" false "forwarded response was empty"
  else
    record forward "$port" false "cannot start the loopback HTTP server"
  fi
done

# 主机公钥：两个入口必须是同一把，否则中间有人代理或改写握手。
key_of() { ssh-keyscan -p "$1" -t ed25519 "$host" 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'; }
entry_key=$(key_of "$entry_port")
direct_key=$(key_of "$direct_port")
if [ -n "$entry_key" ] && [ "$entry_key" = "$direct_key" ]; then
  record host_key 0 true "$entry_key"
else
  record host_key 0 false "entry=${entry_key:-none} direct=${direct_key:-none}"
fi

# 清理：只删本次创建的临时目录与本机临时输入。
for port in "$entry_port" "$direct_port"; do
  rport=$((18080 + port % 1000))
  remote "$port" "pkill -f 'http.server $rport' >/dev/null 2>&1; rm -rf $workdir/$port" >/dev/null 2>&1
done
rm -rf "$local_src"

printf '{"entry_port":%s,"direct_port":%s,"host":"%s","checks":[%s],"passed":%s}\n' \
  "$entry_port" "$direct_port" "$host" "$(IFS=,; echo "${results[*]}")" \
  "$([ $fail -eq 0 ] && echo true || echo false)"
exit "$fail"
