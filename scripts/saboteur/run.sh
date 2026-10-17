#!/usr/bin/env bash
# Saboteur: útoky na vstupy cdctl (argumenty, soubory, konfigurace, zlý server).
# Každý útok má očekávaný výsledek; navíc se hlídá pád (panic), časový limit a paměť.
#
#   scripts/saboteur/run.sh [cesta/k/cdctl]      (výchozí target/debug/cdctl)
#
# Exit 0 = všechny útoky odraženy.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(realpath "${1:-target/debug/cdctl}")"
WORK="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
EVIL=18901; MAX_RSS_KB=300000; FAILS=0; TOTAL=0

python3 "$HERE/evil_server.py" $EVIL "$WORK" >/dev/null 2>&1 &
python3 "$HERE/evil_server.py" 18902 "$WORK" >/dev/null 2>&1 &
mode() { echo "$1" > "$WORK/mode"; }
mode "probe-$$"
for _ in $(seq 50); do [ "$(curl -s "http://127.0.0.1:$EVIL/__mode")" = "probe-$$" ] && break; sleep 0.1; done
[ "$(curl -s "http://127.0.0.1:$EVIL/__mode")" = "probe-$$" ] || { echo "port $EVIL is busy (another server running?)"; exit 1; }

# attack <id> <očekávaný exit> <timeout s> <args...>   (CFG=… volitelně konfigurační soubor)
attack() {
  local id=$1 want=$2 to=$3; shift 3
  local d="$WORK/$id"; mkdir -p "$d/logs"
  env -i PATH="$PATH" HOME="$d/home" CDCTL_CONFIG="${CFG:-$WORK/empty.toml}" CDCTL_LOG_DIR="$d/logs" \
      CDWS_URL="http://127.0.0.1:$EVIL" CD_NODE_HOST=n CD_USER=u CD_PASSWORD=pw-SECRET \
      python3 "$HERE/memrun.py" "$d/rss" "$to" "$BIN" "$@" > "$d/stdout" 2> "$d/stderr" < /dev/null
  local code; code=$(tail -n1 "$d/stdout"); local rss; rss=$(cat "$d/rss")
  LAST="$d"; TOTAL=$((TOTAL+1))
  local why=""
  [ "$code" = "$want" ] || why="exit $code (want $want)"
  grep -q "panicked" "$d/stderr" && why="$why panic"
  [ "$rss" -lt $MAX_RSS_KB ] || why="$why rss ${rss}KB"
  if [ -n "$why" ]; then FAILS=$((FAILS+1)); printf "FAIL %-28s %s\n     %s\n" "$id" "$why" "$(head -c 300 "$d/stderr")"
  else printf "ok   %-28s exit=%s rss=%sKB\n" "$id" "$code" "$rss"; fi
}
# check <popis> <příkaz…> – dodatečná kontrola posledního útoku
check() {
  local desc=$1; shift
  if ! "$@"; then FAILS=$((FAILS+1)); echo "FAIL   ↳ $desc"; fi
}
no_raw_escapes() { ! grep -rqa -e $'\x1b' -e $'\xe2\x80\xae' "$LAST/stderr" "$LAST/logs"; }
no_forged_lines() { ! grep -rq '^2026-01-01' "$LAST/logs" "$LAST/stderr"; }
attacker_got_nothing() { [ ! -s "$WORK/requests-18902.log" ]; }

: > "$WORK/empty.toml"; mode ok
DRY=--dry-run

echo "== process injection =="
attack newline_in_path        1 10 send --snode N --from $'/a\n) PEND' --to /b $DRY
attack sysopts_breakout       1 10 send --snode N --from /a --to /b --from-sysopts 'x ) TO ( FILE=/etc/shadow PNODE ) PEND' $DRY
attack ctrl_chars_in_path     1 10 send --snode N --from $'/a\x01\x1b[31mb' --to /b $DRY
check "no raw escapes" no_raw_escapes
attack bidi_in_path           1 10 send --snode N --from $'/a\xe2\x80\xaeb' --to /b $DRY
attack unicode_name           1 10 send --snode N --from /a --to /b --name 'ŽLUŤ' $DRY
attack quoted_trailing_bslash 1 10 send --snode N --from 'C:\a b\' --to /b $DRY
attack huge_path              1 10 send --snode N --from "/$(head -c 100000 /dev/zero | tr '\0' a)" --to /b $DRY
attack valid_quoted_path      0 10 send --snode N --from "/a b/c'd(1).txt" --to /b $DRY

echo "== resource exhaustion =="
attack submit_dev_zero        1 20 submit --file /dev/zero
attack config_dev_zero        1 20 --config /dev/zero config
attack ca_cert_dev_zero       1 20 --ca-cert /dev/zero version
attack submit_directory       1 10 submit --file /
printf '\xff\xfe' > "$WORK/bad.cdp"
attack submit_binary          1 10 submit --file "$WORK/bad.cdp"

echo "== config abuse =="
cfg() { printf "$1" > "$WORK/c.toml"; echo "$WORK/c.toml"; }
CFG=$(cfg '[log]\nfile = "../../escaped.log"\n') attack log_file_traversal 1 10 config
check "nothing escaped the log dir" test ! -e "$WORK/escaped.log"
CFG=$(cfg '[log]\nfile = "/"\n')            attack log_file_root        1 10 config
CFG=$(cfg '[log]\nfile = ""\n')             attack log_file_empty       1 10 config
CFG=$(cfg '[connection]\ntimeout_secs = 0\n') attack timeout_zero       1 10 version
CFG=$(cfg '[connection]\nnode_port = 0\n')  attack port_zero            1 10 config
CFG=$(cfg '[log]\nlevle = "x"\n')           attack unknown_key          1 10 config
attack log_level_empty        1 10 --log-level '' config
attack timeout_flag_zero      2 10 --timeout 0 config

echo "== CLI argument abuse =="
attack raw_traversal          1 10 raw GET ../../../etc/passwd
attack raw_pct_traversal      1 10 raw GET '%2e%2e/%2e%2e/admin'
attack raw_query_inject       1 10 raw GET 'version?admin=true'
attack raw_bad_method         1 10 raw 'GET X' version
attack raw_deep_json          1 10 raw POST version --json "$(head -c 100000 /dev/zero | tr '\0' '[')"
attack non_utf8_arg           2 10 --url $'\xff\xfe' version
check "server never saw traversal" bash -c "! grep -q -e '/etc/passwd' -e '/admin' '$WORK/requests-$EVIL.log' 2>/dev/null"
mode big_json
env -i PATH="$PATH" CDCTL_CONFIG="$WORK/empty.toml" CDCTL_LOG_DIR="$WORK/pipe" CDWS_URL="http://127.0.0.1:$EVIL" \
    CD_NODE_HOST=n CD_USER=u CD_PASSWORD=x "$BIN" stats 2> "$WORK/pipe.err" | head -c1 > /dev/null
TOTAL=$((TOTAL+1)); if grep -q panicked "$WORK/pipe.err"; then FAILS=$((FAILS+1)); echo "FAIL broken_pipe"; else echo "ok   broken_pipe"; fi
mode ok

echo "== malicious server =="
: > "$WORK/requests-18902.log"
mode redirect_signon;  attack redirect_signon   1 10 version
check "attacker received nothing" attacker_got_nothing
mode redirect_call;    attack redirect_call     1 10 version
check "attacker received nothing" attacker_got_nothing
mode huge_header;      attack huge_auth_header  1 10 version
mode log_injection;    attack log_injection     1 10 --log-stderr version
check "no forged log lines" no_forged_lines
check "no raw escapes" no_raw_escapes
mode huge_body;        attack huge_body_300MB   1 60 version
mode slow;  CFG=$(cfg '[connection]\ntimeout_secs = 2\n') attack slow_server 1 20 version
mode deep_json;        attack deep_json         0 10 version
mode bad_utf8;         attack bad_utf8          0 10 version
mode weird_pnum;       attack weird_pnum_ccode  2 20 submit --server-file /x --wait
check "no raw escapes" no_raw_escapes
mode ok

echo; echo "$((TOTAL-FAILS))/$TOTAL attacks repelled"
[ $FAILS -eq 0 ]
