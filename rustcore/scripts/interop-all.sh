#!/usr/bin/env bash
# Все живые интероп-прогоны NeXX против публичных релеев SimpleX одной командой.
# Для внешнего аудита: каждый шаг печатает OK/FAIL, итог — ALL INTEROP OK или нет.
# Требуется: NEXX_TLS=openssl (Ed448 в sigalgs), CA-цепочка smp6 (ниже в CA_PEM_FILE).
set -u
cd "$(dirname "$0")/.."

HOST=${1:-smp6.simplex.im:5223}
# CA-цепочка живёт в репозитории (assets/), НЕ в scratch — scratch чистится через 24 ч
# и сборка/прогон молча падает (ловушка: include_str! / CA_PEM_FILE из scratch).
CA=${CA_PEM_FILE:-"$(cd "$(dirname "$0")/.." && pwd)/assets/smp6-5223-chain.pem"}
BIN=${CARGO_TARGET_DIR:-/home/thomas/build/cache/cargo-target}/release
export NEXX_TLS=openssl

echo "== build =="
cargo build --release --bin chat_flow --bin agent_smoke --bin agent_rotate --bin smp_cmds --bin invite_flow --bin xftp_chunk --bin xftp_smoke --bin contact_link_smoke --bin xftp_file_smoke --bin xftp_big_smoke --bin agent_rotate_lib_smoke --bin group_smoke || exit 1

run() {
  local name=$1; shift
  echo "== $name =="
  if timeout 180 "$BIN/$name" "$@" 2>&1 | grep -aE "OK|FAIL|panic" | tail -8; then :; fi
}

run chat_flow "$HOST" | grep -q "CHAT UI FLOW OK" && echo "PASS chat_flow" || echo "FAIL chat_flow"
run agent_smoke "$HOST" "$CA" | grep -q "AGENT INTEROP OK" && echo "PASS agent_smoke" || echo "FAIL agent_smoke"
run agent_rotate "$HOST" "$CA" | grep -q "ROTATE INTEROP OK" && echo "PASS agent_rotate" || echo "FAIL agent_rotate"
run smp_cmds "$HOST" "$CA" | grep -q "SMP CMDS INTEROP OK" && echo "PASS smp_cmds" || echo "FAIL smp_cmds"
run invite_flow "$HOST" | grep -q "INVITE FLOW OK" && echo "PASS invite_flow" || echo "FAIL invite_flow"
# XFTP — отдельный релей (порт 443, ALPN xftp/1, без SNI)
XFTP_HOST=${XFTP_HOST:-xftp1.simplex.im:443}
XFTP_H=${XFTP_HOST%%:*}; XFTP_P=${XFTP_HOST##*:}
run xftp_smoke "$XFTP_H" "$XFTP_P" | grep -q "XFTP INTEROP OK" && echo "PASS xftp_smoke" || echo "FAIL xftp_smoke"
run xftp_chunk | grep -q "XFTP CHUNKED INTEROP OK" && echo "PASS xftp_chunk" || echo "FAIL xftp_chunk"
run contact_link_smoke "${HOST%%:*}:5223" | grep -q "CONTACT LINK SMOKE OK" && echo "PASS contact_link_smoke" || echo "FAIL contact_link_smoke"
run xftp_file_smoke "$XFTP_H" "$XFTP_P" | grep -q "XFTP FILE SMOKE OK" && echo "PASS xftp_file_smoke" || echo "FAIL xftp_file_smoke"
echo "== xftp_big_smoke =="
timeout 420 "$BIN/xftp_big_smoke" "$XFTP_H" "$XFTP_P" 2>&1 | grep -aE "OK|FAIL|panic" | tail -4 | tee /tmp/nexx_big_smoke.out
grep -q "XFTP BIG" /tmp/nexx_big_smoke.out && echo "PASS xftp_big_smoke" || echo "FAIL xftp_big_smoke"
run agent_rotate_lib_smoke "${HOST%%:*}:5223" | grep -q "ROTATE LIB SMOKE OK" && echo "PASS agent_rotate_lib_smoke" || echo "FAIL agent_rotate_lib_smoke"
run group_smoke "${HOST%%:*}:5223" | grep -q "GROUP" && echo "PASS group_smoke" || echo "FAIL group_smoke"

echo "== unit tests =="
cargo test --release --lib 2>&1 | grep -E "test result: ok" && echo "PASS unit" || echo "FAIL unit"
