#!/usr/bin/env bash
# Все живые интероп-прогоны NeXX против публичных релеев SimpleX одной командой.
# Для внешнего аудита: каждый шаг печатает OK/FAIL, итог — ALL INTEROP OK или нет.
# Требуется: NEXX_TLS=openssl (Ed448 в sigalgs), CA-цепочка smp6 (ниже в CA_PEM_FILE).
set -u
cd "$(dirname "$0")/.."

HOST=${1:-smp6.simplex.im:5223}
CA=${CA_PEM_FILE:-/home/thomas/.hermes/cache/scratch/smp6-5223-chain.pem}
BIN=${CARGO_TARGET_DIR:-/home/thomas/build/cache/cargo-target}/release
export NEXX_TLS=openssl

echo "== build =="
cargo build --release --bin chat_flow --bin agent_smoke --bin agent_rotate --bin smp_cmds --bin invite_flow || exit 1

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

echo "== unit tests =="
cargo test --release --lib 2>&1 | grep -E "test result: ok" && echo "PASS unit" || echo "FAIL unit"
