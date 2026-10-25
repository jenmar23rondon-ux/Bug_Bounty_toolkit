#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${IDOR_LAB_PORT:-8099}"
cd "$repo_root"
python -m bugbounty_toolkit.idor_lab_server --host 127.0.0.1 --port "$port" &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
wait "$server_pid"
