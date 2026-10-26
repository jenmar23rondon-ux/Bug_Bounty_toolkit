#!/usr/bin/env bash
set -euo pipefail
PORT="${CONTEXT_FUZZ_LAB_PORT:-8191}"
exec python -m bugbounty_toolkit.context_fuzz_lab_server --host 127.0.0.1 --port "$PORT"
