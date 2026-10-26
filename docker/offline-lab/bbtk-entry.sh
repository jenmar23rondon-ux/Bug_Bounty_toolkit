#!/bin/sh
# bbtk entry point for the offline lab image: runs the source tree at /opt/bbtk.
mkdir -p "${HOME:-/tmp/bbtk-home}" 2>/dev/null || true
exec python -c 'import sys; from bugbounty_toolkit.cli import main; sys.argv[0] = "bbtk"; main()' "$@"
