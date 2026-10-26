#!/usr/bin/env bash
# Build the bbtk offline lab image(s). This is the ONLY step that uses the network
# (pinned base image, hash-locked wheels, checksum-verified ffuf, pinned Chromium).
#   scripts/offline_lab/build.sh               # core lab image (bbtk + ffuf)
#   scripts/offline_lab/build.sh --playwright  # also the optional Playwright image
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=common.sh
source "$repo_root/scripts/offline_lab/common.sh"
cd "$repo_root"

build_target() {
  local target="$1" tag="$2" started
  started=$(date +%s)
  DOCKER_BUILDKIT=1 "$DOCKER" build -f docker/offline-lab/Dockerfile --target "$target" -t "$tag" .
  echo "[+] Built $tag (target $target) in $(( $(date +%s) - started ))s;" \
       "size $("$DOCKER" image inspect "$tag" --format '{{.Size}}') bytes"
}

build_target lab "$BBTK_LAB_IMAGE"
if [[ "${1:-}" == "--playwright" ]]; then
  build_target lab-playwright "$BBTK_LAB_PW_IMAGE"
fi
