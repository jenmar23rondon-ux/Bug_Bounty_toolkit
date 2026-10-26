#!/usr/bin/env bash
# Run one bbtk command inside the hardened, network-less offline lab container.
#   scripts/offline_lab/run.sh lab idor
#   scripts/offline_lab/run.sh doctor
#   BBTK_LAB_PROFILE=playwright scripts/offline_lab/run.sh doctor
# No host directory is mounted: results stay inside the container and are
# printed to stdout. The image must already exist (see build.sh).
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=common.sh
source "$repo_root/scripts/offline_lab/common.sh"
image="$BBTK_LAB_IMAGE" memory="$BBTK_LAB_MEMORY" shm=()
if [[ "${BBTK_LAB_PROFILE:-}" == "playwright" ]]; then
  image="$BBTK_LAB_PW_IMAGE" memory="$BBTK_LAB_PW_MEMORY" shm=(--shm-size 256m)
fi
bbtk_lab_require_image "$image" "$([[ $image == "$BBTK_LAB_PW_IMAGE" ]] && echo --playwright)"
mapfile -t flags < <(bbtk_lab_run_flags "$memory")
exec "$DOCKER" run "${flags[@]}" "${shm[@]}" --entrypoint timeout "$image" \
  --signal=KILL "$BBTK_LAB_TIMEOUT" /usr/local/bin/bbtk "$@"
