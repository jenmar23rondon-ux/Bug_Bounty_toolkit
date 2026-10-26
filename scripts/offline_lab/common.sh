#!/usr/bin/env bash
# Shared settings for the bbtk offline lab scripts. Source, do not execute.
# The hardened run profile lives here only, so build/verify/run cannot drift.

BBTK_LAB_IMAGE="${BBTK_LAB_IMAGE:-bbtk-offline-lab:local}"
BBTK_LAB_PW_IMAGE="${BBTK_LAB_PW_IMAGE:-bbtk-offline-lab-playwright:local}"
BBTK_LAB_MEMORY="${BBTK_LAB_MEMORY:-768m}"
BBTK_LAB_PW_MEMORY="${BBTK_LAB_PW_MEMORY:-1536m}"
BBTK_LAB_CPUS="${BBTK_LAB_CPUS:-1.0}"
BBTK_LAB_PIDS="${BBTK_LAB_PIDS:-256}"
BBTK_LAB_TIMEOUT="${BBTK_LAB_TIMEOUT:-600}"
BBTK_LAB_UID=10001
DOCKER="${DOCKER:-docker}"

# bbtk_lab_run_flags <memory>: prints the hardened `docker run` flags one per line.
#   --network none            no interface except loopback; labs only use 127.0.0.1
#   --read-only               immutable root filesystem
#   --tmpfs ...               the only writable paths, owned by the lab user, nosuid/nodev
#   --user / --cap-drop ALL / no-new-privileges: unprivileged, cannot regain privileges
#   --memory = --memory-swap  hard memory cap with no swap
#   --pids-limit / --cpus     process and CPU caps; wall clock is capped by `timeout`
#   --pull never              the run step never downloads an image
# Never added: --privileged, -v/--mount of host paths, docker.sock, --env-file, host network.
bbtk_lab_run_flags() {
  local memory="$1" tmpfs_opts="rw,nosuid,nodev,uid=${BBTK_LAB_UID},gid=${BBTK_LAB_UID},mode=0700"
  printf '%s\n' \
    --rm --pull never \
    --network none \
    --read-only \
    --tmpfs "/tmp:${tmpfs_opts},size=256m" \
    --tmpfs "/opt/bbtk/.test-tmp:${tmpfs_opts},size=128m" \
    --tmpfs "/opt/bbtk/registros:${tmpfs_opts},size=32m" \
    --user "${BBTK_LAB_UID}:${BBTK_LAB_UID}" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory "$memory" --memory-swap "$memory" \
    --cpus "$BBTK_LAB_CPUS" \
    --pids-limit "$BBTK_LAB_PIDS" \
    --stop-timeout 10
}

bbtk_lab_require_image() {
  if ! "$DOCKER" image inspect "$1" >/dev/null 2>&1; then
    echo "[x] Image $1 not found. Build it first (network is allowed only at build time):" >&2
    echo "    scripts/offline_lab/build.sh${2:+ $2}" >&2
    exit 2
  fi
}
