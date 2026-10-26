#!/usr/bin/env bash
# Validate the bbtk offline lab inside hardened, network-less containers.
#   scripts/offline_lab/verify.sh                 # core image
#   scripts/offline_lab/verify.sh --playwright    # + optional Playwright profile
#   scripts/offline_lab/verify.sh --quick         # skip the full unit-test suite
# Prerequisite: scripts/offline_lab/build.sh [--playwright]. This script never
# builds or pulls. Each step runs in a fresh container with the run profile from
# common.sh plus an audit hook that records non-loopback connection attempts made
# by Python processes. Results are written to $BBTK_LAB_RESULTS (default
# ./offline-lab-results) on the host from container stdout; nothing is mounted.
set -uo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=common.sh
source "$repo_root/scripts/offline_lab/common.sh"

playwright=0 quick=0
for arg in "$@"; do
  case "$arg" in
    --playwright) playwright=1 ;;
    --quick) quick=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

results="${BBTK_LAB_RESULTS:-$repo_root/offline-lab-results}"
mkdir -p "$results"
summary="$results/summary.tsv"
printf 'step\timage\tstatus\texit\tseconds\texternal_attempts\tdeliberate_probes\tmemory_peak_bytes\n' > "$summary"

bbtk_lab_require_image "$BBTK_LAB_IMAGE"
((playwright)) && bbtk_lab_require_image "$BBTK_LAB_PW_IMAGE" --playwright

# Runs inside the container: enable the audit hook, run the step under a hard
# wall-clock limit, then report exit code, attempts and peak memory on stdout.
read -r -d '' wrapper <<'SH'
audit=/tmp/connect-audit.jsonl
: > "$audit"
export BBTK_CONNECT_AUDIT="$audit"
export PYTHONPATH="/opt/bbtk/scripts/offline_lab/connect_audit:/opt/bbtk"
timeout -s KILL "$BBTK_STEP_TIMEOUT" "$@"
rc=$?
# Deliberate isolation probes (RFC 5737 TEST-NET + a reserved .invalid name) are
# counted separately; every other non-loopback attempt is a real external attempt.
probe_re='"host": "(192\.0\.2\.1|198\.51\.100\.7|203\.0\.113\.9|bbtk-offline-probe\.invalid)"'
probes=$(grep -cE "$probe_re" "$audit")
attempts=$(grep -cvE "$probe_re" "$audit")
peak=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo unknown)
sed 's/^/@@BBTK-AUDIT /' "$audit"
echo "@@BBTK-METRICS rc=$rc attempts=$attempts probes=$probes peak=$peak"
exit "$rc"
SH

failures=0
step() {
  local name="$1" image="$2" memory="$3"; shift 3
  local log="$results/$name.log" started rc metrics attempts peak status extra=()
  [[ "$image" == "$BBTK_LAB_PW_IMAGE" ]] && extra=(--shm-size 256m)
  mapfile -t flags < <(bbtk_lab_run_flags "$memory")
  echo "==> $name"
  started=$(date +%s)
  "$DOCKER" run "${flags[@]}" "${extra[@]}" -e BBTK_STEP_TIMEOUT="$BBTK_LAB_TIMEOUT" \
    --entrypoint /bin/sh "$image" -c "$wrapper" sh "$@" > "$log" 2>&1
  rc=$?
  metrics=$(grep '^@@BBTK-METRICS' "$log" | tail -1)
  attempts=$(sed -n 's/.*attempts=\([0-9]*\).*/\1/p' <<<"$metrics")
  probes=$(sed -n 's/.*probes=\([0-9]*\).*/\1/p' <<<"$metrics")
  peak=$(sed -n 's/.*peak=\([0-9a-z]*\).*/\1/p' <<<"$metrics")
  status=PASS note=""
  if (( rc != 0 )) || [[ "${attempts:-1}" != "0" ]]; then status=FAIL; fi
  # A green exit code is not enough: a unittest step that ran nothing proves nothing.
  if grep -qE '^Ran 0 tests' "$log"; then status=FAIL note=" [ran 0 tests]"; fi
  if [[ " ${BBTK_NO_SKIP_STEPS:-} " == *" $name "* ]] && grep -qE "skipped '|\(skipped=" "$log"; then
    status=FAIL note=" [tests were skipped in a step that must run them]"
  fi
  [[ $status == FAIL ]] && failures=$((failures + 1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$image" "$status" "$rc" "$(( $(date +%s) - started ))" \
    "${attempts:-unknown}" "${probes:-0}" "${peak:-unknown}" >> "$summary"
  echo "    $status$note (exit $rc, external attempts ${attempts:-unknown}, deliberate probes ${probes:-0}," \
       "peak memory ${peak:-unknown} bytes)"
}

py=/opt/venv/bin/python
img="$BBTK_LAB_IMAGE" mem="$BBTK_LAB_MEMORY"
step version            "$img" "$mem" /usr/local/bin/bbtk --version
step doctor             "$img" "$mem" /usr/local/bin/bbtk doctor
step lab-idor           "$img" "$mem" /usr/local/bin/bbtk lab idor
step lab-web-vuln       "$img" "$mem" /usr/local/bin/bbtk lab web-vuln
step fuzz-plan-offline  "$img" "$mem" /bin/sh -c \
  "/usr/local/bin/bbtk fuzz-plan lab-context-fuzz --har examples/context-fuzz/capture.har --dry-run && \
   $py -m unittest discover -s tests -p 'test_context_fuzz*.py' && \
   $py -m unittest discover -s tests -p 'test_fuzzing.py'"
step ffuf-adapter-tests "$img" "$mem" "$py" -m unittest -v tests.test_workflow tests.test_fuzz_evidence_pipeline
step isolation-checks   "$img" "$mem" "$py" scripts/offline_lab/isolation_checks.py
((quick)) || step unit-suite "$img" "$mem" "$py" scripts/offline_lab/run_suite.py
if ((playwright)); then
  img="$BBTK_LAB_PW_IMAGE" mem="$BBTK_LAB_PW_MEMORY"
  BBTK_NO_SKIP_STEPS="pw-browser-tests"  # the browser profile must really launch Chromium
  step pw-doctor          "$img" "$mem" /usr/local/bin/bbtk doctor
  step pw-local-html      "$img" "$mem" "$py" scripts/offline_lab/isolation_checks.py --only playwright-local-html \
    --only external-connections-blocked --only network-interfaces --only non-root-user
  step pw-browser-tests   "$img" "$mem" "$py" -m unittest -v tests.test_xss_browser
fi

for image in "$BBTK_LAB_IMAGE" $( ((playwright)) && echo "$BBTK_LAB_PW_IMAGE"); do
  printf 'image\t%s\t%s bytes\n' "$image" "$("$DOCKER" image inspect "$image" --format '{{.Size}}')" >> "$results/images.tsv"
done
echo
column -t -s $'\t' "$summary" 2>/dev/null || cat "$summary"
echo "Results: $results"
if (( failures )); then echo "[x] $failures step(s) failed"; exit 1; fi
echo "[+] All offline lab steps passed with zero external connection attempts."
