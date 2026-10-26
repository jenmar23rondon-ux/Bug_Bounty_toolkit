# Reproducible Offline Lab Environment (optional)

An **optional** Docker image that runs bbtk's *synthetic* labs and test suite in a hardened,
network-less container. It adds no scanner, agent, distributed fuzzing or AI model. It is a
reproducible place to run what already exists.

The normal install path is unchanged and remains the default:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

Scope enforcement and human-approval gates are **unchanged**. The container does not relax or
bypass them; `scripts/offline_lab/isolation_checks.py` asserts that bbtk still refuses an
out-of-scope target inside the image.

## Build is separate from run

| Phase | Command | Network |
|---|---|---|
| Build (once) | `scripts/offline_lab/build.sh [--playwright]` | **Yes.** The only networked step. |
| Run | `scripts/offline_lab/run.sh <bbtk args>` | **None** (`--network none`) |
| Verify | `scripts/offline_lab/verify.sh [--playwright] [--quick]` | **None** |

Nothing is downloaded during a lab run: the run profile uses `--pull never`, the image sets
`PIP_NO_INDEX=1`, there is no network interface except loopback, and `doctor` only *reports*
missing tools and never installs them.

```bash
scripts/offline_lab/build.sh                  # core image  (bbtk-offline-lab:local)
scripts/offline_lab/build.sh --playwright     # also the optional browser image
scripts/offline_lab/run.sh --version
scripts/offline_lab/run.sh doctor
scripts/offline_lab/run.sh lab idor
scripts/offline_lab/run.sh lab web-vuln
scripts/offline_lab/verify.sh --playwright    # full evidence run -> offline-lab-results/
```

Use `sudo` for these scripts if your user is not in the `docker` group. Compose is also provided
(`docker/offline-lab/compose.yaml`). It contains no `build:` key, so `compose run` cannot trigger
a networked build implicitly:

```bash
docker compose -f docker/offline-lab/compose.yaml run --rm lab lab idor
docker compose -f docker/offline-lab/compose.yaml --profile playwright run --rm lab-playwright doctor
```

## What is in the image

- Base: `python:3.12-slim-bookworm`, **pinned by digest**.
- Python deps: hash-locked (`docker/offline-lab/requirements-*.lock`), installed with
  `--require-hashes --only-binary=:all: --no-deps`. Core is PyYAML only, the sole runtime
  dependency of the labs.
- `ffuf` 2.1.0 release binary, verified against its published SHA-256 (amd64/arm64).
- `bbtk` source at `/opt/bbtk` (the lab commands need the source tree, not just a wheel).
- Optional `lab-playwright` target: Playwright 1.64.1 plus Chromium (the full browser *and* the
  headless shell, the same set CI installs), so the repository's own browser tests run unmodified.
- `.dockerignore` is an **allowlist**. `.env`, keys, `.netrc`, databases and caches are never sent
  to the build context.

## Run-time isolation profile

Defined once in `scripts/offline_lab/common.sh` and mirrored in `compose.yaml`:

`--network none`, `--read-only`, tmpfs for `/tmp` (which holds `$HOME`), `/opt/bbtk/.test-tmp`
and `/opt/bbtk/registros` (uid 10001, mode 0700, `nosuid,nodev`; **not** `noexec`, since
Chromium and the test suite need to execute from temp), `--user 10001:10001`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--memory` = `--memory-swap` (no swap), `--cpus`, `--pids-limit`, wall-clock `timeout`,
`--pull never`, `--rm`. **No** `--privileged`, **no** docker.sock, **no** volumes or bind mounts.
Results leave the container only through stdout.

Limits (override with environment variables): memory 768m (1536m for Playwright), 1 CPU,
256 pids, 600 s (`BBTK_LAB_MEMORY`, `BBTK_LAB_PW_MEMORY`, `BBTK_LAB_CPUS`, `BBTK_LAB_PIDS`,
`BBTK_LAB_TIMEOUT`).

## Guarantees: verified vs not verified

`isolation_checks.py` reports each property as `pass`, `fail` or **`unverified`**. A property
is only claimed when it was measured inside the running container.

| Property | How it is checked | Status |
|---|---|---|
| Runs as non-root (uid 10001) | `os.getuid()` | verified |
| No capabilities | `CapEff`/`CapPrm`/`CapBnd` = 0 | verified |
| no-new-privileges | `NoNewPrivs: 1` | verified |
| No setuid/setgid binaries | filesystem walk | verified |
| Read-only root FS; only tmpfs writable | write attempts | verified |
| Host private paths absent (`~/.ssh`, `~/.aws`, docker.sock, …) | path probes | verified |
| No bind mounts | `/proc/self/mountinfo` | verified |
| No secret-like env vars, no secrets baked into the image | env + artifact scan | verified |
| Memory / CPU / pids limits | cgroup v2 files; pids limit **exercised** | verified |
| Only `lo` interface | `/sys/class/net` | verified |
| External connections fail | TCP to RFC 5737 TEST-NET (never routable) | verified |
| DNS resolution fails | `.invalid` lookup | verified |
| Lab-internal loopback works | synthetic local service | verified |
| ffuf works against a synthetic service | real ffuf run on loopback | verified |
| bbtk still refuses out-of-scope targets | `bbtk` scope gate | verified |
| Canary secret is not persisted | written-files scan | verified |
| Playwright renders local HTML; external navigation blocked | headless Chromium | verified (browser image) |
| seccomp filter active | `Seccomp:` in `/proc/self/status` | **depends on host runtime**: reported `unverified` if absent |
| AppArmor/SELinux confinement | not measured | **not claimed** |
| Kernel/container-escape resistance | not measurable from inside | **not claimed** |

### Connection auditing and its blind spot

A Python audit hook (`scripts/offline_lab/connect_audit/sitecustomize.py`) records every
non-loopback `socket.connect`/`getaddrinfo` attempt made by Python code. `verify.sh` fails any
step with a non-zero count. Deliberate TEST-NET probes from the isolation checks are counted
separately as `deliberate_probes`. **The hook cannot see non-Python processes** (ffuf,
Chromium). For those, the guarantee rests only on `--network none` (verified: only `lo`
exists, and external connects and DNS fail).

## Limitations and residual risks

- **Docker is not a security boundary against a hostile kernel exploit.** This profile reduces
  exposure, it does not make untrusted code safe. Run only the bundled synthetic labs.
- **Do not add `-v`/`--mount`.** Mounting host directories removes the "no host data" guarantee.
  The shipped profile contains none (asserted by `tests/test_offline_lab.py`), and the in-container
  `bind-mounts` check *detects* one if present, but nothing stops a user adding `-v` to
  `docker run` by hand.
- **seccomp/AppArmor depend on the host's Docker.** Rootless Docker, Docker Desktop (VM-backed on
  macOS/Windows) or a custom runtime may differ. Trust the `isolation-checks` output on *your*
  host, not this document.
- **Build-time trust:** the base image digest, Python wheels and ffuf are hash-pinned. The Debian
  packages installed by `playwright install-deps` are *not* version-pinned, and the Chromium
  download is verified by Playwright's own tooling, not by a hash in this repo.
- **Image size:** core about 152 MB; the Playwright image is about 1.3 GB because it carries the
  full Chromium alongside the headless shell, matching CI so browser tests actually run.
- **Excluded from the in-container unit suite** (each reason is printed by `run_suite.py`):
  CSRF tests (need the optional `bs4` extra, not in the minimal image), the ruff coverage test
  (needs `ruff`), and `test_regeneration_is_byte_identical`, which writes into the frozen
  ranking corpus and is blocked by the read-only FS (see below).
- **Known pre-existing test defect (not fixed here):**
  `tests/test_object_ranking_eval.py::test_regeneration_is_byte_identical` regenerates the frozen
  corpus *in place* (including its MANIFEST) and then compares it with itself, so it cannot detect
  drift. The read-only image exposed this. It should compare against a temp copy instead.

## Platform notes

- **Linux (Debian/Ubuntu/Kali):** supported. On Kali (rolling), the image is still Debian
  bookworm, which avoids the host-side `playwright install-deps` problems on rolling releases.
- **macOS / Windows:** Docker Desktop runs containers in a VM. The flags apply, but the
  seccomp/AppArmor results come from that VM. The scripts are bash; use WSL2 on Windows. The
  normal venv path remains the supported native option.
