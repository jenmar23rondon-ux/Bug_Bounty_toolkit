# syntax=docker/dockerfile:1
# bbtk reproducible offline lab environment.
#
# BUILD (network allowed, separate step):  scripts/offline_lab/build.sh
# RUN   (network disabled, hardened):      scripts/offline_lab/verify.sh
#
# Everything the synthetic labs need is resolved here, at build time. Nothing is
# downloaded when a lab runs: the run step uses --network none.
#
# Targets:
#   lab             bbtk + PyYAML + ffuf (default, minimal)
#   lab-playwright  lab + pinned Playwright library + its matching Chromium build

# Official Python image, pinned by multi-arch manifest digest (python:3.12-slim-bookworm).
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

# ---------------------------------------------------------------- build stage
FROM ${PYTHON_IMAGE} AS build
ARG TARGETARCH
# ffuf 2.1.0 official release; SHA-256 values copied from ffuf_2.1.0_checksums.txt.
ARG FFUF_VERSION=2.1.0
ARG FFUF_SHA256_AMD64=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
ARG FFUF_SHA256_ARM64=6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN python - <<'PY'
import hashlib, os, tarfile, urllib.request
arch = os.environ.get("TARGETARCH") or "amd64"
sums = {"amd64": os.environ["FFUF_SHA256_AMD64"], "arm64": os.environ["FFUF_SHA256_ARM64"]}
if arch not in sums:
    raise SystemExit(f"unsupported TARGETARCH {arch!r}; ffuf checksum not pinned")
version = os.environ["FFUF_VERSION"]
url = f"https://github.com/ffuf/ffuf/releases/download/v{version}/ffuf_{version}_linux_{arch}.tar.gz"
data = urllib.request.urlopen(url, timeout=60).read()
digest = hashlib.sha256(data).hexdigest()
if digest != sums[arch]:
    raise SystemExit(f"ffuf checksum mismatch: {digest} != {sums[arch]}")
path = "/tmp/ffuf.tgz"
open(path, "wb").write(data)
with tarfile.open(path) as archive:
    member = archive.getmember("ffuf")
    archive.extractall("/opt/ffuf", members=[member], filter="data")
os.chmod("/opt/ffuf/ffuf", 0o755)
print("ffuf", version, arch, "sha256 verified", digest)
PY

COPY docker/offline-lab/requirements-core.lock docker/offline-lab/requirements-playwright.lock /tmp/locks/
# Hash-locked, wheel-only installs: pip refuses any artifact whose digest is not in the lock.
# Permissions are fixed here, before COPY, so later layers do not duplicate the files.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/locks/requirements-core.lock \
 && chmod -R go-w /opt/venv

# ---------------------------------------------------------- playwright build
FROM build AS build-playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/locks/requirements-playwright.lock \
 && /opt/venv/bin/python -m playwright install chromium \
 && chmod -R go-w /opt/ms-playwright /opt/venv

# ------------------------------------------------------------- runtime: lab
FROM ${PYTHON_IMAGE} AS lab
LABEL org.opencontainers.image.title="bbtk-offline-lab" \
      org.opencontainers.image.description="Reproducible offline lab environment for bbtk synthetic labs" \
      org.opencontainers.image.source="https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit" \
      org.opencontainers.image.licenses="MIT"
# Fixed, unprivileged identity. No sudo, no setuid helpers are added.
RUN groupadd --system --gid 10001 bbtk \
 && useradd --system --uid 10001 --gid 10001 --home-dir /tmp/bbtk-home --no-create-home --shell /usr/sbin/nologin bbtk
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/ffuf/ffuf /usr/local/bin/ffuf
# Only allowlisted source directories reach the image (see .dockerignore).
COPY --chown=root:root . /opt/bbtk
COPY --chown=root:root --chmod=0755 docker/offline-lab/bbtk-entry.sh /usr/local/bin/bbtk
# Source tree is root-owned and not writable by the lab user; .test-tmp is a mount point for a tmpfs.
RUN find /opt/bbtk -name '__pycache__' -prune -exec rm -rf {} + \
 && mkdir -p /opt/bbtk/.test-tmp /opt/bbtk/registros \
 && chmod -R go-w /opt/bbtk \
 && { find / -xdev -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null || true; }
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/opt/bbtk \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp/bbtk-home \
    TMPDIR=/tmp \
    BBTK_OFFLINE_LAB=1
WORKDIR /opt/bbtk
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/bbtk"]
CMD ["--version"]

# --------------------------------------------------- runtime: lab-playwright
FROM lab AS lab-playwright
USER root
COPY --from=build-playwright /opt/venv /opt/venv
COPY --from=build-playwright /opt/ms-playwright /opt/ms-playwright
# Chromium's runtime shared libraries from Debian (build step; the browser itself was pinned above).
RUN /opt/venv/bin/python -m playwright install-deps chromium \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb \
 && { find / -xdev -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null || true; }
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
USER 10001:10001
