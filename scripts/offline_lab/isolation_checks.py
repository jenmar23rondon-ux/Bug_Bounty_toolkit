"""In-container isolation and functional checks for the bbtk offline lab.

Run inside the hardened container by ``scripts/offline_lab/verify.sh``. Uses the
standard library only. Every check reports ``pass``, ``fail`` or ``unverified``.
``unverified`` means the runtime could not prove the property; it is never
counted as a pass. Network probes only target loopback and RFC 5737
documentation addresses (TEST-NET), never public domains.
"""

from __future__ import annotations

import argparse
import errno
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

# RFC 5737 documentation ranges: reserved, never routed on the public Internet.
TEST_NET_PROBES = (("192.0.2.1", 80), ("198.51.100.7", 443), ("203.0.113.9", 53))
CANARY = "bbtk-canary-" + "7f3e1d9c4b2a"  # synthetic, never a real credential
SECRET_ENV_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY", "CREDENTIAL")
SECRET_ENV_PREFIXES = ("AWS_", "GH_", "GITHUB_", "GOOGLE_", "AZURE_", "OPENAI_", "ANTHROPIC_", "SSH_")
HOST_PRIVATE_PATHS = ("/root/.ssh", "/home", "/var/run/docker.sock", "/run/docker.sock", "/etc/shadow")

Result = dict[str, object]
REPO = Path(os.environ.get("BBTK_REPO", "/opt/bbtk"))


def result(name: str, status: str, detail: str, **extra: object) -> Result:
    return {"name": name, "status": status, "detail": detail, **extra}


def proc_status_field(field: str) -> str | None:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


# ------------------------------------------------------------------ identity
def check_non_root() -> Result:
    uid, gid = os.geteuid(), os.getegid()
    ok = uid != 0 and gid != 0
    return result("non-root-user", "pass" if ok else "fail", f"euid={uid} egid={gid}")


def check_capabilities() -> Result:
    effective = proc_status_field("CapEff")
    bounding = proc_status_field("CapBnd")
    if effective is None:
        return result("capabilities-dropped", "unverified", "/proc/self/status unreadable")
    ok = int(effective, 16) == 0 and int(bounding or "0", 16) == 0
    return result("capabilities-dropped", "pass" if ok else "fail", f"CapEff={effective} CapBnd={bounding}")


def check_no_new_privileges() -> Result:
    value = proc_status_field("NoNewPrivs")
    if value is None:
        return result("no-new-privileges", "unverified", "NoNewPrivs not reported by kernel")
    return result("no-new-privileges", "pass" if value == "1" else "fail", f"NoNewPrivs={value}")


def check_seccomp() -> Result:
    value = proc_status_field("Seccomp")
    if value is None:
        return result("seccomp-filter", "unverified", "kernel does not report Seccomp")
    if value == "2":
        return result("seccomp-filter", "pass", "Seccomp=2 (filter mode active)")
    # Not a failure of bbtk, but the guarantee is NOT provided by this runtime.
    return result("seccomp-filter", "unverified", f"Seccomp={value}; the container runtime applied no seccomp filter")


def check_setuid_binaries() -> Result:
    found: list[str] = []
    for root in ("/usr", "/bin", "/sbin", "/opt"):
        for path in Path(root).rglob("*") if Path(root).is_dir() else []:
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o4000:
                    found.append(str(path))
            except OSError:
                continue
    return result("no-setuid-binaries", "fail" if found else "pass", ", ".join(found[:10]) or "none found")


# --------------------------------------------------------------- filesystem
def _write_probe(directory: Path) -> int | None:
    """Return None when writable, otherwise the errno that refused the write."""
    try:
        fd, name = tempfile.mkstemp(dir=directory)
    except OSError as exc:
        return exc.errno or -1
    os.close(fd)
    os.unlink(name)
    return None


def check_read_only_rootfs() -> Result:
    refused: dict[str, str] = {}
    writable: list[str] = []
    for target in ("/", "/usr", "/etc", "/opt/venv", str(REPO), str(REPO / "bugbounty_toolkit")):
        code = _write_probe(Path(target))
        if code is None:
            writable.append(target)
        else:
            refused[target] = errno.errorcode.get(code, str(code))
    erofs = all(code == "EROFS" for code in refused.values())
    status = "pass" if not writable else "fail"
    detail = f"refused={refused}" + ("" if erofs else " (some refusals are permission-based, not EROFS)")
    if writable:
        detail = f"writable={writable}"
    return result("read-only-root-filesystem", status, detail, kernel_read_only=erofs and not writable)


def check_explicit_temp_dirs() -> Result:
    targets = [Path("/tmp"), REPO / ".test-tmp", REPO / "registros"]
    writable = {str(path): _write_probe(path) is None for path in targets}
    ok = all(writable.values())
    return result("explicit-writable-temp-dirs", "pass" if ok else "fail", json.dumps(writable))


def _accessible(path: Path) -> bool:
    """True only when the lab user can actually reach the path (a root-only parent counts as absent)."""
    try:
        return path.exists() and os.access(path, os.R_OK)
    except OSError:
        return False


def check_no_host_private_paths() -> Result:
    present: list[str] = []
    for raw in HOST_PRIVATE_PATHS:
        path = Path(raw)
        if raw == "/home":
            if path.is_dir() and any(path.iterdir()):
                present.append(raw)
            continue
        if raw == "/etc/shadow":
            try:
                path.read_bytes()
                present.append(raw + " (readable)")
            except OSError:
                pass
            continue
        if _accessible(path):
            present.append(raw)
    home = Path(os.environ.get("HOME", "/tmp/bbtk-home"))
    for name in (".ssh", ".aws", ".config/gh", ".docker", ".netrc", ".git-credentials", ".kube"):
        if _accessible(home / name):
            present.append(str(home / name))
    return result("no-host-credentials-or-sockets", "fail" if present else "pass", ", ".join(present) or "none present")


def check_no_host_bind_mounts() -> Result:
    suspicious: list[str] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return result("no-host-bind-mounts", "unverified", "/proc/self/mountinfo unreadable")
    allowed = {"/", "/proc", "/dev", "/sys", "/tmp", str(REPO / ".test-tmp"), str(REPO / "registros")}
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        mount_point = parts[4]
        fs_type = parts[parts.index("-") + 1] if "-" in parts else ""
        if fs_type in {"proc", "sysfs", "tmpfs", "devpts", "mqueue", "cgroup", "cgroup2", "overlay", "shm"}:
            continue
        if mount_point in {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}:
            continue  # runtime-managed files, not host directories
        if mount_point in allowed or mount_point.startswith(("/proc/", "/sys/", "/dev/")):
            continue
        suspicious.append(f"{mount_point} ({fs_type})")
    return result("no-host-bind-mounts", "fail" if suspicious else "pass", ", ".join(suspicious) or "none")


def check_image_contents() -> Result:
    unwanted = [str(REPO / name) for name in (".git", ".venv", ".env", "dist", "logs", "inputs", "reports")]
    present = [path for path in unwanted if Path(path).exists()]
    leftover = [str(p) for p in (REPO / "registros").iterdir()] if (REPO / "registros").is_dir() else []
    bad = present + [f"registros content: {item}" for item in leftover]
    return result(
        "image-has-no-host-artifacts", "fail" if bad else "pass", ", ".join(bad) or "allowlisted sources only"
    )


def check_no_secret_env() -> Result:
    hits = sorted(
        key
        for key in os.environ
        if any(marker in key.upper() for marker in SECRET_ENV_MARKERS) or key.upper().startswith(SECRET_ENV_PREFIXES)
    )
    return result(
        "no-secret-environment", "fail" if hits else "pass", ", ".join(hits) or "no credential-like variables"
    )


# -------------------------------------------------------------- resources
def _cgroup_value(name: str) -> str | None:
    try:
        return Path("/sys/fs/cgroup", name).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def check_resource_limits() -> Result:
    memory = _cgroup_value("memory.max")
    pids = _cgroup_value("pids.max")
    cpu = _cgroup_value("cpu.max")
    limits = {"memory.max": memory, "pids.max": pids, "cpu.max": cpu}
    if None in limits.values():
        return result("resource-limits", "unverified", f"cgroup v2 files unavailable: {limits}")
    ok = memory != "max" and pids != "max" and not str(cpu).startswith("max")
    return result("resource-limits", "pass" if ok else "fail", json.dumps(limits))


def check_pids_limit_enforced() -> Result:
    limit = _cgroup_value("pids.max")
    if limit in (None, "max"):
        return result("pids-limit-enforced", "unverified", f"pids.max={limit}")
    children: list[subprocess.Popen[bytes]] = []
    refused = False
    try:
        for _ in range(int(str(limit)) + 16):
            try:
                children.append(subprocess.Popen(["sleep", "5"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            except OSError:
                refused = True
                break
    finally:
        for child in children:
            child.kill()
        for child in children:
            child.wait()
    detail = f"pids.max={limit}; spawned {len(children)} before refusal" if refused else f"spawned {len(children)}"
    return result("pids-limit-enforced", "pass" if refused else "fail", detail)


# ------------------------------------------------------------------ network
def check_interfaces() -> Result:
    try:
        names = sorted(entry.name for entry in Path("/sys/class/net").iterdir())
    except OSError:
        return result("network-interfaces", "unverified", "/sys/class/net unreadable")
    ok = names == ["lo"]
    return result("network-interfaces", "pass" if ok else "fail", f"interfaces={names}")


def check_external_connections_blocked() -> Result:
    outcomes: list[dict[str, object]] = []
    connected = 0
    for host, port in TEST_NET_PROBES:
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=2):
                connected += 1
                outcome = "CONNECTED"
        except OSError as exc:
            outcome = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
        outcomes.append(
            {"target": f"{host}:{port}", "outcome": outcome, "ms": round((time.monotonic() - started) * 1000)}
        )
    status = "pass" if connected == 0 else "fail"
    return result("external-connections-blocked", status, f"{connected}/{len(outcomes)} connected", probes=outcomes)


def check_dns_unavailable() -> Result:
    # A reserved .invalid name: resolving it never reaches a public domain, and
    # with no interface besides lo no resolver is reachable at all.
    try:
        socket.getaddrinfo("bbtk-offline-probe.invalid", 80)
    except socket.gaierror as exc:
        return result("dns-resolution-unavailable", "pass", f"resolution failed: {exc.strerror or exc}")
    return result("dns-resolution-unavailable", "fail", "reserved name unexpectedly resolved")


class _Handler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, bytes]] = {}
    seen_headers: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        _Handler.seen_headers.append(str(self.headers))
        status, body = self.routes.get(self.path.split("?", 1)[0], (404, b"not found"))
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return


def start_synthetic_service(routes: dict[str, tuple[int, bytes]]) -> tuple[http.server.ThreadingHTTPServer, int]:
    _Handler.routes = routes
    _Handler.seen_headers = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, int(server.server_address[1])


def stop_synthetic_service(server: http.server.ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


def check_loopback_allowed() -> Result:
    server, port = start_synthetic_service({"/ping": (200, b"pong")})
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
            conn.sendall(b"GET /ping HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            # HTTP/1.0: the server closes when done. One recv() may return only the
            # headers (they are written separately from the body), so read to EOF.
            chunks = []
            while chunk := conn.recv(4096):
                chunks.append(chunk)
            data = b"".join(chunks)
    finally:
        stop_synthetic_service(server)
    ok = b"pong" in data
    return result("lab-internal-loopback-allowed", "pass" if ok else "fail", f"127.0.0.1:{port} -> {data[:15]!r}")


# --------------------------------------------------------------- functional
def check_ffuf_against_synthetic() -> Result:
    binary = shutil.which("ffuf")
    if not binary:
        return result("ffuf-synthetic-service", "fail", "ffuf not on PATH")
    version = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=10).stdout.strip()
    expected = {"admin", "api", "backup"}
    routes = {f"/{name}": (200, f"synthetic {name}".encode()) for name in expected}
    server, port = start_synthetic_service(routes)
    with tempfile.TemporaryDirectory() as work:
        wordlist = Path(work) / "words.txt"
        wordlist.write_text("\n".join(sorted(expected | {"missing", "nothing", "absent"})) + "\n", encoding="utf-8")
        output = Path(work) / "out.json"
        try:
            completed = subprocess.run(
                [
                    binary,
                    "-u",
                    f"http://127.0.0.1:{port}/FUZZ",
                    "-w",
                    str(wordlist),
                    "-mc",
                    "200",
                    "-t",
                    "2",
                    "-rate",
                    "50",
                    "-maxtime",
                    "30",
                    "-s",
                    "-o",
                    str(output),
                    "-of",
                    "json",
                    "-noninteractive",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            stop_synthetic_service(server)
        found = set()
        if output.is_file():
            found = {
                item["input"]["FUZZ"] for item in json.loads(output.read_text(encoding="utf-8")).get("results", [])
            }
    ok = completed.returncode == 0 and found == expected
    return result(
        "ffuf-synthetic-service",
        "pass" if ok else "fail",
        f"{version}; found={sorted(found)} expected={sorted(expected)} rc={completed.returncode}",
    )


def _bbtk(args: list[str], records: Path, log: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-c", "import sys; from bugbounty_toolkit.cli import main; sys.argv[0]='bbtk'; main()"]
    command += ["--records-root", str(records)]
    if log is not None:
        command += ["--log-file", str(log)]
    return subprocess.run(command + args, capture_output=True, text=True, timeout=120, cwd=str(REPO))


def check_scope_blocks_out_of_scope() -> Result:
    """bbtk's own scope control must refuse a non-scoped target before any connection."""
    with tempfile.TemporaryDirectory() as work:
        records = Path(work) / "records"
        _bbtk(["init", "scope-lab", "--authorization", "synthetic offline lab"], records)
        _bbtk(["scope", "add", "scope-lab", "127.0.0.1"], records)
        refused = _bbtk(["request", "scope-lab", "--url", "http://192.0.2.10/out-of-scope"], records)
    text = (refused.stdout + refused.stderr).lower()
    ok = refused.returncode != 0 and "scope" in text
    return result(
        "bbtk-scope-control-intact",
        "pass" if ok else "fail",
        f"rc={refused.returncode}; message={text.strip()[:160]!r}",
    )


def check_secret_not_leaked() -> Result:
    server, port = start_synthetic_service({"/whoami": (200, b"synthetic account page")})
    leaks: list[str] = []
    with tempfile.TemporaryDirectory() as work:
        records = Path(work) / "records"
        log = Path(work) / "bbtk.log"
        _bbtk(["init", "leak-lab", "--authorization", "synthetic offline lab", "--automation-allowed"], records)
        _bbtk(["scope", "add", "leak-lab", "127.0.0.1"], records)
        try:
            sent = _bbtk(
                [
                    "request",
                    "leak-lab",
                    "--url",
                    f"http://127.0.0.1:{port}/whoami?access_token={CANARY}",
                    "--header",
                    f"Authorization: Bearer {CANARY}",
                    "--cookie",
                    f"session={CANARY}",
                ],
                records,
                log,
            )
        finally:
            stop_synthetic_service(server)
        delivered = any(CANARY in headers for headers in _Handler.seen_headers)
        if CANARY in sent.stdout or CANARY in sent.stderr:
            leaks.append("console output")
        for path in Path(work).rglob("*"):
            if path.is_file() and CANARY.encode() in path.read_bytes():
                leaks.append(str(path.relative_to(work)))
        written = sum(1 for path in Path(work).rglob("*") if path.is_file())
    ok = sent.returncode == 0 and delivered and not leaks
    detail = f"rc={sent.returncode}; canary delivered to synthetic service={delivered}; files scanned={written}; "
    detail += f"leaks={leaks or 'none'}"
    return result("secret-not-persisted", "pass" if ok else "fail", detail)


def check_playwright_local_html() -> Result:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError:
        return result("playwright-local-html", "fail", "playwright library not importable in this image")
    page_html = (
        b"<!doctype html><title>bbtk offline</title><div id='out'></div>"
        b"<script>document.getElementById('out').textContent='rendered-'+(6*7)</script>"
    )
    server, port = start_synthetic_service({"/lab.html": (200, page_html)})
    blocked_external = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}/lab.html", timeout=15000)
                rendered = page.text_content("#out")
                try:
                    page.goto("http://192.0.2.1/", timeout=5000)
                    blocked_external = False
                except Exception:  # noqa: BLE001 - any navigation error means the request did not complete
                    blocked_external = True
                version = browser.version
            finally:
                browser.close()
    finally:
        stop_synthetic_service(server)
    ok = rendered == "rendered-42" and blocked_external is True
    return result(
        "playwright-local-html",
        "pass" if ok else "fail",
        f"chromium {version}; DOM text={rendered!r}; TEST-NET navigation blocked={blocked_external}",
    )


CHECKS: dict[str, Callable[[], Result]] = {
    "non-root-user": check_non_root,
    "capabilities-dropped": check_capabilities,
    "no-new-privileges": check_no_new_privileges,
    "seccomp-filter": check_seccomp,
    "no-setuid-binaries": check_setuid_binaries,
    "read-only-root-filesystem": check_read_only_rootfs,
    "explicit-writable-temp-dirs": check_explicit_temp_dirs,
    "no-host-credentials-or-sockets": check_no_host_private_paths,
    "no-host-bind-mounts": check_no_host_bind_mounts,
    "image-has-no-host-artifacts": check_image_contents,
    "no-secret-environment": check_no_secret_env,
    "resource-limits": check_resource_limits,
    "pids-limit-enforced": check_pids_limit_enforced,
    "network-interfaces": check_interfaces,
    "external-connections-blocked": check_external_connections_blocked,
    "dns-resolution-unavailable": check_dns_unavailable,
    "lab-internal-loopback-allowed": check_loopback_allowed,
    "ffuf-synthetic-service": check_ffuf_against_synthetic,
    "bbtk-scope-control-intact": check_scope_blocks_out_of_scope,
    "secret-not-persisted": check_secret_not_leaked,
}
OPTIONAL_CHECKS: dict[str, Callable[[], Result]] = {"playwright-local-html": check_playwright_local_html}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--playwright", action="store_true", help="also run the optional Playwright local HTML check")
    parser.add_argument("--require-seccomp", action="store_true", help="treat an absent seccomp filter as a failure")
    parser.add_argument("--only", action="append", help="run only the named check (repeatable)")
    options = parser.parse_args(argv)
    selected = dict(CHECKS)
    if options.playwright:
        selected.update(OPTIONAL_CHECKS)
    if options.only:
        selected = {name: fn for name, fn in {**CHECKS, **OPTIONAL_CHECKS}.items() if name in options.only}
    results: list[Result] = []
    for name, check in selected.items():
        try:
            results.append(check())
        except Exception as exc:  # noqa: BLE001 - report, never crash the whole run
            results.append(result(name, "fail", f"check raised {type(exc).__name__}: {exc}"))
    failed = [item for item in results if item["status"] == "fail"]
    if options.require_seccomp:
        failed += [item for item in results if item["name"] == "seccomp-filter" and item["status"] != "pass"]
    summary = {
        "passed": sum(item["status"] == "pass" for item in results),
        "failed": len(failed),
        "unverified": [item["name"] for item in results if item["status"] == "unverified"],
    }
    print(json.dumps({"summary": summary, "checks": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
