from __future__ import annotations

import hashlib
import itertools
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from .core.scope_validator import ScopeValidator


MAX_APK_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 256 * 1024 * 1024
MAX_DECOMPILED_FILES = 20_000
MAX_DECOMPILED_BYTES = 256 * 1024 * 1024
DECOMPILER_TIMEOUT_SECONDS = 120

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]{1,128}@[A-Z0-9.-]{1,190}\.[A-Z]{2,63}\b")
GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
STRIPE_KEY_RE = re.compile(r"\bsk_[0-9A-Za-z_-]{12,}\b")
ASSIGNED_SECRET_RE = re.compile(
    r"(?i)(?P<name>\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token)\b)"
    r"\s*[\"']?\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9._~+/-]{8,512})"
)
FIREBASE_RE = re.compile(
    r"(?i)(?:[a-z0-9-]+\.)*firebaseio\.com|(?:[a-z0-9-]+\.)*firebasestorage(?:\.googleapis\.com|\.app)"
)
TRAILING_URL_PUNCTUATION = ".,;:!?)}\"'"
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _safe_archive_name(name: str) -> str:
    parts = ["[parent]" if part == ".." else part for part in PurePosixPath(name.replace("\\", "/")).parts]
    return "/".join(part for part in parts if part not in {"", "."})[:300]


def _masked(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _masked_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


def _safe_url(value: str) -> tuple[str, str | None]:
    value = value.rstrip(TRAILING_URL_PUNCTUATION)
    parsed = urlsplit(value)
    host = parsed.hostname
    if host is None or parsed.scheme.lower() not in {"http", "https"}:
        return "", None
    safe_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    try:
        port = parsed.port
    except ValueError:
        return "", None
    netloc = safe_host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", "")), host.lower()


def _scope_status(scope: ScopeValidator, url: str) -> str:
    try:
        scope.require(url)
    except (OSError, ValueError):
        return "out_of_scope"
    return "in_scope"


def _add_finding(findings: list[dict[str, Any]], seen: set[tuple[str, str, str]], finding: dict[str, Any]) -> None:
    key = (
        str(finding.get("type")),
        str(finding.get("file")),
        str(finding.get("value_masked", finding.get("value", ""))),
    )
    if key not in seen:
        seen.add(key)
        findings.append(finding)


def _decode_length8(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset >= limit:
        raise ValueError("Malformed Android binary XML")
    first = data[offset]
    offset += 1
    if first & 0x80:
        if offset >= limit:
            raise ValueError("Malformed Android binary XML")
        return ((first & 0x7F) << 8) | data[offset], offset + 1
    return first, offset


def _decode_length16(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset + 2 > limit:
        raise ValueError("Malformed Android binary XML")
    first = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if first & 0x8000:
        if offset + 2 > limit:
            raise ValueError("Malformed Android binary XML")
        second = struct.unpack_from("<H", data, offset)[0]
        return ((first & 0x7FFF) << 16) | second, offset + 2
    return first, offset


def _string_pool(data: bytes, offset: int, header_size: int, chunk_size: int) -> tuple[list[str], bool]:
    end = offset + chunk_size
    if chunk_size < header_size or offset + 28 > end:
        raise ValueError("Malformed Android binary XML")
    string_count, style_count, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
    if string_count > 100_000 or style_count > 100_000:
        raise ValueError("Android manifest string pool exceeds its limit")
    offsets_start = offset + header_size
    offsets_end = offsets_start + 4 * (string_count + style_count)
    if offsets_end > end or offset + strings_start > end:
        raise ValueError("Malformed Android binary XML")
    is_utf8 = bool(flags & 0x100)
    values: list[str] = []
    strings_base = offset + strings_start
    for index in range(string_count):
        relative = struct.unpack_from("<I", data, offsets_start + index * 4)[0]
        cursor = strings_base + relative
        if cursor >= end:
            raise ValueError("Malformed Android binary XML")
        if is_utf8:
            _, cursor = _decode_length8(data, cursor, end)
            byte_length, cursor = _decode_length8(data, cursor, end)
            if cursor + byte_length > end:
                raise ValueError("Malformed Android binary XML")
            values.append(data[cursor : cursor + byte_length].decode("utf-8", errors="replace"))
        else:
            char_length, cursor = _decode_length16(data, cursor, end)
            byte_length = char_length * 2
            if cursor + byte_length > end:
                raise ValueError("Malformed Android binary XML")
            values.append(data[cursor : cursor + byte_length].decode("utf-16le", errors="replace"))
    return values, is_utf8


def _deep_link_values(schemes: set[str], hosts: set[str], paths: set[str]) -> list[str]:
    if not schemes and not hosts:
        return []
    scheme_values = sorted(schemes) or [""]
    host_values = sorted(hosts) or [""]
    path_values = sorted(paths) or [""]
    values = []
    for scheme, host, path in itertools.product(scheme_values, host_values, path_values):
        if scheme and host:
            value = f"{scheme}://{host}{path}"
        elif scheme:
            value = f"{scheme}:{path}"
        else:
            value = f"//{host}{path}"
        values.append(value)
    return values


def _parse_text_manifest(data: bytes) -> list[str]:
    text = data.decode("utf-8-sig", errors="strict")
    root = ET.fromstring(text)
    found: list[str] = []
    for intent_filter in root.iter():
        if intent_filter.tag.rsplit("}", 1)[-1] != "intent-filter":
            continue
        actions: set[str] = set()
        categories: set[str] = set()
        schemes: set[str] = set()
        hosts: set[str] = set()
        paths: set[str] = set()
        for child in intent_filter:
            tag = child.tag.rsplit("}", 1)[-1]
            name = child.attrib.get(f"{{{ANDROID_NS}}}name", child.attrib.get("name", ""))
            if tag == "action":
                actions.add(name)
            elif tag == "category":
                categories.add(name)
            elif tag == "data":
                for key, destination in (
                    ("scheme", schemes),
                    ("host", hosts),
                    ("path", paths),
                    ("pathPrefix", paths),
                    ("pathPattern", paths),
                ):
                    value = child.attrib.get(f"{{{ANDROID_NS}}}{key}", child.attrib.get(key))
                    if value:
                        destination.add(value)
        if "android.intent.action.VIEW" in actions and "android.intent.category.BROWSABLE" in categories:
            found.extend(_deep_link_values(schemes, hosts, paths))
    return sorted(set(found))


def _parse_binary_manifest(data: bytes) -> list[str]:
    if len(data) < 8:
        raise ValueError("Malformed Android binary XML")
    file_type, file_header_size, file_size = struct.unpack_from("<HHI", data, 0)
    if file_type != 0x0003 or file_header_size < 8 or file_size > len(data):
        raise ValueError("Malformed Android binary XML")
    strings: list[str] = []
    offset = file_header_size
    active_filter: dict[str, set[str]] | None = None
    found: list[str] = []
    while offset + 8 <= file_size:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or header_size < 8 or offset + chunk_size > file_size:
            raise ValueError("Malformed Android binary XML")
        if chunk_type == 0x0001:
            strings, _ = _string_pool(data, offset, header_size, chunk_size)
        elif chunk_type == 0x0102:
            if not strings or header_size < 16 or chunk_size < header_size + 20:
                raise ValueError("Malformed Android binary XML")
            element_ext = offset + header_size
            name_index = struct.unpack_from("<I", data, element_ext + 4)[0]
            if name_index >= len(strings):
                raise ValueError("Malformed Android binary XML")
            tag = strings[name_index]
            attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", data, element_ext + 8)
            if attribute_count > 10_000 or attribute_size < 20:
                raise ValueError("Malformed Android binary XML")
            first_attribute = element_ext + attribute_start
            if first_attribute + attribute_count * attribute_size > offset + chunk_size:
                raise ValueError("Malformed Android binary XML")
            attrs: dict[str, str] = {}
            for index in range(attribute_count):
                attribute = first_attribute + index * attribute_size
                attr_name = struct.unpack_from("<I", data, attribute + 4)[0]
                raw_value = struct.unpack_from("<I", data, attribute + 8)[0]
                value_type = data[attribute + 15]
                typed_value = struct.unpack_from("<I", data, attribute + 16)[0]
                value_index = (
                    raw_value if raw_value != 0xFFFFFFFF else typed_value if value_type == 0x03 else 0xFFFFFFFF
                )
                if attr_name >= len(strings):
                    continue
                if value_index < len(strings):
                    attrs[strings[attr_name]] = strings[value_index]
            if tag == "intent-filter":
                active_filter = {
                    "actions": set(),
                    "categories": set(),
                    "schemes": set(),
                    "hosts": set(),
                    "paths": set(),
                }
            elif active_filter is not None:
                if tag == "action" and attrs.get("name"):
                    active_filter["actions"].add(attrs["name"])
                elif tag == "category" and attrs.get("name"):
                    active_filter["categories"].add(attrs["name"])
                elif tag == "data":
                    for key in ("scheme", "host", "path", "pathPrefix", "pathPattern"):
                        if attrs.get(key):
                            target = "paths" if key.startswith("path") else key + "s"
                            active_filter[target].add(attrs[key])
        elif chunk_type == 0x0103 and active_filter is not None:
            name_index = (
                struct.unpack_from("<I", data, offset + header_size + 4)[0]
                if header_size >= 16 and chunk_size >= header_size + 8
                else 0xFFFFFFFF
            )
            if name_index < len(strings) and strings[name_index] == "intent-filter":
                if (
                    "android.intent.action.VIEW" in active_filter["actions"]
                    and "android.intent.category.BROWSABLE" in active_filter["categories"]
                ):
                    found.extend(
                        _deep_link_values(active_filter["schemes"], active_filter["hosts"], active_filter["paths"])
                    )
                active_filter = None
        offset += chunk_size
    return sorted(set(found))


def parse_android_manifest(data: bytes) -> list[str]:
    """Extract browsable VIEW intent-filter URIs from textual or binary Android XML."""
    if data.lstrip().startswith(b"<") or data.startswith(b"\xef\xbb\xbf"):
        return _parse_text_manifest(data)
    return _parse_binary_manifest(data)


class ApkScanner:
    """Perform bounded, offline, in-memory static analysis of an APK archive."""

    def __init__(self, scope: ScopeValidator):
        self.scope = scope

    @staticmethod
    def validate_input(apk: Path) -> Path:
        path = apk.expanduser().resolve()
        if not path.is_file():
            raise ValueError("APK path must identify a readable regular file.")
        if path.stat().st_size > MAX_APK_BYTES:
            raise ValueError("APK exceeds the 512 MiB input limit.")
        if not zipfile.is_zipfile(path):
            raise ValueError("Input is not a valid APK/ZIP archive.")
        return path

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _add_url(
        self, findings: list[dict[str, Any]], seen: set[tuple[str, str, str]], value: str, member: str
    ) -> None:
        safe_url, host = _safe_url(value)
        if not safe_url or host is None:
            return
        status = _scope_status(self.scope, safe_url)
        _add_finding(
            findings,
            seen,
            {
                "type": "endpoint",
                "file": member,
                "value": safe_url,
                "host": host,
                "scope": status,
                "classification": "informational",
            },
        )
        if "firebaseio.com" in host or "firebasestorage" in host:
            _add_finding(
                findings,
                seen,
                {
                    "type": "firebase",
                    "file": member,
                    "value": safe_url,
                    "host": host,
                    "scope": status,
                    "classification": "informational",
                },
            )

    def _scan_content(
        self,
        content: bytes,
        member: str,
        findings: list[dict[str, Any]],
        seen: set[tuple[str, str, str]],
    ) -> None:
        text = content.decode("latin-1", errors="ignore")
        for match in URL_RE.finditer(text):
            self._add_url(findings, seen, match.group(0), member)
        for match in FIREBASE_RE.finditer(text):
            value = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
            host = value.lower()
            scope_status = _scope_status(self.scope, f"https://{host}/")
            _add_finding(
                findings,
                seen,
                {
                    "type": "firebase",
                    "file": member,
                    "value": value,
                    "host": host,
                    "scope": scope_status,
                    "classification": "informational",
                },
            )
        for pattern, kind in ((GOOGLE_KEY_RE, "google_api_key"), (STRIPE_KEY_RE, "prefixed_secret")):
            for match in pattern.finditer(text):
                value = match.group(0)
                _add_finding(
                    findings,
                    seen,
                    {
                        "type": "secret",
                        "secret_kind": kind,
                        "file": member,
                        "value_masked": _masked(value),
                        "length_bucket": "9-32" if len(value) <= 32 else "33+",
                        "classification": "candidate",
                    },
                )
        for match in ASSIGNED_SECRET_RE.finditer(text):
            value = match.group("value").rstrip(".,;)")
            if value.lower() in {"example", "placeholder", "changeme", "your_api_key", "your-token"}:
                continue
            name = re.sub(r"[^a-z0-9]+", "_", match.group("name").lower()).strip("_")
            _add_finding(
                findings,
                seen,
                {
                    "type": "secret",
                    "secret_kind": name,
                    "file": member,
                    "value_masked": _masked(value),
                    "length_bucket": "8-16" if len(value) <= 16 else "17-64" if len(value) <= 64 else "65+",
                    "classification": "candidate",
                },
            )
        for match in EMAIL_RE.finditer(text):
            value = match.group(0)
            _add_finding(
                findings,
                seen,
                {
                    "type": "email",
                    "file": member,
                    "value_masked": _masked_email(value),
                    "classification": "informational",
                },
            )

    @staticmethod
    def _decompiler() -> tuple[str, str] | None:
        for name in ("jadx", "apktool"):
            executable = shutil.which(name)
            if executable:
                return name, executable
        return None

    def _scan_decompiled(
        self,
        apk: Path,
        findings: list[dict[str, Any]],
        seen: set[tuple[str, str, str]],
    ) -> dict[str, Any]:
        selected = self._decompiler()
        if selected is None:
            return {"status": "unavailable", "reason": "jadx_or_apktool_not_installed"}
        name, executable = selected
        scanned = 0
        bytes_scanned = 0
        try:
            with tempfile.TemporaryDirectory(prefix="bbtk-apk-") as directory:
                root = Path(directory)
                output = root / "decoded"
                if name == "jadx":
                    command = [executable, "-d", str(output), str(apk)]
                else:
                    command = [executable, "d", "-f", "-o", str(output), str(apk)]
                try:
                    result = subprocess.run(
                        command,
                        cwd=root,
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=DECOMPILER_TIMEOUT_SECONDS,
                        shell=False,
                    )
                except subprocess.TimeoutExpired:
                    return {"status": "timed_out", "tool": name, "timeout_seconds": DECOMPILER_TIMEOUT_SECONDS}
                if result.returncode != 0 or not output.is_dir():
                    return {"status": "failed", "tool": name, "reason": "decompiler_failed"}
                for path in sorted(output.rglob("*")):
                    if scanned >= MAX_DECOMPILED_FILES:
                        break
                    if path.is_symlink() or not path.is_file():
                        continue
                    size = path.stat().st_size
                    if size > MAX_MEMBER_BYTES or bytes_scanned + size > MAX_DECOMPILED_BYTES:
                        continue
                    data = path.read_bytes()
                    bytes_scanned += len(data)
                    scanned += 1
                    relative = _safe_archive_name(path.relative_to(output).as_posix())
                    self._scan_content(data, f"{name}/{relative}", findings, seen)
                return {"status": "complete", "tool": name, "files_scanned": scanned, "bytes_scanned": bytes_scanned}
        except OSError:
            return {"status": "failed", "tool": name, "reason": "decompiler_io_error"}

    def scan(self, apk: Path, *, decompile: bool = False) -> dict[str, Any]:
        """Scan ZIP members and manifest metadata without extracting or executing APK contents."""
        path = self.validate_input(apk)
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        warnings: list[str] = []
        files_scanned = 0
        bytes_scanned = 0
        skipped: list[dict[str, str]] = []
        manifest_status = "not_found"
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise ValueError("APK archive contains more than 20,000 entries.")
                for info in members:
                    if info.is_dir():
                        continue
                    member = _safe_archive_name(info.filename)
                    if stat.S_ISLNK(info.external_attr >> 16):
                        skipped.append({"file": member, "reason": "symbolic_link"})
                        continue
                    if info.file_size > MAX_MEMBER_BYTES:
                        skipped.append({"file": member, "reason": "member_size_limit"})
                        continue
                    if bytes_scanned >= MAX_TOTAL_SCAN_BYTES or info.file_size > MAX_TOTAL_SCAN_BYTES - bytes_scanned:
                        skipped.append({"file": member, "reason": "total_scan_limit"})
                        continue
                    try:
                        with archive.open(info) as handle:
                            content = handle.read(MAX_MEMBER_BYTES + 1)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        skipped.append({"file": member, "reason": "unreadable_or_encrypted"})
                        continue
                    if len(content) > MAX_MEMBER_BYTES:
                        skipped.append({"file": member, "reason": "member_size_limit"})
                        continue
                    if len(content) > MAX_TOTAL_SCAN_BYTES - bytes_scanned:
                        skipped.append({"file": member, "reason": "total_scan_limit"})
                        continue
                    bytes_scanned += len(content)
                    files_scanned += 1
                    self._scan_content(content, member, findings, seen)
                    if PurePosixPath(member).name == "AndroidManifest.xml":
                        try:
                            for link in parse_android_manifest(content):
                                scope_status = "not_applicable"
                                host = None
                                if link.lower().startswith(("http://", "https://")):
                                    safe_link, host = _safe_url(link)
                                    scope_status = _scope_status(self.scope, safe_link) if safe_link else "out_of_scope"
                                _add_finding(
                                    findings,
                                    seen,
                                    {
                                        "type": "deep_link",
                                        "file": member,
                                        "value": link,
                                        "host": host,
                                        "scope": scope_status,
                                        "classification": "informational",
                                    },
                                )
                            manifest_status = "parsed"
                        except (ET.ParseError, UnicodeDecodeError, ValueError, struct.error):
                            manifest_status = "unparsed"
                            warnings.append(
                                "AndroidManifest.xml was present but its intent filters could not be parsed."
                            )
        except (OSError, zipfile.BadZipFile) as exc:
            raise ValueError("Could not read a valid APK archive.") from exc

        decompile_result: dict[str, Any] = {"status": "not_requested"}
        if decompile:
            decompile_result = self._scan_decompiled(path, findings, seen)
            if decompile_result.get("status") in {"unavailable", "failed", "timed_out"}:
                warnings.append("Optional decompilation was not completed; ZIP contents were still scanned.")

        counts: dict[str, int] = {}
        scope_counts = {"in_scope": 0, "out_of_scope": 0, "not_applicable": 0}
        secret_types: dict[str, int] = {}
        for finding in findings:
            kind = str(finding["type"])
            counts[kind] = counts.get(kind, 0) + 1
            scope_value = finding.get("scope")
            if scope_value in scope_counts and kind in {"endpoint", "firebase", "deep_link"}:
                scope_counts[str(scope_value)] += 1
            if kind == "secret":
                secret_kind = str(finding["secret_kind"])
                secret_types[secret_kind] = secret_types.get(secret_kind, 0) + 1

        secret_count = counts.get("secret", 0)
        return {
            "type": "apk-scan",
            "classification": "candidate" if secret_count else "not_observed",
            "confirmed": False,
            "source": {"filename": path.name, "size_bytes": path.stat().st_size, "sha256": self._sha256(path)},
            "scan_mode": "zip_plus_decompiler" if decompile_result.get("status") == "complete" else "zip_only",
            "decompiler": decompile_result,
            "manifest_status": manifest_status,
            "files_scanned": files_scanned + int(decompile_result.get("files_scanned", 0)),
            "bytes_scanned": bytes_scanned + int(decompile_result.get("bytes_scanned", 0)),
            "counts": counts,
            "scope_counts": scope_counts,
            "secret_pattern_counts": secret_types,
            "results": findings,
            "skipped_entries": skipped,
            "warnings": warnings,
            "network_requests_sent": 0,
            "execution": "static_only; APK code was not executed",
        }
