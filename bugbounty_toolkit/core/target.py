from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit


@dataclass(frozen=True)
class Target:
    url: str

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""


def normalize_url(url: str, default_scheme: str = "https") -> str:
    clean = url.strip()
    if not clean:
        raise ValueError("URL cannot be empty.")
    if "://" not in clean:
        clean = f"{default_scheme}://{clean}"
    parsed = urlsplit(clean)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError(f"URL is missing a host: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Use an Authorization header instead of credentials in a URL.")
    if parsed.port == 0 or any(char.isspace() or ord(char) < 32 for char in clean) or "\\" in clean:
        raise ValueError("URL contains invalid whitespace, a backslash or a port of zero.")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))


def load_text_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_routes(path: Path, base_url: str | None = None) -> list[str]:
    routes: list[str] = []
    normalized_base = normalize_url(base_url) if base_url else None
    for line in load_text_lines(path):
        if line.startswith(("http://", "https://")):
            routes.append(normalize_url(line))
            continue
        if not normalized_base:
            raise ValueError(f"Relative route requires --base-url: {line}")
        routes.append(normalize_url(urljoin(normalized_base.rstrip("/") + "/", line)))
    return list(dict.fromkeys(routes))
