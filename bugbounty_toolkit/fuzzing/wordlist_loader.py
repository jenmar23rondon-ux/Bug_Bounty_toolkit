from __future__ import annotations

from pathlib import Path


def require_wordlist(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    if not path.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    return path


def preview_wordlist(path: Path, limit: int = 5) -> list[str]:
    require_wordlist(path)
    values: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            values.append(clean)
        if len(values) >= limit:
            break
    return values
