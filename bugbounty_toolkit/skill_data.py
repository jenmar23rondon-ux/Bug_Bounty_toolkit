"""Locate repository or installed skill resources without network access."""

from __future__ import annotations

from pathlib import Path
import sys


def resolve_skill_root(package_directory: Path | None = None, prefix: Path | None = None) -> Path:
    """Return the source-tree skill directory or its installed data-files location."""
    package_dir = package_directory or Path(__file__).resolve().parent
    environment_prefix = prefix or Path(sys.prefix)
    source_tree = package_dir.parent / "skills"
    installed_data = environment_prefix / "share" / "bug-bounty-toolkit" / "skills"
    if source_tree.is_dir():
        return source_tree
    return installed_data
