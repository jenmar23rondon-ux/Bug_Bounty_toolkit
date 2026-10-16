"""Preview or install the complete sibling skill family without network access."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil


SKILL_NAMES = (
    "bugbounty-executor",
    "bugbounty-xss",
    "bugbounty-sqli",
    "bugbounty-jwt",
    "bugbounty-authentication",
    "bugbounty-access-control",
)


def linked(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def check_path(path: Path) -> None:
    if any(linked(part) for part in (path, *path.parents)):
        raise ValueError("Skill installation does not follow symlinks or junctions.")


def install_skills(source: Path, destination: Path, *, execute: bool = False, update: bool = False) -> dict:
    source = source.absolute()
    destination = destination.expanduser().absolute()
    check_path(source)
    check_path(destination)
    source = source.resolve()
    destination = destination.resolve()
    if source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError("Skill source and destination must not overlap.")

    # Preflight the whole family before any writes, including update conflicts.
    copies = []
    for name in SKILL_NAMES:
        folder = source / name
        if not (folder / "SKILL.md").is_file():
            raise ValueError(f"Incomplete skill family: {name} is missing.")
        for item in sorted(folder.rglob("*")):
            if "__pycache__" in item.parts:
                continue
            check_path(item)
            if not item.is_file() or item.suffix not in {".md", ".yaml", ".py"}:
                continue
            target = destination / name / item.relative_to(folder)
            check_path(target)
            if any(part.exists() and not part.is_dir() for part in target.parents):
                raise ValueError("A destination parent is not a directory.")
            if target.exists() and not target.is_file():
                raise ValueError(f"A destination file is blocked by a directory: {target}")
            changed = not target.exists() or item.read_bytes() != target.read_bytes()
            if target.exists() and changed and not update:
                raise ValueError("Existing skill files differ; review them and pass --update to replace managed files.")
            copies.append((item, target, changed))
    if execute:
        for item, target, changed in copies:
            if changed:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)
    return {"skills": list(SKILL_NAMES), "destination": str(destination),
            "files_changed": sum(changed for _, _, changed in copies),
            "executed": execute, "network_requests_sent": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    parser.add_argument("--destination", type=Path, default=home / "skills")
    parser.add_argument("--execute", action="store_true", help="Install files; default only previews")
    parser.add_argument("--update", action="store_true", help="Replace differing managed files; leave unrelated files intact")
    args = parser.parse_args()
    try:
        import json
        print(json.dumps(install_skills(Path(__file__).resolve().parents[1] / "skills", args.destination,
                                       execute=args.execute, update=args.update), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
