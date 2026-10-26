from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import sqlite3
import sys

from . import __version__
from .core.records import ProgramPaths
from .core.settings import load_settings
from .core.scope_validator import ScopeValidator
from .skill_data import resolve_skill_root


OPTIONAL_MODULES = {
    "csrf": ("bs4",),
    "xss": ("bs4", "lxml", "html5lib", "playwright"),
    "sqli": ("sqlparse",),
    "jwt": ("jwt", "jose", "cryptography", "jwcrypto"),
    "http": ("requests", "aiohttp", "httpx"),
    "databases": ("pymysql", "psycopg2"),
    "dashboard": ("fastapi", "uvicorn"),
    "takeover": ("dns.resolver",),
}


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def playwright_browsers_root(environ: dict[str, str] | None = None, platform: str | None = None) -> Path | None:
    """Return the directory Playwright uses for downloaded browsers, without importing Playwright."""
    env = os.environ if environ is None else environ
    configured = env.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if configured == "0":
        return None  # browsers live inside the Playwright package; location is version specific
    if configured:
        return Path(configured)
    current = platform or sys.platform
    if current.startswith("win"):
        local = env.get("LOCALAPPDATA")
        return Path(local) / "ms-playwright" if local else None
    if current == "darwin":
        return Path(env.get("HOME", str(Path.home()))) / "Library" / "Caches" / "ms-playwright"
    cache = env.get("XDG_CACHE_HOME") or str(Path(env.get("HOME", str(Path.home()))) / ".cache")
    return Path(cache) / "ms-playwright"


def playwright_browser_check(library_available: bool, browsers_root: Path | None) -> tuple[str, str]:
    """Report whether a Chromium build is present for Playwright. Never downloads or launches a browser."""
    if not library_available:
        return "warning", "Playwright library not installed; optional browser confirmation unavailable"
    if browsers_root is None:
        return "warning", "Playwright browser location is package-local or unknown; not inspected"
    try:
        builds = sorted(
            entry.name for entry in browsers_root.iterdir() if entry.is_dir() and entry.name.startswith("chromium")
        )
    except OSError:
        builds = []
    if builds:
        return "ok", f"Chromium build(s) at {browsers_root}: {', '.join(builds)}"
    return (
        "warning",
        f"Playwright installed but no Chromium build at {browsers_root}; install it during setup with "
        "'python -m playwright install chromium' (bbtk never downloads browsers automatically)",
    )


def diagnose(
    records_root: Path,
    program: str | None = None,
    skills_root: Path | None = None,
    installed_skills: Path | None = None,
) -> dict[str, object]:
    """Run local-only checks for runtime, optional packages, skills and program configuration."""
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    python_ok = sys.version_info >= (3, 10)
    add(
        "python",
        "ok" if python_ok else "error",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    try:
        yaml_available = importlib.util.find_spec("yaml") is not None
    except (ImportError, ValueError):
        yaml_available = False
    add(
        "dependency:PyYAML",
        "ok" if yaml_available else "error",
        "required" if yaml_available else "missing; install the base package",
    )

    for extra, modules in OPTIONAL_MODULES.items():
        missing = []
        for module in modules:
            try:
                available = importlib.util.find_spec(module) is not None
            except (ImportError, ValueError):
                available = False
            if not available:
                missing.append(module)
        add(
            f"extra:{extra}",
            "ok" if not missing else "warning",
            "all optional modules available" if not missing else "optional modules missing: " + ", ".join(missing),
        )
    add(
        "tool:ffuf",
        "ok" if shutil.which("ffuf") else "warning",
        "available on PATH" if shutil.which("ffuf") else "not installed; ffuf adapter unavailable",
    )
    browser_status, browser_detail = playwright_browser_check(
        _module_available("playwright"), playwright_browsers_root()
    )
    add("tool:playwright-browser", browser_status, browser_detail)
    if os.environ.get("BBTK_OFFLINE_LAB") == "1":
        add(
            "environment:offline-lab",
            "ok",
            "bbtk offline lab image; external network is expected to be disabled by the container runtime",
        )
    ollama_path = shutil.which("ollama")
    add(
        "tool:ollama",
        "ok" if ollama_path else "warning",
        f"available on PATH at {ollama_path}" if ollama_path else "not installed; local model review unavailable",
    )
    add("toolkit-version", "ok", __version__)

    root = skills_root or resolve_skill_root()
    skill_files = sorted(root.glob("bugbounty-*/SKILL.md")) if root.is_dir() else []
    add(
        "skill-source",
        "ok" if skill_files else "warning",
        f"{len(skill_files)} topic/router skill files found at {root}",
    )
    if installed_skills is None:
        home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
        installed_skills = home / "skills"
    expected = [path.parent.name for path in skill_files]
    installed = [name for name in expected if (installed_skills / name / "SKILL.md").is_file()]
    missing_skills = sorted(set(expected) - set(installed))
    add(
        "skill-installation",
        "ok" if expected and not missing_skills else "warning",
        "all repository skills installed"
        if expected and not missing_skills
        else f"{len(installed)}/{len(expected)} installed at {installed_skills}",
    )

    settings_path = Path(__file__).resolve().parents[1] / "config" / "settings.yaml"
    if program:
        paths = ProgramPaths(records_root, program)
        settings_path = paths.program_dir / "settings.yaml"
        scope_ok = paths.scope_file.is_file()
        if scope_ok:
            try:
                scope = ScopeValidator(paths.scope_file).summary()
                add(
                    "program-scope",
                    "ok" if scope["allowed"] else "warning",
                    f"{len(scope['allowed'])} allowed and {len(scope['excluded'])} excluded rules",
                )
            except (OSError, ValueError):
                add("program-scope", "error", "scope file is invalid or unreadable; details omitted")
        else:
            add(
                "program-scope",
                "warning",
                "scope file is missing; network requests will be rejected until scope is configured",
            )
        authorized = False
        if paths.db_path.is_file():
            try:
                connection = sqlite3.connect(paths.db_path.resolve().as_uri() + "?mode=ro", uri=True)
                try:
                    row = connection.execute("select value from program where key = 'authorization'").fetchone()
                    authorized = bool(row and str(row[0]).strip())
                finally:
                    connection.close()
            except sqlite3.Error:
                add("program-authorization", "warning", "program record could not be read")
        add(
            "program-authorization",
            "ok" if authorized else "warning",
            "authorization reference recorded" if authorized else "no authorization reference recorded",
        )
    if not yaml_available and settings_path.is_file():
        add("configuration", "warning", "cannot validate YAML settings until PyYAML is installed")
    else:
        try:
            load_settings(settings_path if settings_path.is_file() else None)
            add(
                "configuration",
                "ok",
                f"valid settings: {settings_path if settings_path.is_file() else 'built-in defaults'}",
            )
        except (OSError, ValueError):
            add("configuration", "error", "settings are invalid or unreadable; details omitted")

    return {
        "toolkit_version": __version__,
        "network_requests_sent": 0,
        "program": program,
        "ok": not any(item["status"] == "error" for item in checks),
        "checks": checks,
    }
