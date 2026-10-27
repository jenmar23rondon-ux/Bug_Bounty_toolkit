"""Offline, conservative authorization code review for local FastAPI / Express sources.

This module performs *static* observation only:

* It reads files under one explicitly authorized local root (no symlink escapes,
  no ``node_modules``/virtualenvs, size-capped).
* Python is parsed with :mod:`ast`; JavaScript is scanned with a small lexer that
  masks strings/comments and bracket-matches calls. Nothing from the audited
  project is imported, executed, installed or sent anywhere.
* It produces *hypotheses* for human review. ``finding_confirmed`` is always
  ``False`` and ``human_review_required`` is always ``True``.

Supported subset (documented in ``docs/offline-authorization-code-audit.md``):

* FastAPI: ``@app.<method>`` / ``@router.<method>`` decorators, ``APIRouter`` and
  ``FastAPI`` ``dependencies=[Depends(...)]``, ``include_router(dependencies=...)``,
  parameter ``Depends(...)``, ``@app.middleware("http")``, locally-defined helpers.
* Express: ``app|router.<method>(path, ...middleware, handler)``, ``.use(...)``
  (order-sensitive), ``express.Router()``, local ``function`` / arrow helpers and
  local middleware factories.

Absence of a recognised check is never treated as proof of a vulnerability, and a
function *named* ``authorize`` proves nothing: helper bodies are inspected and
empty / unreachable checks are ignored. Anything dynamic or unresolved is reported
as ``unknown`` (abstention).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

SCHEMA_VERSION = "offline-authz-audit/1"
MAX_FILE_BYTES = 1_000_000
MAX_HELPER_DEPTH = 4
SKIP_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".tox"})
PY_SUFFIXES = frozenset({".py"})
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
HTTP_METHODS = ("get", "post", "put", "patch", "delete")

Tri = Literal["observed", "not_observed", "unknown", "not_applicable"]

OWNER_TOKEN = re.compile(r"(owner|user_?id|tenant|account_?id|created_?by|author|org_?id)", re.I)
USER_TOKEN = re.compile(r"(current_?user|\buser\b|principal|req\.user|request\.user|session|\bme\b|caller|actor)", re.I)
ROLE_TOKEN = re.compile(r"(role|admin|permission|scope|is_staff|is_superuser|can_)", re.I)
AUTHN_TOKEN = re.compile(r"(user|token|session|credential|authorization|api_?key|bearer|principal)", re.I)
DENY_STATUS = re.compile(r"\b(401|403|404)\b|HTTP_40[134]|Unauthorized|Forbidden|NotFound|HTTPException", re.I)


@dataclass
class CheckSummary:
    authn: bool = False
    function_authz: bool = False
    object_authz: bool = False
    unresolved: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)

    def merge(self, other: CheckSummary) -> None:
        self.authn |= other.authn
        self.function_authz |= other.function_authz
        self.object_authz |= other.object_authz
        for u in other.unresolved:
            if u not in self.unresolved:
                self.unresolved.append(u)
        for r in other.refs:
            if r not in self.refs:
                self.refs.append(r)


@dataclass
class RouteObservation:
    route_ref: str
    http_method: str
    path: str
    source_file: str
    source_lines: list[int]
    framework: str
    resource_parameter: str | None
    authn_observed: Tri
    authn_scopes: list[str]
    function_authz_observed: Tri
    object_authz_observed: Tri
    analysis_coverage: Literal["complete", "partial"]
    unresolved_calls: list[str]
    possible_authorization_gap: bool | None
    evidence_refs: list[str]
    limitations: list[str]
    human_review_required: bool = True
    finding_confirmed: bool = False


@dataclass
class AuditReport:
    schema_version: str
    root: str
    routes: list[RouteObservation]
    files_read: list[str]
    files_skipped: dict[str, str]
    unauthorized_reads: int = 0
    target_code_executions: int = 0
    network_connections: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["elapsed_seconds"] = round(self.elapsed_seconds, 4)
        return data


# --------------------------------------------------------------------------- utilities


def _ownership_text(a: str, b: str) -> bool:
    return bool((OWNER_TOKEN.search(a) and USER_TOKEN.search(b)) or (OWNER_TOKEN.search(b) and USER_TOKEN.search(a)))


def _ownership_in_text(text: str) -> bool:
    """JS / generic fallback: a comparison operator joining an owner token and a user token."""
    for m in re.finditer(r"([^&|()?:;{},]+?)\s*(===|!==|==|!=)\s*([^&|()?:;{},]+)", text):
        if _ownership_text(m.group(1), m.group(3)):
            return True
    for m in re.finditer(r"(\w+)\s*:\s*([\w.\[\]'\"]+)", text):
        if _ownership_text(m.group(1), m.group(2)):
            return True
    return False


def iter_authorized_files(root: Path) -> tuple[list[Path], dict[str, str]]:
    """Return candidate files strictly inside ``root`` (symlinks escaping root are skipped)."""
    root = root.resolve()
    files: list[Path] = []
    skipped: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts):
            continue
        if path.suffix not in PY_SUFFIXES | JS_SUFFIXES:
            continue
        try:
            real = path.resolve()
        except OSError:
            continue
        rel = str(path.relative_to(root))
        if root not in real.parents and real != root:
            skipped[rel] = "outside_authorized_root"
            continue
        if not real.is_file():
            continue
        if real.stat().st_size > MAX_FILE_BYTES:
            skipped[rel] = "too_large"
            continue
        files.append(path)
    return files, skipped


# --------------------------------------------------------------------------- python / FastAPI


def _dotted(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive
        return "<expr>"


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_constant_false(test: ast.expr) -> bool:
    return isinstance(test, ast.Constant) and not test.value


def _depends_targets(node: ast.AST | None) -> list[ast.expr]:
    out: list[ast.expr] = []
    if node is None:
        return out
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _call_name(sub) in {"Depends", "Security"} and sub.args:
            out.append(sub.args[0])
    return out


class PyIndex:
    """Index of locally defined functions across the authorized root (by simple name)."""

    def __init__(self) -> None:
        self.funcs: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
        self.imported: set[str] = set()

    def add_module(self, rel: str, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(node.name, []).append((rel, node))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.imported.add((alias.asname or alias.name).split(".")[0])

    def resolve(self, name: str) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        hits = self.funcs.get(name, [])
        return hits[0] if len(hits) == 1 else None


SAFE_PY_CALLS = frozenset(
    {
        "HTTPException",
        "Depends",
        "Security",
        "len",
        "str",
        "int",
        "dict",
        "list",
        "print",
        "JSONResponse",
        "get",
        "filter",
        "filter_by",
        "first",
        "one",
        "all",
        "query",
        "select",
        "where",
        "execute",
        "scalar",
        "append",
        "items",
        "values",
        "keys",
        "isinstance",
        "getattr",
        "bool",
        "set",
        "tuple",
        "format",
        "lower",
        "startswith",
        "split",
        "strip",
        "call_next",
        "ValueError",
    }
)


class PyCheckAnalyzer:
    def __init__(self, index: PyIndex) -> None:
        self.index = index
        self.cache: dict[str, CheckSummary] = {}

    def function(self, rel: str, fn: ast.FunctionDef | ast.AsyncFunctionDef, depth: int = 0) -> CheckSummary:
        key = f"{rel}:{fn.lineno}"
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = CheckSummary()  # recursion guard
        summary = self.block(rel, fn.body, depth)
        for default in list(fn.args.defaults) + [d for d in fn.args.kw_defaults if d is not None]:
            for target in _depends_targets(default):
                summary.merge(self.dependency(rel, target, depth + 1))
        self.cache[key] = summary
        return summary

    def dependency(self, rel: str, target: ast.expr, depth: int) -> CheckSummary:
        name = _call_name(target)
        if isinstance(target, ast.Call):  # dependency factory, e.g. Depends(require_role("admin"))
            name = _call_name(target.func)
        resolved = self.index.resolve(name) if name else None
        if resolved is None or depth > MAX_HELPER_DEPTH:
            return CheckSummary(unresolved=[f"{rel}:{getattr(target, 'lineno', 0)}:Depends({_dotted(target)})"])
        return self.function(resolved[0], resolved[1], depth)

    def _deny_block(self, body: list[ast.stmt]) -> bool:
        for stmt in body:
            if isinstance(stmt, ast.Raise):
                return True
            if isinstance(stmt, ast.Return) and stmt.value is not None and DENY_STATUS.search(_dotted(stmt.value)):
                return True
        return False

    def _helper_return_text(self, test: ast.expr, depth: int) -> str:
        texts = [_dotted(test)]
        for sub in ast.walk(test):
            if isinstance(sub, ast.Call):
                name = _call_name(sub)
                resolved = self.index.resolve(name) if name else None
                if resolved and depth <= MAX_HELPER_DEPTH:
                    for node in ast.walk(resolved[1]):
                        if isinstance(node, ast.Return) and node.value is not None:
                            texts.append(_dotted(node.value))
        return " ".join(texts)

    def _classify_test(self, rel: str, test: ast.expr, depth: int, summary: CheckSummary) -> None:
        text = self._helper_return_text(test, depth)
        lineref = f"{rel}:{test.lineno}"
        owner = False
        for sub in ast.walk(ast.parse(text, mode="eval")) if _parses(text) else []:
            if isinstance(sub, ast.Compare):
                sides = [_dotted(sub.left)] + [_dotted(c) for c in sub.comparators]
                if any(_ownership_text(sides[0], s) for s in sides[1:]):
                    owner = True
        if not owner:
            owner = _ownership_in_text(text)
        if owner:
            summary.object_authz = True
        elif ROLE_TOKEN.search(text):
            summary.function_authz = True
        elif AUTHN_TOKEN.search(text):
            summary.authn = True
        else:
            return
        summary.refs.append(lineref)

    def block(self, rel: str, body: list[ast.stmt], depth: int) -> CheckSummary:
        summary = CheckSummary()
        for stmt in body:
            if isinstance(stmt, ast.If):
                if _is_constant_false(stmt.test):
                    continue  # dead code
                if self._deny_block(stmt.body):
                    self._classify_test(rel, stmt.test, depth, summary)
                summary.merge(self._calls_in(rel, stmt.test, depth))
                summary.merge(self.block(rel, stmt.body, depth))
                summary.merge(self.block(rel, stmt.orelse, depth))
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                for attr in ("body", "orelse", "finalbody"):
                    summary.merge(self.block(rel, getattr(stmt, attr, []) or [], depth))
                for h in getattr(stmt, "handlers", []) or []:
                    summary.merge(self.block(rel, h.body, depth))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            else:
                summary.merge(self._calls_in(rel, stmt, depth))
                self._query_scope(rel, stmt, summary)
            if isinstance(stmt, (ast.Return, ast.Raise)):
                break  # following statements are unreachable
        return summary

    def _query_scope(self, rel: str, stmt: ast.stmt, summary: CheckSummary) -> None:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                for kw in sub.keywords:
                    if kw.arg and _ownership_text(kw.arg, _dotted(kw.value)):
                        summary.object_authz = True
                        summary.refs.append(f"{rel}:{sub.lineno}")
            if isinstance(sub, ast.Compare) and isinstance(sub.ops[0], ast.Eq):
                if _ownership_text(_dotted(sub.left), _dotted(sub.comparators[0])) and not isinstance(stmt, ast.If):
                    summary.object_authz = True
                    summary.refs.append(f"{rel}:{sub.lineno}")

    def _calls_in(self, rel: str, node: ast.AST, depth: int) -> CheckSummary:
        summary = CheckSummary()
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            name = _call_name(sub)
            if not name or name in SAFE_PY_CALLS:
                continue
            resolved = self.index.resolve(name)
            if resolved is not None and depth < MAX_HELPER_DEPTH:
                summary.merge(self.function(resolved[0], resolved[1], depth + 1))
                continue
            arg_text = " ".join(_dotted(a) for a in list(sub.args) + [k.value for k in sub.keywords])
            if USER_TOKEN.search(arg_text) or ROLE_TOKEN.search(name) or "auth" in name.lower():
                summary.unresolved.append(f"{rel}:{sub.lineno}:{_dotted(sub.func)}")
        return summary


def _parses(text: str) -> bool:
    try:
        ast.parse(text, mode="eval")
    except SyntaxError:
        return False
    return True


def _path_params(path: str) -> list[str]:
    return re.findall(r"\{(\w+)(?::[^}]*)?\}", path) + re.findall(r":(\w+)", path)


def _resource_param(path: str) -> str | None:
    params = _path_params(path)
    return params[-1] if params else None


def _finalize(
    framework: str,
    method: str,
    path: str,
    rel: str,
    lines: list[int],
    scopes: list[str],
    summary: CheckSummary,
    limitations: list[str],
) -> RouteObservation:
    resource = _resource_param(path)
    unresolved = list(summary.unresolved)
    authn: Tri = "observed" if scopes or summary.authn else ("unknown" if unresolved else "not_observed")
    func_authz: Tri = "observed" if summary.function_authz else ("unknown" if unresolved else "not_observed")
    gap: bool | None
    if resource is None:
        obj: Tri = "not_applicable"
        gap = False
    elif summary.object_authz:
        obj, gap = "observed", False
    elif unresolved:
        obj, gap = "unknown", None
        limitations.append("unresolved_calls_may_contain_authorization")
    else:
        obj, gap = "not_observed", True
        limitations.append("absence_of_recognised_check_is_not_proof_of_vulnerability")
    if summary.function_authz and resource is not None and not summary.object_authz:
        limitations.append("function_level_check_does_not_imply_object_ownership")
    return RouteObservation(
        route_ref=f"{method.upper()} {path}",
        http_method=method.upper(),
        path=path,
        source_file=rel,
        source_lines=lines,
        framework=framework,
        resource_parameter=resource,
        authn_observed=authn,
        authn_scopes=sorted(set(scopes)),
        function_authz_observed=func_authz,
        object_authz_observed=obj,
        analysis_coverage="partial" if unresolved else "complete",
        unresolved_calls=unresolved,
        possible_authorization_gap=gap,
        evidence_refs=sorted(set(summary.refs), key=lambda r: (r.rsplit(":", 1)[0], int(r.rsplit(":", 1)[1]))),
        limitations=limitations,
    )


def _router_level_py(
    tree: ast.Module, rel: str, analyzer: PyCheckAnalyzer
) -> tuple[dict[str, tuple[CheckSummary, str]], CheckSummary | None]:
    """Return per-router dependency summaries and the global (FastAPI app / middleware) summary."""
    routers: dict[str, tuple[CheckSummary, str]] = {}
    global_summary: CheckSummary | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and len(node.targets) == 1:
            target = node.targets[0]
            ctor = _call_name(node.value.func)
            if isinstance(target, ast.Name) and ctor in {"APIRouter", "FastAPI"}:
                s = CheckSummary()
                for kw in node.value.keywords:
                    if kw.arg == "dependencies":
                        for dep in _depends_targets(kw.value):
                            s.merge(analyzer.dependency(rel, dep, 0))
                routers[target.id] = (s, "global" if ctor == "FastAPI" else "router")
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if _call_name(call.func) == "include_router" and call.args and isinstance(call.args[0], ast.Name):
                name = call.args[0].id
                for kw in call.keywords:
                    if kw.arg == "dependencies":
                        s = routers.get(name, (CheckSummary(), "router"))[0]
                        for dep in _depends_targets(kw.value):
                            s.merge(analyzer.dependency(rel, dep, 0))
                        routers[name] = (s, "router")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and _call_name(dec.func) == "middleware":
                    global_summary = global_summary or CheckSummary()
                    global_summary.merge(analyzer.function(rel, node))
    return routers, global_summary


def analyze_python_file(rel: str, tree: ast.Module, analyzer: PyCheckAnalyzer) -> list[RouteObservation]:
    routers, middleware = _router_level_py(tree, rel, analyzer)
    out: list[RouteObservation] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            method = dec.func.attr
            if method not in HTTP_METHODS or not dec.args:
                continue
            if not (isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)):
                continue
            owner = _dotted(dec.func.value)
            path = dec.args[0].value
            summary = CheckSummary()
            scopes: list[str] = []
            limitations: list[str] = []
            if middleware is not None:
                summary.merge(middleware)
                if middleware.authn:
                    scopes.append("global")
            if owner in routers:
                rs, kind = routers[owner]
                summary.merge(rs)
                if rs.authn:
                    scopes.append(kind)
            else:
                summary.unresolved.append(f"{rel}:{dec.lineno}:router({owner})")
            route_deps = CheckSummary()
            for kw in dec.keywords:
                if kw.arg == "dependencies":
                    for dep in _depends_targets(kw.value):
                        route_deps.merge(analyzer.dependency(rel, dep, 0))
            if route_deps.authn:
                scopes.append("route")
            summary.merge(route_deps)
            fn_summary = analyzer.function(rel, node)
            if fn_summary.authn:
                scopes.append("function")
            summary.merge(fn_summary)
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            out.append(_finalize("fastapi", method, path, rel, [dec.lineno, end], scopes, summary, limitations))
    return out


# --------------------------------------------------------------------------- JavaScript / Express


def mask_js(src: str) -> str:
    """Replace comment bodies and string contents with spaces (quotes kept, newlines kept)."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "'\"`":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                elif src[j] == "\n" and c != "`":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _match_bracket(masked: str, start: int) -> int:
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack: list[str] = []
    for i in range(start, len(masked)):
        ch = masked[i]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")}]":
            if not stack or stack.pop() != ch:
                return -1
            if not stack:
                return i
    return -1


def _split_args(masked: str, start: int, end: int) -> list[tuple[int, int]]:
    parts: list[tuple[int, int]] = []
    depth = 0
    seg = start
    for i in range(start, end):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((seg, i))
            seg = i + 1
    if masked[seg:end].strip():
        parts.append((seg, end))
    return parts


@dataclass
class JsFunction:
    name: str
    start: int
    body: str  # masked body text
    raw_body: str
    is_factory: bool


class JsFile:
    def __init__(self, rel: str, src: str) -> None:
        self.rel = rel
        self.src = src
        self.masked = mask_js(src)
        self.functions: dict[str, JsFunction] = {}
        self._index_functions()

    def line(self, offset: int) -> int:
        return self.src.count("\n", 0, offset) + 1

    def _index_functions(self) -> None:
        patterns = [
            re.compile(r"\bfunction\s+(\w+)\s*\("),
            re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*\w*\s*)?\("),
            re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(\w+)\s*=>"),
        ]
        for pat in patterns:
            for m in pat.finditer(self.masked):
                name = m.group(1)
                brace = self.masked.find("{", m.end())
                if brace == -1:
                    continue
                end = _match_bracket(self.masked, brace)
                if end == -1:
                    continue
                body = self.masked[brace : end + 1]
                raw = self.src[brace : end + 1]
                factory = bool(re.search(r"return\s+(?:async\s*)?(?:function\b|\(?[\w\s,]*\)?\s*=>)", body))
                self.functions.setdefault(name, JsFunction(name, m.start(), body, raw, factory))


def _strip_dead_js(body: str) -> str:
    while True:
        m = re.search(r"\bif\s*\(\s*(?:false|0)\s*\)\s*\{", body)
        if m is None:
            break
        end = _match_bracket(body, m.end() - 1)
        if end == -1:
            break
        body = body[: m.start()] + " " * (end + 1 - m.start()) + body[end + 1 :]
    # Drop code following an unconditional top-level return at function body depth 1.
    depth = 0
    for m in re.finditer(r"[{}]|\breturn\b", body):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        elif depth == 1:
            prefix = body[: m.start()].rstrip()
            if prefix.endswith(("{", ";", "}")) and not re.search(r"\b(if|else)\b[^;{}]*$", prefix[-80:]):
                semi = body.find(";", m.end())
                if semi != -1:
                    return body[: semi + 1] + "}"
    return body


JS_SAFE_CALLS = frozenset(
    {
        "status",
        "json",
        "send",
        "next",
        "find",
        "findOne",
        "findById",
        "get",
        "filter",
        "push",
        "map",
        "require",
        "Router",
        "express",
        "listen",
        "parseInt",
        "Number",
        "String",
        "end",
        "sendStatus",
        "includes",
        "some",
        "every",
        "split",
        "startsWith",
        "toString",
        "log",
        "Error",
        "then",
        "catch",
        "if",
        "for",
        "while",
        "switch",
        "return",
        "function",
        "async",
        "await",
        "typeof",
        "use",
    }
)


def _js_deny_conditions(body: str) -> list[tuple[int, str]]:
    """Return (offset, condition) for ``if (cond) ... 401/403/404 or throw`` patterns."""
    out: list[tuple[int, str]] = []
    for m in re.finditer(r"\bif\s*\(", body):
        start = m.end() - 1
        end = _match_bracket(body, start)
        if end == -1:
            continue
        cond = body[start + 1 : end]
        rest = body[end + 1 : end + 400].lstrip()
        if rest.startswith("{"):
            close = _match_bracket(rest, 0)
            branch = rest[: close + 1] if close != -1 else rest
        else:
            branch = rest.split(";", 1)[0]
        if re.search(r"\b(401|403|404)\b|\bthrow\b|sendStatus\(\s*40[134]", branch):
            out.append((m.start(), cond))
    return out


class JsCheckAnalyzer:
    def __init__(self, jf: JsFile) -> None:
        self.jf = jf

    def body(self, body: str, raw: str, base: int, depth: int = 0) -> CheckSummary:
        summary = CheckSummary()
        body = _strip_dead_js(body)
        for off, cond in _js_deny_conditions(body):
            text = cond + " " + self._helper_returns(cond)
            ref = f"{self.jf.rel}:{self.jf.line(base + off)}"
            if _ownership_in_text(text):
                summary.object_authz = True
            elif ROLE_TOKEN.search(text):
                summary.function_authz = True
            elif AUTHN_TOKEN.search(text):
                summary.authn = True
            else:
                continue
            summary.refs.append(ref)
        for m in re.finditer(r"\{([^{}]*)\}", body):
            inner = m.group(1)
            if re.search(
                r"(where|find|filter|query)", body[max(0, m.start() - 40) : m.start()], re.I
            ) and _ownership_in_text(inner):
                summary.object_authz = True
                summary.refs.append(f"{self.jf.rel}:{self.jf.line(base + m.start())}")
        for m in re.finditer(r"(?<![.\w])(\w+)\s*\(", body):
            name = m.group(1)
            if name in JS_SAFE_CALLS:
                continue
            fn = self.jf.functions.get(name)
            if fn is not None and depth < MAX_HELPER_DEPTH:
                summary.merge(self.body(fn.body, fn.raw_body, self.jf.masked.find(fn.body, fn.start), depth + 1))
                continue
            close = _match_bracket(body, m.end() - 1)
            args = body[m.end() : close] if close != -1 else ""
            if fn is None and (USER_TOKEN.search(args) or ROLE_TOKEN.search(name) or "auth" in name.lower()):
                summary.unresolved.append(f"{self.jf.rel}:{self.jf.line(base + m.start())}:{name}")
        for m in re.finditer(r"(\w+)\.(\w+)\s*\(([^()]*)\)", body):
            obj, meth, args = m.groups()
            if (
                obj in {"res", "req", "console", "db", "JSON", "Object", "Math", "router", "app"}
                or meth in JS_SAFE_CALLS
            ):
                continue
            if USER_TOKEN.search(args) or "auth" in meth.lower() or ROLE_TOKEN.search(meth):
                summary.unresolved.append(f"{self.jf.rel}:{self.jf.line(base + m.start())}:{obj}.{meth}")
        return summary

    def _helper_returns(self, cond: str) -> str:
        texts: list[str] = []
        for m in re.finditer(r"(\w+)\s*\(", cond):
            fn = self.jf.functions.get(m.group(1))
            if fn is not None:
                texts.extend(re.findall(r"return\s+([^;]+);", fn.body))
        return " ".join(texts)

    def middleware(self, start: int, end: int) -> CheckSummary:
        offset = start
        masked_arg = self.jf.masked[start:end]
        lead = len(masked_arg) - len(masked_arg.lstrip())
        offset += lead
        masked_arg = masked_arg.strip()
        arg = self.jf.src[start:end].strip()
        ident = re.fullmatch(r"\w+", arg)
        if ident:
            fn = self.jf.functions.get(arg)
            if fn is None:
                return CheckSummary(unresolved=[f"{self.jf.rel}:{self.jf.line(offset)}:middleware({arg})"])
            return self.body(fn.body, fn.raw_body, self.jf.masked.find(fn.body, fn.start))
        call = re.fullmatch(r"(\w+)\s*\((.*)\)", arg, re.S)
        if call:
            fn = self.jf.functions.get(call.group(1))
            if fn is None or not fn.is_factory:
                return CheckSummary(
                    unresolved=[f"{self.jf.rel}:{self.jf.line(offset)}:middleware({call.group(1)}(...))"]
                )
            return self.body(fn.body, fn.raw_body, self.jf.masked.find(fn.body, fn.start))
        if arg.startswith(("(", "async", "function")) or "=>" in arg:
            brace = masked_arg.find("{")
            if brace == -1:
                return CheckSummary()
            return self.body(masked_arg[brace:], arg[brace:], offset + brace)
        return CheckSummary(unresolved=[f"{self.jf.rel}:{self.jf.line(offset)}:middleware({arg[:40]})"])


def analyze_js_file(jf: JsFile) -> list[RouteObservation]:
    masked, src = jf.masked, jf.src
    analyzer = JsCheckAnalyzer(jf)
    routers = set(re.findall(r"(\w+)\s*=\s*(?:express\.)?Router\s*\(", masked))
    apps = set(re.findall(r"(\w+)\s*=\s*express\s*\(\s*\)", masked))
    if not routers and not apps:
        return []
    # Collect .use registrations (order sensitive) and mounts.
    uses: list[tuple[int, str, CheckSummary, str | None]] = []  # (offset, owner, summary, mounted router)
    routes: list[tuple[int, str, str, str, list[tuple[int, int]], int]] = []
    for m in re.finditer(r"\b(\w+)\s*\.\s*(use|get|post|put|patch|delete)\s*\(", masked):
        owner, verb = m.group(1), m.group(2)
        if owner not in routers | apps:
            continue
        open_paren = m.end() - 1
        close = _match_bracket(masked, open_paren)
        if close == -1:
            continue
        args = _split_args(masked, open_paren + 1, close)
        if verb == "use":
            mounted = None
            summary = CheckSummary()
            for a, b in args:
                text = src[a:b].strip()
                if text[:1] in "'\"`":
                    continue
                if text in routers:
                    mounted = text
                    continue
                summary.merge(analyzer.middleware(a, b))
            uses.append((m.start(), owner, summary, mounted))
            continue
        if not args:
            continue
        first = src[args[0][0] : args[0][1]].strip()
        if first[:1] not in "'\"`":
            continue
        routes.append((m.start(), owner, verb, first[1:-1], args[1:], close))
    out: list[RouteObservation] = []
    for start, owner, verb, path, rest, close in routes:
        summary = CheckSummary()
        scopes: list[str] = []
        limitations: list[str] = []
        for off, use_owner, use_summary, mounted in uses:
            applies = False
            scope = "router"
            if use_owner == owner and off < start and mounted is None:
                applies = True
                scope = "global" if owner in apps else "router"
            elif mounted == owner:
                applies = True
                scope = "router"
            elif owner in routers and use_owner in apps and mounted is None and off < start:
                # app-level middleware before router routes: applies only if router mounted after it.
                mount_offs = [o for o, _, _, mt in uses if mt == owner]
                applies = any(off < mo for mo in mount_offs)
                scope = "global"
            if applies:
                summary.merge(use_summary)
                if use_summary.authn:
                    scopes.append(scope)
        if owner in routers and not any(mt == owner for _, _, _, mt in uses):
            limitations.append("router_mount_not_observed_in_file")
        for idx, (a, b) in enumerate(rest):
            part = analyzer.middleware(a, b)
            if part.authn:
                scopes.append("route" if idx < len(rest) - 1 else "function")
            summary.merge(part)
        out.append(
            _finalize("express", verb, path, jf.rel, [jf.line(start), jf.line(close)], scopes, summary, limitations)
        )
    return out


# --------------------------------------------------------------------------- driver


def audit(root: Path) -> AuditReport:
    """Statically audit ``root``. Reads files only; never imports or executes them."""
    t0 = time.perf_counter()
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"authorized root is not a local directory: {root}")
    files, skipped = iter_authorized_files(root)
    resolved_root = root.resolve()
    files_read: list[str] = []
    py_trees: list[tuple[str, ast.Module]] = []
    js_files: list[JsFile] = []
    index = PyIndex()
    for path in files:
        rel = str(path.relative_to(resolved_root))
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            skipped[rel] = f"unreadable:{type(exc).__name__}"
            continue
        files_read.append(rel)
        if path.suffix in PY_SUFFIXES:
            try:
                tree = ast.parse(text, filename=rel)
            except SyntaxError as exc:
                skipped[rel] = f"syntax_error:line {exc.lineno}"
                continue
            index.add_module(rel, tree)
            py_trees.append((rel, tree))
        else:
            if _match_bracket(mask_js("{" + text + "}"), 0) == -1:
                skipped[rel] = "unbalanced_brackets"
                continue
            js_files.append(JsFile(rel, text))
    analyzer = PyCheckAnalyzer(index)
    routes: list[RouteObservation] = []
    for rel, tree in py_trees:
        routes.extend(analyze_python_file(rel, tree, analyzer))
    for jf in js_files:
        routes.extend(analyze_js_file(jf))
    routes.sort(key=lambda r: (r.source_file, r.source_lines[0]))
    return AuditReport(
        schema_version=SCHEMA_VERSION,
        root=resolved_root.name,
        routes=routes,
        files_read=files_read,
        files_skipped=skipped,
        elapsed_seconds=time.perf_counter() - t0,
    )


def to_ledger_candidates(report: AuditReport, *, reviewer: str, reviewed: bool) -> list[dict[str, Any]]:
    """Export possible gaps as *candidate* ledger entries. Requires explicit human review.

    Never sets a confirmed status; callers must record these via the Evidence Ledger's own APIs.
    """
    if not reviewed or not reviewer.strip():
        raise PermissionError("ledger export requires explicit human review (reviewed=True and reviewer)")
    return [
        {
            "kind": "static_authorization_hypothesis",
            "status": "candidate",
            "route_ref": r.route_ref,
            "evidence_refs": list(r.evidence_refs) or [f"{r.source_file}:{r.source_lines[0]}"],
            "reviewer": reviewer,
            "finding_confirmed": False,
        }
        for r in report.routes
        if r.possible_authorization_gap is True
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline static authorization audit (FastAPI/Express subset)")
    parser.add_argument("root", type=Path, help="local, authorized source directory")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = audit(args.root)
    text = json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
