"""Evidence-preserving, offline semantic diff of *stored* HTTP responses.

The engine compares two responses that were already captured. It never builds
or sends requests, never executes JavaScript, never loads external resources and
never emits a vulnerability verdict or a ``confirmed`` state. Denial semantics
remain the authority of :mod:`bugbounty_toolkit.analysis.authorization_denial`
(PR #52); this module only attaches that module's public assessment verbatim.

Values are never copied into the output: every observed value is represented by
a short SHA-256 fingerprint plus its JSON type, so the diff document is
shareable without leaking captured secrets. Authz-relevant and sensitive field
differences are always preserved; volatile keys are ignored only when an
explicit, recorded rule says so.
"""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
from html.parser import HTMLParser
import json
import re
from typing import Any, Mapping, Sequence

from .authorization_denial import assess_response

SCHEMA_VERSION = "bbtk-semantic-response-diff/1"

DEFAULT_MAX_BODY_BYTES = 1_000_000
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 20_000
DEFAULT_MAX_HTML_TAGS = 5_000
DEFAULT_MAX_CHANGES = 500

# Fields whose differences must never be hidden by a normalization rule.
_PROTECTED_TOKENS = (
    "id",
    "uid",
    "uuid",
    "owner",
    "user",
    "account",
    "tenant",
    "org",
    "organization",
    "role",
    "roles",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "group",
    "groups",
    "admin",
    "acl",
    "access",
    "email",
    "phone",
    "name",
    "username",
    "author",
    "creator",
    "member",
    "members",
    "is_admin",
    "privilege",
    "privileges",
    "visibility",
    "private",
    "public",
    "shared",
)
_SENSITIVE_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "session",
    "cookie",
    "ssn",
    "card",
    "cvv",
    "iban",
    "auth",
    "credential",
    "private_key",
    "otp",
)
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "www-authenticate",
    }
)
# Headers that are noise for structural diffs (never authz-relevant alone).
NOISE_HEADERS = frozenset(
    {
        "date",
        "server",
        "via",
        "x-request-id",
        "x-correlation-id",
        "x-amzn-trace-id",
        "cf-ray",
        "age",
        "expires",
        "pragma",
        "cache-control",
        "etag",
        "last-modified",
        "vary",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "content-encoding",
        "accept-ranges",
        "x-powered-by",
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
        "referrer-policy",
        "content-security-policy",
    }
)
_STRUCTURAL_HEADERS = frozenset({"content-type", "location", "content-length"})
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(name: str) -> set[str]:
    return {part for part in _TOKEN_SPLIT.split(name.lower()) if part}


def is_protected_key(name: str) -> bool:
    return bool(_tokens(name) & set(_PROTECTED_TOKENS))


def is_sensitive_key(name: str) -> bool:
    return bool(_tokens(name) & set(_SENSITIVE_TOKENS))


def fingerprint(value: Any) -> str:
    """Stable short digest of a JSON-compatible value (never the raw value)."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _normalize_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (headers or {}).items():
        result[str(key).lower()] = str(value)
    return result


def _content_type_family(value: str) -> str:
    base = value.split(";", 1)[0].strip().lower()
    if "json" in base:
        return "json"
    if "html" in base:
        return "html"
    if base.startswith("text/"):
        return "text"
    if not base:
        return "unknown"
    return base


def _parse_json_safe(text: str) -> tuple[Any | None, str | None]:
    """Parse JSON rejecting duplicate keys. Returns (value, error)."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique), None
    except RecursionError:
        return None, "json_depth_exceeded"
    except ValueError as exc:
        return None, "json_duplicate_key" if "duplicate" in str(exc) else "json_invalid"
    except json.JSONDecodeError:
        return None, "json_invalid"


@dataclass(frozen=True)
class StoredResponse:
    """A response already captured offline; never fetched by this module."""

    status_code: int | None
    headers: Mapping[str, str]
    body: str
    origin_ref: str | None = None
    body_fingerprint: str | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> StoredResponse:
        status = data.get("status_code", data.get("status"))
        if status is not None and not isinstance(status, int):
            try:
                status = int(status)
            except (TypeError, ValueError):
                status = None
        headers_raw = data.get("headers") or {}
        if not isinstance(headers_raw, Mapping):
            headers_raw = {}
        body = data.get("body", data.get("body_text", ""))
        if body is None:
            body = ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        else:
            body = str(body)
        origin = data.get("origin_ref") or data.get("origin") or data.get("id")
        fp = data.get("body_fingerprint")
        return cls(
            status_code=status if isinstance(status, int) else None,
            headers={str(k): str(v) for k, v in headers_raw.items()},
            body=body,
            origin_ref=str(origin) if origin is not None else None,
            body_fingerprint=str(fp) if fp is not None else None,
        )


@dataclass
class _Limits:
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_nodes: int = DEFAULT_MAX_NODES
    max_html_tags: int = DEFAULT_MAX_HTML_TAGS
    max_changes: int = DEFAULT_MAX_CHANGES


class _HtmlSkeleton(HTMLParser):
    """Extract tag/attribute-name skeleton; never execute scripts or fetch URLs."""

    def __init__(self, max_tags: int) -> None:
        super().__init__(convert_charrefs=True)
        self.max_tags = max_tags
        self.tags: list[dict[str, Any]] = []
        self.truncated = False
        self._stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.tags) >= self.max_tags:
            self.truncated = True
            return
        names = sorted({name.lower() for name, _ in attrs if name})
        self.tags.append({"tag": tag.lower(), "attrs": names, "event": "start"})
        self._stack.append(tag.lower())

    def handle_endtag(self, tag: str) -> None:
        if len(self.tags) >= self.max_tags:
            self.truncated = True
            return
        self.tags.append({"tag": tag.lower(), "attrs": [], "event": "end"})
        if self._stack and self._stack[-1] == tag.lower():
            self._stack.pop()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text or len(self.tags) >= self.max_tags:
            if len(self.tags) >= self.max_tags:
                self.truncated = True
            return
        # Length bucket only — never store raw text.
        bucket = 0 if len(text) == 0 else 1 if len(text) < 16 else 2 if len(text) < 64 else 3
        self.tags.append({"tag": "#text", "attrs": [], "event": "text", "bucket": bucket})


def _html_structure(body: str, max_tags: int) -> dict[str, Any]:
    parser = _HtmlSkeleton(max_tags)
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return {"kind": "html", "error": "html_parse_error", "tag_count": 0, "fingerprint": fingerprint("")}
    return {
        "kind": "html",
        "tag_count": sum(1 for item in parser.tags if item["event"] == "start"),
        "skeleton": parser.tags[:max_tags],
        "truncated": parser.truncated,
        "fingerprint": fingerprint(parser.tags[:max_tags]),
    }


def _walk_json(
    value: Any,
    path: str,
    *,
    depth: int,
    limits: _Limits,
    nodes: list[int],
) -> dict[str, Any] | None:
    if nodes[0] >= limits.max_nodes or depth > limits.max_depth:
        return None
    nodes[0] += 1
    entry: dict[str, Any] = {
        "path": path or "/",
        "type": json_type_name(value),
        "fingerprint": fingerprint(value),
    }
    if isinstance(value, dict):
        entry["keys"] = sorted(str(k) for k in value.keys())
        children: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda item: str(item)):
            child_path = f"{path}/{str(key).replace('~', '~0').replace('/', '~1')}"
            child = _walk_json(value[key], child_path, depth=depth + 1, limits=limits, nodes=nodes)
            if child is None:
                entry["truncated"] = True
                break
            children[str(key)] = child
        entry["children"] = children
    elif isinstance(value, list):
        entry["length"] = len(value)
        items: list[dict[str, Any]] = []
        for index, item in enumerate(value):
            child = _walk_json(item, f"{path}/{index}", depth=depth + 1, limits=limits, nodes=nodes)
            if child is None:
                entry["truncated"] = True
                break
            items.append(child)
        entry["items"] = items
        entry["item_fingerprints"] = [item["fingerprint"] for item in items]
    return entry


def _body_model(body: str, content_type: str, limits: _Limits) -> dict[str, Any]:
    family = _content_type_family(content_type)
    encoded = body.encode("utf-8", errors="replace")
    truncated = len(encoded) > limits.max_body_bytes
    if truncated:
        body = encoded[: limits.max_body_bytes].decode("utf-8", errors="replace")
    model: dict[str, Any] = {
        "family": family,
        "byte_length": len(encoded),
        "observed_length": len(body.encode("utf-8", errors="replace")),
        "truncated": truncated,
        "body_fingerprint": fingerprint(body),
        "empty": not body.strip(),
    }
    if family == "json" or (family in {"unknown", "text"} and body.lstrip()[:1] in "{["):
        root, error = _parse_json_safe(body)
        if error:
            model["json_error"] = error
            model["kind"] = "opaque"
        else:
            nodes = [0]
            tree = _walk_json(root, "", depth=0, limits=limits, nodes=nodes)
            model["kind"] = "json"
            model["tree"] = tree
            model["node_count"] = nodes[0]
            if tree is None:
                model["json_error"] = "json_limits_exceeded"
                model["kind"] = "opaque"
    elif family == "html" or (family in {"unknown", "text"} and "<" in body[:200].lower()):
        model["kind"] = "html"
        model["html"] = _html_structure(body, limits.max_html_tags)
    else:
        model["kind"] = "opaque"
        # Relevant textual tokens: short denial/access phrases only (fingerprinted).
        lowered = body.lower()
        markers = []
        for token in ("forbidden", "unauthorized", "access denied", "not found", "login", "success", "error"):
            if token in lowered:
                markers.append(token)
        model["text_markers"] = markers
    return model


def _rule_matches(path: str, key: str, rules: Sequence[str]) -> str | None:
    for rule in rules:
        if not rule:
            continue
        if rule.startswith("/") or rule.startswith("*"):
            if fnmatch.fnmatch(path, rule) or fnmatch.fnmatch(path.lstrip("/"), rule.lstrip("/")):
                return rule
        elif rule == key or fnmatch.fnmatch(key, rule):
            return rule
        elif key.lower() == rule.lower():
            return rule
    return None


def _volatile_allowed(path: str, key: str, rules: Sequence[str]) -> str | None:
    """Return the matching rule only when the key is not authz-protected."""
    if is_protected_key(key) or is_sensitive_key(key):
        return None
    # Path segments: refuse to ignore if any path segment is protected.
    for segment in path.strip("/").split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if segment.isdigit():
            continue
        if is_protected_key(segment) or is_sensitive_key(segment):
            return None
    return _rule_matches(path, key, rules)


def _change(
    path: str,
    kind: str,
    *,
    left: Any = None,
    right: Any = None,
    left_type: str | None = None,
    right_type: str | None = None,
    authz_relevant: bool = False,
    sensitive: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "path": path,
        "kind": kind,
        "authz_relevant": authz_relevant,
        "sensitive": sensitive,
    }
    if left_type is not None:
        item["left_type"] = left_type
    if right_type is not None:
        item["right_type"] = right_type
    if left is not None:
        item["left"] = left
    if right is not None:
        item["right"] = right
    if note:
        item["note"] = note
    return item


def _diff_json_trees(
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
    *,
    rules: Sequence[str],
    normalizations: list[str],
    changes: list[dict[str, Any]],
    limits: _Limits,
) -> None:
    if left is None and right is None:
        return
    if left is None or right is None:
        changes.append(
            _change(
                (right or left or {}).get("path", "/"),
                "schema_changed",
                left_type=None if left is None else left.get("type"),
                right_type=None if right is None else right.get("type"),
                authz_relevant=True,
            )
        )
        return
    path = left.get("path") or right.get("path") or "/"
    key = path.rsplit("/", 1)[-1] if path != "/" else ""
    key = key.replace("~1", "/").replace("~0", "~")

    if left.get("type") != right.get("type"):
        changes.append(
            _change(
                path,
                "type_changed",
                left={"fingerprint": left.get("fingerprint")},
                right={"fingerprint": right.get("fingerprint")},
                left_type=left.get("type"),
                right_type=right.get("type"),
                authz_relevant=is_protected_key(key) or is_sensitive_key(key) or path == "/",
                sensitive=is_sensitive_key(key),
            )
        )
        return

    if left.get("type") == "object":
        left_keys = set(left.get("keys") or [])
        right_keys = set(right.get("keys") or [])
        left_children = left.get("children") or {}
        right_children = right.get("children") or {}
        for name in sorted(left_keys - right_keys):
            child_path = f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}"
            rule = _volatile_allowed(child_path, name, rules)
            if rule:
                normalizations.append(f"ignore_removed_key:{rule}:{child_path}")
                continue
            changes.append(
                _change(
                    child_path,
                    "key_removed",
                    left={"fingerprint": (left_children.get(name) or {}).get("fingerprint")},
                    left_type=(left_children.get(name) or {}).get("type"),
                    authz_relevant=is_protected_key(name) or is_sensitive_key(name),
                    sensitive=is_sensitive_key(name),
                )
            )
        for name in sorted(right_keys - left_keys):
            child_path = f"{path.rstrip('/')}/{name}" if path != "/" else f"/{name}"
            rule = _volatile_allowed(child_path, name, rules)
            if rule:
                normalizations.append(f"ignore_added_key:{rule}:{child_path}")
                continue
            changes.append(
                _change(
                    child_path,
                    "key_added",
                    right={"fingerprint": (right_children.get(name) or {}).get("fingerprint")},
                    right_type=(right_children.get(name) or {}).get("type"),
                    authz_relevant=is_protected_key(name) or is_sensitive_key(name),
                    sensitive=is_sensitive_key(name),
                )
            )
        for name in sorted(left_keys & right_keys):
            if len(changes) >= limits.max_changes:
                break
            _diff_json_trees(
                left_children.get(name),
                right_children.get(name),
                rules=rules,
                normalizations=normalizations,
                changes=changes,
                limits=limits,
            )
        return

    if left.get("type") == "array":
        left_items = left.get("items") or []
        right_items = right.get("items") or []
        left_fps = left.get("item_fingerprints") or [item.get("fingerprint") for item in left_items]
        right_fps = right.get("item_fingerprints") or [item.get("fingerprint") for item in right_items]
        if left_fps != right_fps:
            if sorted(left_fps) == sorted(right_fps) and len(left_fps) == len(right_fps):
                changes.append(
                    _change(
                        path,
                        "array_reordered",
                        left={"length": left.get("length"), "fingerprint": left.get("fingerprint")},
                        right={"length": right.get("length"), "fingerprint": right.get("fingerprint")},
                        left_type="array",
                        right_type="array",
                        note="same_multiset_different_order",
                    )
                )
            else:
                changes.append(
                    _change(
                        path,
                        "array_changed",
                        left={"length": left.get("length"), "fingerprint": left.get("fingerprint")},
                        right={"length": right.get("length"), "fingerprint": right.get("fingerprint")},
                        left_type="array",
                        right_type="array",
                        authz_relevant=is_protected_key(key),
                        sensitive=is_sensitive_key(key),
                    )
                )
                # Also surface per-index type/value diffs up to the shorter length.
                for index, (a, b) in enumerate(zip(left_items, right_items)):
                    if len(changes) >= limits.max_changes:
                        break
                    if a.get("fingerprint") != b.get("fingerprint"):
                        _diff_json_trees(
                            a,
                            b,
                            rules=rules,
                            normalizations=normalizations,
                            changes=changes,
                            limits=limits,
                        )
                if len(left_items) != len(right_items):
                    changes.append(
                        _change(
                            path,
                            "array_length_changed",
                            left={"length": left.get("length")},
                            right={"length": right.get("length")},
                            authz_relevant=is_protected_key(key),
                        )
                    )
        return

    # Scalars
    if left.get("fingerprint") != right.get("fingerprint"):
        rule = _volatile_allowed(path, key, rules)
        if rule:
            normalizations.append(f"ignore_value:{rule}:{path}")
            return
        changes.append(
            _change(
                path,
                "value_changed",
                left={"fingerprint": left.get("fingerprint")},
                right={"fingerprint": right.get("fingerprint")},
                left_type=left.get("type"),
                right_type=right.get("type"),
                authz_relevant=is_protected_key(key) or is_sensitive_key(key),
                sensitive=is_sensitive_key(key),
            )
        )


def _side_summary(response: StoredResponse, model: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    assessment = assess_response(response.status_code, response.body, headers).as_dict()
    # Strip free-form reasons that might echo body snippets? Reasons are codes — keep.
    declared = headers.get("content-length")
    observed = model["byte_length"]
    length_note: dict[str, Any] = {"observed": observed}
    if declared is not None:
        try:
            length_note["declared"] = int(declared.strip())
            length_note["mismatch"] = length_note["declared"] != observed
        except ValueError:
            length_note["declared_raw_fingerprint"] = fingerprint(declared)
            length_note["mismatch"] = True
    return {
        "origin_ref": response.origin_ref,
        "status_code": response.status_code,
        "content_type": headers.get("content-type", ""),
        "content_type_family": model["family"],
        "location_fingerprint": fingerprint(headers["location"]) if "location" in headers else None,
        "has_location": "location" in headers,
        "content_length": length_note,
        "body_fingerprint": response.body_fingerprint or model["body_fingerprint"],
        "body_kind": model["kind"],
        "body_truncated": model["truncated"],
        "assessment": assessment,
    }


def _header_changes(
    left_headers: dict[str, str],
    right_headers: dict[str, str],
    changes: list[dict[str, Any]],
) -> None:
    left_keys = {k for k in left_headers if k not in NOISE_HEADERS and k not in SENSITIVE_HEADERS}
    right_keys = {k for k in right_headers if k not in NOISE_HEADERS and k not in SENSITIVE_HEADERS}
    # Sensitive headers: report presence-only diffs, never values.
    for name in sorted(SENSITIVE_HEADERS):
        left_present = name in left_headers
        right_present = name in right_headers
        if left_present != right_present:
            changes.append(
                _change(
                    f"/headers/{name}",
                    "sensitive_header_presence_changed",
                    left={"present": left_present},
                    right={"present": right_present},
                    authz_relevant=True,
                    sensitive=True,
                )
            )
    for name in sorted((left_keys | right_keys) - _STRUCTURAL_HEADERS):
        if name in left_headers and name not in right_headers:
            changes.append(
                _change(
                    f"/headers/{name}",
                    "header_removed",
                    left={"fingerprint": fingerprint(left_headers[name])},
                )
            )
        elif name in right_headers and name not in left_headers:
            changes.append(
                _change(
                    f"/headers/{name}",
                    "header_added",
                    right={"fingerprint": fingerprint(right_headers[name])},
                )
            )
        elif left_headers.get(name) != right_headers.get(name):
            changes.append(
                _change(
                    f"/headers/{name}",
                    "header_changed",
                    left={"fingerprint": fingerprint(left_headers[name])},
                    right={"fingerprint": fingerprint(right_headers[name])},
                )
            )


def _similarity(changes: list[dict[str, Any]], structural_equal: bool) -> str:
    if structural_equal:
        return "identical"
    authz = sum(1 for item in changes if item.get("authz_relevant"))
    if authz:
        return "low"
    kinds = {item["kind"] for item in changes}
    if (
        kinds <= {"array_reordered"}
        or kinds <= {"value_changed"}
        and all(not item.get("authz_relevant") for item in changes)
    ):
        # Pure volatile/reorder noise already filtered; remaining soft diffs.
        if len(changes) <= 3:
            return "high"
        return "medium"
    if any(
        item["kind"] in {"status_changed", "content_type_changed", "schema_changed", "type_changed"} for item in changes
    ):
        return "low"
    if len(changes) <= 5:
        return "medium"
    return "low"


def _behavioral_equivalence(
    left: dict[str, Any],
    right: dict[str, Any],
    changes: list[dict[str, Any]],
) -> bool:
    """Same status class + content-type family + schema shape. Not authorization."""

    def status_class(code: int | None) -> str:
        if code is None:
            return "missing"
        return f"{code // 100}xx"

    if status_class(left.get("status_code")) != status_class(right.get("status_code")):
        return False
    if left.get("content_type_family") != right.get("content_type_family"):
        return False
    blocking = {
        "schema_changed",
        "type_changed",
        "key_added",
        "key_removed",
        "content_type_changed",
        "status_changed",
        "location_changed",
        "body_kind_changed",
    }
    if any(item["kind"] in blocking and item.get("authz_relevant") for item in changes):
        return False
    # Presence of authz-relevant value changes means not behaviorally equivalent.
    if any(item.get("authz_relevant") and item["kind"] == "value_changed" for item in changes):
        return False
    return True


def diff_responses(
    left: StoredResponse | Mapping[str, Any],
    right: StoredResponse | Mapping[str, Any],
    *,
    ignore_volatile: Sequence[str] | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_html_tags: int = DEFAULT_MAX_HTML_TAGS,
    max_changes: int = DEFAULT_MAX_CHANGES,
) -> dict[str, Any]:
    """Compare two stored responses; return a minimized, shareable diff document.

    Never sends HTTP, never confirms findings, never hides authz-relevant fields.
    """
    left_resp = left if isinstance(left, StoredResponse) else StoredResponse.from_mapping(left)
    right_resp = right if isinstance(right, StoredResponse) else StoredResponse.from_mapping(right)
    limits = _Limits(
        max_body_bytes=max_body_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_html_tags=max_html_tags,
        max_changes=max_changes,
    )
    rules = tuple(ignore_volatile or ())
    left_headers = _normalize_headers(left_resp.headers)
    right_headers = _normalize_headers(right_resp.headers)
    left_model = _body_model(left_resp.body, left_headers.get("content-type", ""), limits)
    right_model = _body_model(right_resp.body, right_headers.get("content-type", ""), limits)

    changes: list[dict[str, Any]] = []
    normalizations: list[str] = []
    if rules:
        for rule in rules:
            normalizations.append(f"volatile_rule_registered:{rule}")

    # Status
    if left_resp.status_code != right_resp.status_code:
        changes.append(
            _change(
                "/status_code",
                "status_changed",
                left={"status_code": left_resp.status_code},
                right={"status_code": right_resp.status_code},
                authz_relevant=True,
            )
        )

    # Content-Type
    left_ct = left_headers.get("content-type", "")
    right_ct = right_headers.get("content-type", "")
    if (
        _content_type_family(left_ct) != _content_type_family(right_ct)
        or left_ct.split(";")[0].strip().lower() != right_ct.split(";")[0].strip().lower()
    ):
        changes.append(
            _change(
                "/headers/content-type",
                "content_type_changed",
                left={"fingerprint": fingerprint(left_ct), "family": _content_type_family(left_ct)},
                right={"fingerprint": fingerprint(right_ct), "family": _content_type_family(right_ct)},
                authz_relevant=True,
            )
        )

    # Location
    left_loc = left_headers.get("location")
    right_loc = right_headers.get("location")
    if left_loc != right_loc:
        changes.append(
            _change(
                "/headers/location",
                "location_changed",
                left={
                    "present": left_loc is not None,
                    "fingerprint": fingerprint(left_loc) if left_loc is not None else None,
                },
                right={
                    "present": right_loc is not None,
                    "fingerprint": fingerprint(right_loc) if right_loc is not None else None,
                },
                authz_relevant=True,
            )
        )

    # Content-Length declared vs observed (per side) and cross-side observed.
    for label, headers, model in (("left", left_headers, left_model), ("right", right_headers, right_model)):
        declared = headers.get("content-length")
        if declared is not None:
            try:
                declared_n = int(declared.strip())
            except ValueError:
                declared_n = -1
            if declared_n != model["byte_length"]:
                changes.append(
                    _change(
                        f"/{label}/content-length",
                        "content_length_mismatch",
                        left={"declared": declared_n, "observed": model["byte_length"]} if label == "left" else None,
                        right={"declared": declared_n, "observed": model["byte_length"]} if label == "right" else None,
                        note=label,
                    )
                )
    if left_model["byte_length"] != right_model["byte_length"]:
        changes.append(
            _change(
                "/body/byte_length",
                "body_length_changed",
                left={"byte_length": left_model["byte_length"]},
                right={"byte_length": right_model["byte_length"]},
            )
        )

    _header_changes(left_headers, right_headers, changes)

    if left_model["kind"] != right_model["kind"]:
        changes.append(
            _change(
                "/body",
                "body_kind_changed",
                left={"kind": left_model["kind"]},
                right={"kind": right_model["kind"]},
                authz_relevant=True,
            )
        )
    elif left_model["kind"] == "json":
        _diff_json_trees(
            left_model.get("tree"),
            right_model.get("tree"),
            rules=rules,
            normalizations=normalizations,
            changes=changes,
            limits=limits,
        )
        for side, model in (("left", left_model), ("right", right_model)):
            if model.get("json_error"):
                changes.append(
                    _change(
                        f"/body/{side}",
                        "json_parse_issue",
                        note=str(model["json_error"]),
                    )
                )
    elif left_model["kind"] == "html":
        left_html = left_model.get("html") or {}
        right_html = right_model.get("html") or {}
        if left_html.get("fingerprint") != right_html.get("fingerprint"):
            changes.append(
                _change(
                    "/body/html",
                    "html_structure_changed",
                    left={
                        "fingerprint": left_html.get("fingerprint"),
                        "tag_count": left_html.get("tag_count"),
                        "truncated": left_html.get("truncated", False),
                    },
                    right={
                        "fingerprint": right_html.get("fingerprint"),
                        "tag_count": right_html.get("tag_count"),
                        "truncated": right_html.get("truncated", False),
                    },
                    authz_relevant=True,
                    note="html_treated_as_data_no_js",
                )
            )
    else:
        if left_model.get("body_fingerprint") != right_model.get("body_fingerprint"):
            changes.append(
                _change(
                    "/body",
                    "opaque_body_changed",
                    left={
                        "fingerprint": left_model.get("body_fingerprint"),
                        "markers": left_model.get("text_markers") or [],
                    },
                    right={
                        "fingerprint": right_model.get("body_fingerprint"),
                        "markers": right_model.get("text_markers") or [],
                    },
                )
            )

    truncated_output = len(changes) >= limits.max_changes
    if len(changes) > limits.max_changes:
        changes = changes[: limits.max_changes]

    left_side = _side_summary(left_resp, left_model, left_headers)
    right_side = _side_summary(right_resp, right_model, right_headers)
    structural_equality = len(changes) == 0 and not truncated_output
    # Ignoring volatiles can yield structural equality after normalization.
    similarity = _similarity(changes, structural_equality)
    behavioral = _behavioral_equivalence(left_side, right_side, changes)

    summary = {
        "change_count": len(changes),
        "authz_relevant_changes": sum(1 for item in changes if item.get("authz_relevant")),
        "sensitive_changes": sum(1 for item in changes if item.get("sensitive")),
        "added_keys": sum(1 for item in changes if item["kind"] == "key_added"),
        "removed_keys": sum(1 for item in changes if item["kind"] == "key_removed"),
        "type_changes": sum(1 for item in changes if item["kind"] == "type_changed"),
        "value_changes": sum(1 for item in changes if item["kind"] == "value_changed"),
        "array_reorders": sum(1 for item in changes if item["kind"] == "array_reordered"),
        "volatile_ignored": sum(1 for item in normalizations if item.startswith("ignore_")),
        "output_truncated": truncated_output,
        "body_truncated": bool(left_model["truncated"] or right_model["truncated"]),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "structural_equality": structural_equality,
        "similarity": similarity,
        "behavioral_equivalence": behavioral,
        "normalizations_applied": normalizations,
        "limits": {
            "max_body_bytes": limits.max_body_bytes,
            "max_depth": limits.max_depth,
            "max_nodes": limits.max_nodes,
            "max_html_tags": limits.max_html_tags,
            "max_changes": limits.max_changes,
        },
        "left": left_side,
        "right": right_side,
        "changes": changes,
        "summary": summary,
        # Explicit non-verdict fields — never auto-confirm.
        "confirmed": False,
        "finding_confirmed": False,
        "vulnerability_verdict": None,
        "notes": [
            "Structural equality is not authorized access.",
            "Behavioral equivalence is not a vulnerability verdict.",
            "Denial classification authority remains analysis.authorization_denial (PR #52).",
            "Reflected identifiers are fingerprints only and are not proof.",
        ],
    }


def naive_baseline_diff(
    left: StoredResponse | Mapping[str, Any],
    right: StoredResponse | Mapping[str, Any],
) -> dict[str, Any]:
    """Phase-0 baseline: status + content-type + exact body equality only."""
    left_resp = left if isinstance(left, StoredResponse) else StoredResponse.from_mapping(left)
    right_resp = right if isinstance(right, StoredResponse) else StoredResponse.from_mapping(right)
    left_headers = _normalize_headers(left_resp.headers)
    right_headers = _normalize_headers(right_resp.headers)
    status_equal = left_resp.status_code == right_resp.status_code
    ct_equal = (
        left_headers.get("content-type", "").split(";")[0].strip().lower()
        == right_headers.get("content-type", "").split(";")[0].strip().lower()
    )
    body_equal = left_resp.body == right_resp.body
    equal = status_equal and ct_equal and body_equal
    return {
        "schema_version": "bbtk-semantic-response-diff-baseline/1",
        "equal": equal,
        "status_equal": status_equal,
        "content_type_equal": ct_equal,
        "body_equal": body_equal,
        "reports_difference": not equal,
        "confirmed": False,
        "finding_confirmed": False,
        "vulnerability_verdict": None,
    }


__all__ = [
    "SCHEMA_VERSION",
    "SENSITIVE_HEADERS",
    "StoredResponse",
    "diff_responses",
    "fingerprint",
    "is_protected_key",
    "is_sensitive_key",
    "json_type_name",
    "naive_baseline_diff",
]
