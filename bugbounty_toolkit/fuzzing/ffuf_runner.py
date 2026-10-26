from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..core.http_client import HttpClient, RequestSpec
from ..core.records import RecordStore
from ..core.redaction import redact_data, redact_url
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..reporting.evidence import utc_stamp, write_evidence_json
from ..utils.exceptions import ExternalToolError
from .results_parser import build_authorization_followups, classify_ffuf_results, parse_ffuf_results
from .wordlist_loader import require_wordlist
from .wordlist_manager import _parsed_lines


@dataclass(frozen=True)
class FfufOptions:
    url: str
    wordlist: Path
    threads: int = 5
    timeout: int = 10
    rate: int = 1
    match_codes: str | None = "200,204,301,302,307,401,403"
    filter_size: str | None = None
    max_entries: int = 100
    max_seconds: float = 120.0


@dataclass(frozen=True)
class _PreparedInputs:
    path: Path
    entries: tuple[str, ...]
    prepared_sha256: str
    source_size_bytes: int
    source_mtime_ns: int


class FfufRunner:
    def __init__(self, store: RecordStore, scope: ScopeValidator, client: HttpClient | None = None):
        self.store = store
        self.scope = scope
        self.client = client

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _usable_entries(path: Path, limit: int) -> tuple[str, ...]:
        selected: list[str] = []
        seen: set[str] = set()
        for parsed in _parsed_lines(path):
            if parsed.value is None or parsed.invalid or parsed.value in seen:
                continue
            seen.add(parsed.value)
            selected.append(parsed.value)
            if len(selected) >= limit:
                break
        return tuple(selected)

    def preview_entries(self, options: FfufOptions) -> tuple[str, ...]:
        """Return capped, deduplicated inputs after checking each generated URL."""
        url = normalize_url(options.url)
        parsed = urlsplit(url)
        if "FUZZ" in parsed.netloc or "FUZZ" not in parsed.path + parsed.query:
            raise ValueError("Use FUZZ in the path or query of a fixed authorized host.")
        if min(options.threads, options.timeout, options.rate, options.max_entries) <= 0 or options.max_seconds <= 0:
            raise ValueError("Threads, timeout, rate, entry cap and maximum duration must be positive.")
        if options.threads > 64 or options.max_entries > 1_000_000:
            raise ValueError("ffuf threads are capped at 64 and maximum entries at 1,000,000.")
        wordlist = require_wordlist(options.wordlist).resolve()
        entries = self._usable_entries(wordlist, options.max_entries)
        if not entries:
            raise ValueError("Wordlist has no usable entries.")
        for value in entries:
            self.scope.require(normalize_url(url.replace("FUZZ", value)))
        baseline_url = normalize_url(url.replace("FUZZ", f".__bbtk_baseline_{uuid.uuid4().hex}__"))
        self.scope.require(baseline_url)
        return entries

    def validate(self, options: FfufOptions) -> Path:
        """Validate target, limits, and every destination in the capped input set."""
        self.preview_entries(options)
        return require_wordlist(options.wordlist).resolve()

    def _prepare_inputs(self, source: Path, destination: Path, limit: int) -> _PreparedInputs:
        entries = self._usable_entries(source, limit)
        if not entries:
            raise ValueError("Wordlist has no usable entries.")
        destination.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
        stat = source.stat()
        return _PreparedInputs(destination, entries, self._sha256(destination), stat.st_size, stat.st_mtime_ns)

    def _baseline(self, options: FfufOptions) -> dict[str, object] | None:
        if self.client is None:
            return None
        marker = f".__bbtk_baseline_{uuid.uuid4().hex}__"
        url = normalize_url(options.url.replace("FUZZ", marker))
        response = self.client.send(RequestSpec("GET", url))
        body = response.body_text
        return {
            "status": response.status_code,
            "length": response.body_size,
            "words": len(re.findall(r"\S+", body)),
            "lines": len(body.splitlines()),
            "content_type": response.headers.get("content-type", "")[:200],
            "redirectlocation": response.headers.get("location", "")[:8192],
            "body_truncated": bool(getattr(response, "body_truncated", False)),
            "duration_ms": response.duration_ms,
            "probe_path": urlsplit(url).path,
        }

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
        from ..core.secure_subprocess import kill_process_tree

        kill_process_tree(process)  # type: ignore[arg-type]

    def _run_process(self, command: list[str], environment: dict[str, str], log_path: Path, max_seconds: float) -> int:
        """Launch ffuf through the shared secure subprocess contract (no shell)."""
        from ..core.secure_subprocess import (
            CODE_TIMEOUT,
            PolicyRejected,
            SecureSubprocessError,
            SecureToolLimits,
            SecureToolRequest,
            run_secure_subprocess,
        )

        if not command or Path(command[0]).name != "ffuf":
            raise ExternalToolError("[policy_executable_not_allowed] ffuf runner only executes the ffuf binary.")
        roots = (self.store.paths.program_dir.resolve(),)
        # Temporary wordlist dirs are created under raw_dir; also allow the process cwd temp.
        request = SecureToolRequest(
            executable_name="ffuf",
            argv=tuple(command),
            output_path=log_path,
            limits=SecureToolLimits(
                timeout_seconds=float(max_seconds),
                max_output_bytes=50_000_000,
                max_output_file_bytes=50_000_000,
            ),
            env=environment,
            allowed_path_roots=roots,
            contact_external=True,
            authorization_attested=True,
            scope_attested=True,
            budget_attested=True,
        )
        try:
            result = run_secure_subprocess(request)
        except PolicyRejected as exc:
            raise ExternalToolError(str(exc)) from exc
        except SecureSubprocessError as exc:
            if exc.code == CODE_TIMEOUT:
                raise ExternalToolError(
                    f"ffuf exceeded its {max_seconds:g}s wall-clock limit and was stopped."
                ) from exc
            raise ExternalToolError(str(exc)) from exc
        except KeyboardInterrupt:
            raise
        return result.returncode

    def run(self, options: FfufOptions) -> tuple[Path, list[dict[str, object]]]:
        wordlist = self.validate(options)
        if shutil.which("ffuf") is None:
            raise ExternalToolError("Required tool not found in PATH: ffuf")

        timestamp = utc_stamp()
        output_path = self.store.paths.raw_dir / f"{timestamp}-ffuf.json"
        log_path = self.store.paths.raw_dir / f"{timestamp}-ffuf.log"
        baseline = self._baseline(options)
        if baseline is not None and baseline.get("status") == 429:
            evidence = write_evidence_json(
                self.store.paths.evidence_dir / "fuzzing",
                {
                    "type": "ffuf",
                    "status": "stopped_rate_limited_baseline",
                    "raw_output": None,
                    "baseline": baseline,
                    "results": [],
                    "followup_candidates": [],
                    "limits": {"planned_requests_upper_bound": 1, "ffuf_requests_observed": None},
                },
                "ffuf",
            )
            self.store.add_run("ffuf", redact_url(options.url), ["ffuf", "baseline-rate-limited"], 0, evidence)
            return evidence, []

        with tempfile.TemporaryDirectory(prefix="bbtk-ffuf-input-", dir=self.store.paths.raw_dir) as temporary:
            prepared = self._prepare_inputs(wordlist, Path(temporary) / "selected.txt", options.max_entries)
            command = [
                "ffuf",
                "-u",
                normalize_url(options.url),
                "-w",
                str(prepared.path),
                "-of",
                "json",
                "-o",
                str(output_path),
                "-t",
                str(options.threads),
                "-timeout",
                str(options.timeout),
                "-rate",
                str(options.rate),
                "-maxtime",
                str(max(1, int(options.max_seconds))),
                "-noninteractive",
                "-ic",
                "-r=false",
                "-recursion=false",
                "-ac=false",
                "-X",
                "GET",
            ]
            if options.match_codes:
                command.extend(["-mc", options.match_codes])
            if options.filter_size:
                command.extend(["-fs", options.filter_size])

            config_dir = Path(temporary) / "config"
            config_dir.mkdir()
            environment = dict(os.environ, XDG_CONFIG_HOME=str(config_dir.resolve()))
            try:
                run_timeout = options.max_seconds
                client_budget = getattr(self.client, "execution_budget", None)
                if client_budget is not None:
                    remaining = client_budget.remaining_seconds()
                    if remaining is not None:
                        run_timeout = min(run_timeout, remaining)
                if run_timeout <= 0:
                    raise ExternalToolError("Run time budget expired before ffuf could start.")
                return_code = self._run_process(command, environment, log_path, run_timeout)
            except ExternalToolError:
                self.store.add_run(
                    "ffuf",
                    redact_url(options.url),
                    ["ffuf", "supervised"],
                    124,
                    output_path if output_path.exists() else log_path,
                )
                raise
            if return_code != 0:
                self.store.add_run("ffuf", redact_url(options.url), ["ffuf", "supervised"], return_code, output_path)
                raise ExternalToolError(f"ffuf exited with code {return_code}. See {log_path}")
            raw_results = parse_ffuf_results(output_path)
            results = classify_ffuf_results(raw_results, baseline)
            followups = build_authorization_followups(results)
            safe_results = redact_data(results)
            evidence = write_evidence_json(
                self.store.paths.evidence_dir / "fuzzing",
                {
                    "type": "ffuf",
                    "raw_output": str(output_path),
                    "log": str(log_path),
                    "wordlist": str(wordlist),
                    "source_wordlist_size_bytes": prepared.source_size_bytes,
                    "source_wordlist_mtime_ns": prepared.source_mtime_ns,
                    "selected_wordlist_sha256": prepared.prepared_sha256,
                    "selected_entries": len(prepared.entries),
                    "baseline": baseline,
                    "results": safe_results,
                    "response_groups": self._response_group_summary(results),
                    "followup_candidates": followups,
                    "limits": {
                        "max_entries": options.max_entries,
                        "max_seconds": options.max_seconds,
                        "rate_per_second": options.rate,
                        "concurrency": options.threads,
                        "planned_requests_upper_bound": len(prepared.entries) + int(baseline is not None),
                        "ffuf_requests_observed": None,
                    },
                    "interpretation": "Discovery signals only; no vulnerability is confirmed by status code.",
                },
                "ffuf",
            )
            recorded_command = [
                "ffuf",
                "-u",
                redact_url(options.url),
                "-w",
                str(wordlist),
                "-rate",
                str(options.rate),
                "-t",
                str(options.threads),
                "-timeout",
                str(options.timeout),
                "-maxtime",
                str(max(1, int(options.max_seconds))),
                "-r=false",
                "-recursion=false",
            ]
            self.store.add_run("ffuf", redact_url(options.url), recorded_command, return_code, evidence)
            return evidence, safe_results

    @staticmethod
    def _response_group_summary(results: list[dict[str, object]]) -> list[dict[str, object]]:
        groups: dict[str, dict[str, object]] = {}
        for result in results:
            group_id = result.get("response_group")
            if not isinstance(group_id, str):
                continue
            current = groups.setdefault(
                group_id,
                {
                    "response_group": group_id,
                    "status": result.get("status"),
                    "length": result.get("length"),
                    "words": result.get("words"),
                    "lines": result.get("lines"),
                    "classification": result.get("classification"),
                    "count": 0,
                },
            )
            current["count"] = int(current["count"]) + 1
        return sorted(groups.values(), key=lambda row: str(row["response_group"]))
