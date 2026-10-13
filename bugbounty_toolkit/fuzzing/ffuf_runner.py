from __future__ import annotations

import shutil
import subprocess
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..core.records import RecordStore
from ..core.scope_validator import ScopeValidator
from ..core.target import normalize_url
from ..core.redaction import redact_url, redact_data
from ..reporting.evidence import utc_stamp, write_evidence_json
from ..utils.exceptions import ExternalToolError
from .results_parser import parse_ffuf_results
from .wordlist_loader import require_wordlist


@dataclass(frozen=True)
class FfufOptions:
    url: str
    wordlist: Path
    threads: int = 5
    timeout: int = 10
    rate: int = 1
    match_codes: str | None = "200,204,301,302,307,401,403"
    filter_size: str | None = None


class FfufRunner:
    def __init__(self, store: RecordStore, scope: ScopeValidator):
        self.store = store
        self.scope = scope

    def run(self, options: FfufOptions) -> tuple[Path, list[dict[str, object]]]:
        wordlist = self.validate(options)
        if shutil.which("ffuf") is None:
            raise ExternalToolError("Required tool not found in PATH: ffuf")

        timestamp = utc_stamp()
        output_path = self.store.paths.raw_dir / f"{timestamp}-ffuf.json"
        log_path = self.store.paths.raw_dir / f"{timestamp}-ffuf.log"
        command = [
            "ffuf",
            "-u",
            normalize_url(options.url),
            "-w",
            str(wordlist),
            "-of",
            "json",
            "-o",
            str(output_path),
            "-t",
            str(options.threads),
            "-timeout",
            str(options.timeout),
            "-rate", str(options.rate),
            "-noninteractive", "-ic", "-r=false", "-recursion=false", "-ac=false",
            "-X", "GET",
        ]
        if options.match_codes:
            command.extend(["-mc", options.match_codes])
        if options.filter_size:
            command.extend(["-fs", options.filter_size])

        # Isolate ffuf from a user's ffufrc, which can enable redirects, recursion or extra inputs.
        config_dir = self.store.paths.raw_dir / f"{timestamp}-ffuf-config"
        config_dir.mkdir()
        environment = dict(os.environ, XDG_CONFIG_HOME=str(config_dir.resolve()))
        with log_path.open("w", encoding="utf-8") as output:
            process = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, text=True, check=False, env=environment)

        recorded_command = [redact_url(item) if item.startswith(("http://", "https://")) else item for item in command]
        if process.returncode != 0:
            self.store.add_run("ffuf", redact_url(options.url), recorded_command, process.returncode, output_path)
            raise ExternalToolError(f"ffuf exited with code {process.returncode}. See {log_path}")
        results = redact_data(parse_ffuf_results(output_path))
        evidence = write_evidence_json(self.store.paths.evidence_dir / "fuzzing", {
            "type": "ffuf", "raw_output": str(output_path), "log": str(log_path), "results": results,
        }, "ffuf")
        self.store.add_run("ffuf", redact_url(options.url), recorded_command, process.returncode, evidence)
        return evidence, results

    def validate(self, options: FfufOptions) -> Path:
        url = normalize_url(options.url)
        parsed = urlsplit(url)
        if "FUZZ" in parsed.netloc or "FUZZ" not in parsed.path + parsed.query:
            raise ValueError("Use FUZZ in the path or query of a fixed authorized host.")
        if min(options.threads, options.timeout, options.rate) <= 0:
            raise ValueError("Threads, timeout and rate must be positive.")
        wordlist = require_wordlist(options.wordlist).resolve()
        count = 0
        with wordlist.open(encoding="utf-8-sig") as handle:
            for line in handle:
                value = line.rstrip("\r\n")
                if not value or value.startswith("#"):
                    continue
                self.scope.require(normalize_url(url.replace("FUZZ", value)))
                count += 1
        if not count:
            raise ValueError("Wordlist has no usable entries.")
        return wordlist
