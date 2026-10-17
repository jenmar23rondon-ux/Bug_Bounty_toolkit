from __future__ import annotations

from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from ..core.http_client import NoRedirects
from .comparison import AccessCase, AccessControlTester, load_case
from .guards import is_loopback_url


class AccessWriteLabTester(AccessControlTester):
    def validate(self, case_file: Path, max_tests: int = 3) -> AccessCase:
        if type(max_tests) is not int or max_tests < 3:
            raise ValueError("Three requests must fit: owner write, actor write, then one crossed lab write.")
        case = load_case(case_file, self.scope, allow_lab_writes=True)
        if case.mode != "lab-write":
            raise ValueError("Use a declared JSON body resource pointer for lab write checks.")
        if not all(is_loopback_url(request.prepared_url()) for request in (case.owner, case.actor, case.cross)):
            raise ValueError("Automated write comparisons are restricted to localhost or loopback IPs.")
        return case

    def run(self, case_file: Path, evidence_dir: Path, max_tests: int = 3):
        self.validate(case_file, max_tests)
        if hasattr(self.client, "opener"):
            self.client.opener = build_opener(ProxyHandler({}), NoRedirects())
        return super().run(case_file, evidence_dir, max_tests)
