from __future__ import annotations

from pathlib import Path

from ..core.http_client import HttpClient, RequestSpec, ResponseRecord
from ..core.request_builder import build_request, parse_raw_http_request
from ..core.scope_validator import ScopeValidator
from ..reporting.evidence import write_evidence_json
from .headers import parse_cookie_items, parse_header_items
from .parameters import parse_parameter_items
from .response_analyzer import analyze_response


class RequestReplayer:
    def __init__(self, scope: ScopeValidator, client: HttpClient):
        self.scope = scope
        self.client = client

    def from_raw_file(self, raw_path: Path, base_url: str | None = None) -> RequestSpec:
        spec = parse_raw_http_request(raw_path.read_text(encoding="utf-8"), base_url=base_url)
        self.scope.require(spec.url)
        return spec

    def from_cli(
        self,
        url: str,
        method: str = "GET",
        headers: list[str] | None = None,
        cookies: list[str] | None = None,
        params: list[str] | None = None,
        body: str | None = None,
    ) -> RequestSpec:
        parsed_headers = parse_header_items(headers)
        cookie_header = parse_cookie_items(cookies)
        if cookie_header:
            parsed_headers["Cookie"] = cookie_header
        spec = build_request(
            url=url,
            method=method,
            headers=parsed_headers,
            params=parse_parameter_items(params),
            body=body,
        )
        self.scope.require(spec.url)
        return spec

    def send_and_save(
        self, spec: RequestSpec, destination: Path, markers: list[str] | None = None
    ) -> tuple[ResponseRecord, Path]:
        self.scope.require(spec.prepared_url())
        record = self.client.send(spec)
        evidence = {
            "type": "http_request",
            "analysis": analyze_response(record, markers=markers),
            "exchange": record.to_dict(),
        }
        path = write_evidence_json(destination, evidence, prefix="request")
        return record, path
