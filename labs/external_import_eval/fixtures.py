"""Synthetic Nuclei, ZAP, FFUF and SQLMap artifacts for the external-import eval.

Every host is 127.0.0.1. Nothing here is a real report or a runnable scanner.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from bugbounty_toolkit.analysis.external_importers import MAX_EXTERNAL_BYTES

HOST = "127.0.0.1:9"
ORIGIN = f"http://{HOST}"


@dataclass(frozen=True)
class Gold:
    source_file: str
    record_index: int
    status: str
    tool: str
    vulnerability_class: str | None


@dataclass(frozen=True)
class Case:
    name: str
    path: Path
    gold: tuple[Gold, ...]
    diagnostics: tuple[tuple[str, int | None], ...]
    fatal: str | None
    legacy_format: str
    false_positive: bool = False
    tool: str | None = None


def _request(path: str, extra: str = "") -> str:
    return f"GET {ORIGIN}{path} HTTP/1.1\r\nHost: {HOST}\r\n{extra}\r\n"


def _response(body: str) -> str:
    return f"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nContent-Length: {len(body.encode())}\r\n\r\n{body}"


def _nuclei(
    template: str, path: str, severity: str, tags: list[str], body: str | None, **extra: object
) -> dict[str, object]:
    row: dict[str, object] = {
        "template-id": template,
        "matched-at": f"{ORIGIN}{path}",
        "info": {"name": template, "severity": severity, "tags": tags},
        **extra,
    }
    if body is not None:
        row["request"] = _request(path)
        row["response"] = _response(body)
    return row


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def build_cases(root: Path) -> tuple[Case, ...]:
    """Write the eval inputs under ``root`` and return their gold labels."""
    cases: list[Case] = []

    clean = root / "nuclei-clean.jsonl"
    _write(clean, json.dumps(_nuclei("synthetic-reflection", "/search", "low", ["xss"], "welcome")) + "\n")
    cases.append(
        Case(
            "nuclei-clean",
            clean,
            (Gold(clean.name, 1, "candidate", "nuclei", "cross_site_scripting"),),
            (),
            None,
            "nuclei-jsonl",
        )
    )

    critical = root / "nuclei-critical.jsonl"
    row = _nuclei("synthetic-critical", "/welcome", "critical", ["xss"], "welcome", access_confirmed=True)
    row["classification"] = "confirmed"
    row["vulnerabilities_confirmed"] = 5
    _write(critical, json.dumps(row) + "\n")
    cases.append(
        Case(
            "nuclei-critical-false-positive",
            critical,
            (Gold(critical.name, 1, "candidate", "nuclei", "cross_site_scripting"),),
            (),
            None,
            "nuclei-jsonl",
            True,
        )
    )

    bare = root / "nuclei-bare.jsonl"
    _write(bare, json.dumps(_nuclei("synthetic-critical-bare", "/welcome", "critical", ["xss"], None)) + "\n")
    cases.append(
        Case(
            "nuclei-critical-no-evidence",
            bare,
            (Gold(bare.name, 1, "needs_review", "nuclei", "cross_site_scripting"),),
            (),
            None,
            "nuclei-jsonl",
            True,
        )
    )

    siblings = root / "nuclei-siblings.jsonl"
    _write(
        siblings,
        "\n".join(
            (
                json.dumps(_nuclei("synthetic-reflection", "/search", "low", ["xss"], "welcome")),
                '{"template-id":',
                json.dumps(_nuclei("synthetic-exposure", "/health", "info", ["exposure"], "ok")),
            )
        )
        + "\n",
    )
    cases.append(
        Case(
            "nuclei-siblings",
            siblings,
            (
                Gold(siblings.name, 1, "candidate", "nuclei", "cross_site_scripting"),
                Gold(siblings.name, 3, "candidate", "nuclei", "information_exposure"),
            ),
            (("malformed_json", 2),),
            None,
            "nuclei-jsonl",
        )
    )

    array_path = root / "nuclei-array.json"
    array_path.write_bytes(
        json.dumps(
            [
                _nuclei("synthetic-reflection", "/search", "low", ["xss"], "welcome"),
                "not-a-record",
                _nuclei("synthetic-exposure", "/health", "info", ["exposure"], "ok"),
            ]
        ).encode()
    )
    cases.append(
        Case(
            "nuclei-array-siblings",
            array_path,
            (
                Gold(array_path.name, 1, "candidate", "nuclei", "cross_site_scripting"),
                Gold(array_path.name, 3, "candidate", "nuclei", "information_exposure"),
            ),
            (("record_not_object", 2),),
            None,
            "nuclei-json",
        )
    )

    empty = root / "nuclei-empty.jsonl"
    empty.write_bytes(b"")
    cases.append(Case("nuclei-empty", empty, (), (("empty_input", None),), "empty_input", "nuclei-jsonl"))

    truncated = root / "nuclei-truncated.json"
    _write(truncated, '{"template-id": "synthetic-reflection"')
    cases.append(Case("nuclei-truncated", truncated, (), (("malformed_json", None),), "malformed_json", "nuclei-json"))

    unknown = root / "nuclei-unknown-version.json"
    unknown_row = _nuclei("synthetic-reflection", "/search", "low", ["xss"], "welcome")
    unknown_row["nuclei-version"] = "9.9.9"
    _write(unknown, json.dumps(unknown_row))
    cases.append(
        Case(
            "nuclei-unknown-version",
            unknown,
            (Gold(unknown.name, 1, "needs_review", "nuclei", "cross_site_scripting"),),
            (("unknown_version", None),),
            None,
            "nuclei-json",
        )
    )

    cookies = root / "nuclei-cookies.jsonl"
    cookie_row = _nuclei("synthetic-reflection", "/search", "low", ["xss"], "welcome")
    cookie_row["request"] = _request("/search", "Cookie: a=alpha-secret-value\r\nCookie: a=beta-secret-value\r\n")
    _write(cookies, json.dumps(cookie_row) + "\n")
    cases.append(
        Case(
            "nuclei-contradictory-session",
            cookies,
            (Gold(cookies.name, 1, "abstain", "nuclei", "cross_site_scripting"),),
            (("ambiguous_session", 1),),
            None,
            "nuclei-jsonl",
        )
    )

    zap_clean = root / "zap-clean.json"
    _write(
        zap_clean,
        json.dumps(
            {
                "@version": "2.14.0",
                "site": [
                    {
                        "@name": ORIGIN,
                        "alerts": [
                            {
                                "alert": "Cross Site Scripting (Reflected)",
                                "riskcode": "3",
                                "cweid": "79",
                                "instances": [
                                    {
                                        "uri": f"{ORIGIN}/search?q=1",
                                        "method": "GET",
                                        "param": "q",
                                        "request-header": _request("/search?q=1").split("\r\n\r\n", 1)[0],
                                        "request-body": "",
                                        "response-header": _response("welcome").split("\r\n\r\n", 1)[0],
                                        "response-body": "welcome",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
    )
    cases.append(
        Case(
            "zap-json-clean",
            zap_clean,
            (Gold(zap_clean.name, 1, "candidate", "zap", "cross_site_scripting"),),
            (),
            None,
            "auto",
        )
    )

    zap_bare = root / "zap-high.json"
    _write(
        zap_bare,
        json.dumps(
            {
                "@version": "2.14.0",
                "site": [
                    {
                        "alerts": [
                            {
                                "alert": "SQL Injection",
                                "riskcode": "3",
                                "instances": [{"uri": f"{ORIGIN}/item?id=1", "method": "GET", "param": "id"}],
                            }
                        ]
                    }
                ],
            }
        ),
    )
    cases.append(
        Case(
            "zap-high-no-evidence",
            zap_bare,
            (Gold(zap_bare.name, 1, "needs_review", "zap", "sql_injection"),),
            (),
            None,
            "auto",
            True,
        )
    )

    zap_siblings = root / "zap-siblings.json"
    _write(
        zap_siblings,
        json.dumps(
            {
                "@version": "2.14.0",
                "site": [
                    {
                        "alerts": [
                            {
                                "alert": "Cross Site Scripting (Reflected)",
                                "riskcode": "2",
                                "instances": [
                                    {
                                        "uri": f"{ORIGIN}/search?q=1",
                                        "method": "GET",
                                        "request-header": _request("/search?q=1").split("\r\n\r\n", 1)[0],
                                        "request-body": "",
                                        "response-header": _response("welcome").split("\r\n\r\n", 1)[0],
                                        "response-body": "welcome",
                                    }
                                ],
                            },
                            {"pluginid": "0"},
                        ]
                    }
                ],
            }
        ),
    )
    cases.append(
        Case(
            "zap-siblings",
            zap_siblings,
            (Gold(zap_siblings.name, 1, "candidate", "zap", "cross_site_scripting"),),
            (("record_missing_identity", 2),),
            None,
            "auto",
        )
    )

    zap_xml = root / "zap-clean.xml"
    request_header = _request("/search?q=1").split("\r\n\r\n", 1)[0]
    response_header = _response("welcome").split("\r\n\r\n", 1)[0]
    _write(
        zap_xml,
        '<OWASPZAPReport version="2.14.0"><site name="http://127.0.0.1:9"><alerts><alertitem>'
        "<alert>Cross Site Scripting (Reflected)</alert><name>Cross Site Scripting (Reflected)</name>"
        "<riskcode>3</riskcode><cweid>79</cweid><instances><instance>"
        "<uri>http://127.0.0.1:9/search?q=1</uri><method>GET</method><param>q</param>"
        f"<requestheader>{request_header}</requestheader><requestbody></requestbody>"
        f"<responseheader>{response_header}</responseheader><responsebody>welcome</responsebody>"
        "</instance></instances></alertitem></alerts></site></OWASPZAPReport>\n",
    )
    cases.append(
        Case(
            "zap-xml-clean",
            zap_xml,
            (Gold(zap_xml.name, 1, "candidate", "zap", "cross_site_scripting"),),
            (),
            None,
            "auto",
        )
    )

    dtd = root / "zap-dtd.xml"
    _write(
        dtd,
        """<!DOCTYPE zap [<!ENTITY leak "ENTITY-LEAK-MARKER">]>
<OWASPZAPReport version="2.14.0"><site name="http://127.0.0.1:9"><alerts>
<alertitem><alert>&leak;</alert></alertitem></alerts></site></OWASPZAPReport>
""",
    )
    cases.append(Case("zap-dtd", dtd, (), (("xml_dtd_forbidden", None),), "xml_dtd_forbidden", "auto"))

    broken_xml = root / "zap-truncated.xml"
    _write(broken_xml, '<OWASPZAPReport version="2.14.0"><site>')
    cases.append(Case("zap-truncated", broken_xml, (), (("malformed_xml", None),), "malformed_xml", "auto"))

    zap_version = root / "zap-version.json"
    _write(
        zap_version,
        json.dumps(
            {
                "@version": "3.0.0",
                "site": [
                    {
                        "alerts": [
                            {
                                "alert": "Cross Site Scripting (Reflected)",
                                "riskcode": "3",
                                "instances": [
                                    {
                                        "uri": f"{ORIGIN}/search?q=1",
                                        "method": "GET",
                                        "request-header": _request("/search?q=1").split("\r\n\r\n", 1)[0],
                                        "request-body": "",
                                        "response-header": _response("welcome").split("\r\n\r\n", 1)[0],
                                        "response-body": "welcome",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ),
    )
    cases.append(
        Case(
            "zap-unknown-version",
            zap_version,
            (Gold(zap_version.name, 1, "needs_review", "zap", "cross_site_scripting"),),
            (("unknown_version", None),),
            None,
            "auto",
        )
    )

    ffuf = root / "ffuf.json"
    _write(
        ffuf,
        json.dumps(
            {
                "commandline": "ffuf",
                "config": {"version": "2.1.0"},
                "results": [{"url": f"{ORIGIN}/admin", "status": 200, "length": 5, "input": {"FUZZ": "admin"}}],
            }
        ),
    )
    cases.append(
        Case(
            "ffuf-clean",
            ffuf,
            (Gold(ffuf.name, 1, "candidate", "ffuf", "content_discovery"),),
            (),
            None,
            "ffuf-json",
        )
    )

    ffuf_bad = root / "ffuf-siblings.json"
    _write(
        ffuf_bad,
        json.dumps(
            {
                "results": [
                    {"url": f"{ORIGIN}/admin", "status": 200, "length": 5, "input": {"FUZZ": "admin"}},
                    "not-a-row",
                    {"status": 200},
                ]
            }
        ),
    )
    cases.append(
        Case(
            "ffuf-siblings",
            ffuf_bad,
            (Gold(ffuf_bad.name, 1, "candidate", "ffuf", "content_discovery"),),
            (("record_not_object", 2), ("record_missing_identity", 3)),
            None,
            "ffuf-json",
        )
    )

    ffuf_csv = root / "ffuf.csv"
    _write(
        ffuf_csv,
        "FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines\n"
        f"admin,{ORIGIN}/admin,,1,200,5,1,1\n"
        "broken,only-three\n",
    )
    cases.append(
        Case(
            "ffuf-csv",
            ffuf_csv,
            (Gold(ffuf_csv.name, 2, "candidate", "ffuf", "content_discovery"),),
            (("malformed_csv", 3),),
            None,
            "csv",
        )
    )

    ffuf_empty = root / "ffuf-empty.json"
    _write(ffuf_empty, json.dumps({"commandline": "ffuf", "results": []}))
    cases.append(Case("ffuf-empty", ffuf_empty, (), (("empty_results", None),), None, "ffuf-json"))

    ffuf_version = root / "ffuf-version.json"
    _write(
        ffuf_version,
        json.dumps(
            {
                "version": "9.0",
                "results": [{"url": f"{ORIGIN}/admin", "status": 200, "length": 5}],
            }
        ),
    )
    cases.append(
        Case(
            "ffuf-unknown-version",
            ffuf_version,
            (Gold(ffuf_version.name, 1, "needs_review", "ffuf", "content_discovery"),),
            (("unknown_version", None),),
            None,
            "ffuf-json",
        )
    )

    log = root / "sqlmap.log"
    _write(
        log,
        "sqlmap/1.8.4#stable\n"
        "[10:00:01] [INFO] testing URL 'http://127.0.0.1:9/item?id=1'\n"
        "[10:00:02] [INFO] GET parameter 'id' appears to be 'boolean-based blind' injectable\n"
        "[10:00:03] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others?\n"
        "[10:00:04] [WARNING] GET parameter 'q' does not appear to be injectable\n"
        "[10:00:05] [INFO] GET parameter 'id' appears to be\n",
    )
    cases.append(
        Case(
            "sqlmap-log",
            log,
            (
                Gold(log.name, 3, "needs_review", "sqlmap", "sql_injection"),
                Gold(log.name, 4, "needs_review", "sqlmap", "sql_injection"),
                Gold(log.name, 5, "abstain", "sqlmap", None),
            ),
            (("log_claim_unparsed", 6),),
            None,
            "auto",
            True,
            "sqlmap",
        )
    )

    sql_csv = root / "sqlmap-results.csv"
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["target", "place", "parameter", "technique", "payload", "request", "response"])
    writer.writerow(
        [
            f"{ORIGIN}/item?id=1",
            "GET",
            "id",
            "boolean-based blind",
            "payload-must-not-be-copied",
            _request("/item?id=1"),
            _response("ok"),
        ]
    )
    _write(sql_csv, buffer.getvalue())
    cases.append(
        Case(
            "sqlmap-csv-false-positive",
            sql_csv,
            (Gold(sql_csv.name, 2, "candidate", "sqlmap", "sql_injection"),),
            (("payload_column_omitted", None),),
            None,
            "auto",
            True,
            "sqlmap",
        )
    )

    version_log = root / "sqlmap-v2.log"
    _write(
        version_log,
        "sqlmap/2.0.0#stable\n[10:00:01] [INFO] GET parameter 'id' appears to be 'boolean-based blind' injectable\n",
    )
    cases.append(
        Case(
            "sqlmap-unknown-version",
            version_log,
            (Gold(version_log.name, 2, "needs_review", "sqlmap", "sql_injection"),),
            (("unknown_version", None),),
            None,
            "auto",
            True,
            "sqlmap",
        )
    )

    output = root / "sqlmap-output"
    output.mkdir()
    _write(output / "target.txt", f"{ORIGIN}/item?id=1\n")
    _write(
        output / "log",
        "sqlmap/1.8.4#stable\n[10:00:01] [INFO] GET parameter 'id' appears to be 'boolean-based blind' injectable\n",
    )
    _write(
        output / "results.csv",
        f"target,place,parameter,technique\n{ORIGIN}/item?id=1,GET,id,boolean-based blind\n",
    )
    connection = sqlite3.connect(output / "session.sqlite")
    connection.execute("create table storage (id integer primary key, value blob)")
    connection.execute("insert into storage (value) values (?)", (b"\x80\x04not-unpickled",))
    connection.commit()
    connection.close()
    (output / "dump").mkdir()
    _write(output / "dump" / "users.csv", "id,name\n1,secret-dump-row\n")
    cases.append(
        Case(
            "sqlmap-directory",
            output,
            (
                Gold("log", 2, "needs_review", "sqlmap", "sql_injection"),
                Gold("results.csv", 2, "needs_review", "sqlmap", "sql_injection"),
            ),
            (("session_pickle_refused", None), ("sqlmap_dump_skipped", None)),
            None,
            "auto",
            True,
            "sqlmap",
        )
    )

    unknown_text = root / "notes.txt"
    _write(unknown_text, "hello from a local note\n")
    cases.append(Case("unknown-text", unknown_text, (), (("unknown_format", None),), "unknown_format", "auto"))

    nul = root / "nul.bin"
    nul.write_bytes(b"a\x00b")
    cases.append(Case("nul-bytes", nul, (), (("nul_rejected", None),), "nul_rejected", "auto"))

    encoding = root / "bad-encoding.bin"
    encoding.write_bytes(b"\xff\xfe\xfa")
    cases.append(Case("encoding-invalid", encoding, (), (("encoding_invalid", None),), "encoding_invalid", "auto"))

    oversized = root / "oversized.jsonl"
    descriptor = os.open(oversized, os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.truncate(descriptor, MAX_EXTERNAL_BYTES + 1)
    finally:
        os.close(descriptor)
    cases.append(Case("oversized", oversized, (), (("oversized_input", None),), "oversized_input", "nuclei-jsonl"))
    return tuple(cases)
