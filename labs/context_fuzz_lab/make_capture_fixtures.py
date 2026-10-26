"""Deterministically derive Burp XML and raw HTTP fixtures from the synthetic lab HAR.

Offline only. The output represents exactly the same exchanges (method, origin, path,
query, headers, status, body) as ``fixtures/capture.har`` so planner parity can be tested.
Run: python labs/context_fuzz_lab/make_capture_fixtures.py
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import urlsplit

LAB = Path(__file__).resolve().parent
FIXTURES = LAB / "fixtures"


def _request_text(entry: dict) -> str:
    request = entry["request"]
    parts = urlsplit(request["url"])
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    headers = [f"Host: {parts.netloc}"]
    headers += [f"{row['name']}: {row['value']}" for row in request.get("headers", [])]
    body = (request.get("postData") or {}).get("text", "")
    return f"{request['method']} {target} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body


def _response_text(entry: dict) -> str:
    response = entry["response"]
    content = response.get("content", {})
    body = content.get("text", "")
    headers = [f"{row['name']}: {row['value']}" for row in response.get("headers", [])]
    if not any(line.lower().startswith("content-type:") for line in headers) and content.get("mimeType"):
        headers.append(f"Content-Type: {content['mimeType']}")
    headers.append(f"Content-Length: {len(body.encode('utf-8'))}")
    reason = "OK" if response["status"] == 200 else "Unauthorized"
    return f"HTTP/1.1 {response['status']} {reason}\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body


def build() -> dict[str, bytes]:
    har = json.loads((FIXTURES / "capture.har").read_text(encoding="utf-8"))
    entries = har["log"]["entries"]
    items = []
    outputs: dict[str, bytes] = {}
    for index, entry in enumerate(entries):
        parts = urlsplit(entry["request"]["url"])
        req, resp = _request_text(entry), _response_text(entry)
        items.append(
            "  <item>\n"
            f"    <url><![CDATA[{entry['request']['url']}]]></url>\n"
            f"    <host>{parts.hostname}</host>\n    <port>{parts.port}</port>\n"
            f"    <protocol>{parts.scheme}</protocol>\n    <method>{entry['request']['method']}</method>\n"
            f'    <request base64="true">{base64.b64encode(req.encode()).decode()}</request>\n'
            f"    <status>{entry['response']['status']}</status>\n"
            f'    <response base64="true">{base64.b64encode(resp.encode()).decode()}</response>\n'
            "  </item>\n"
        )
        outputs[f"raw/{index:02d}.request.http"] = req.encode()
        outputs[f"raw/{index:02d}.response.http"] = resp.encode()
    xml = '<?xml version="1.0"?>\n<items burpVersion="synthetic-lab">\n' + "".join(items) + "</items>\n"
    outputs["capture.burp.xml"] = xml.encode()
    return outputs


def main() -> None:
    for name, data in build().items():
        target = FIXTURES / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


if __name__ == "__main__":
    main()
