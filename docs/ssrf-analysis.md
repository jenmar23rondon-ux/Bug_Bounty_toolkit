# Offline SSRF analysis (stronger, candidate-only)

`analysis/ssrf_analysis.py` and `bbtk analyze ssrf` discover SSRF-prone
parameters in a local HAR/capture and emit **candidate** payload/test ideas.
They complement live `bbtk ssrf-check` (fixed five payloads + loopback canary
confirmation bar). Nothing here sends HTTP. `finding_confirmed` stays false.
Version stays 0.2.2.

## Usage

```bash
bbtk analyze ssrf \
  --input path/to/capture.har \
  --output reports/ssrf-plan.json \
  --markdown reports/ssrf-plan.md
```

## Parameter detection

Name heuristics across **query**, **form**, **JSON body**, **XML-ish tags**,
and selected headers (`X-Original-URL`, `X-Forwarded-Host`, …):

`url`, `uri`, `dest`, `redirect`, `fetch`, `image`, `webhook`, `callback`,
`proxy`, `host`, `domain`, `feed`, `xml`, `file`, …

## Candidate idea classes (not executed)

| Class | Examples | Notes |
| --- | --- | --- |
| internal_ip | 127.0.0.1, 10/8, 192.168/16, 172.16/12 | Candidate ideas only |
| cloud_metadata | 169.254.169.254 paths | Bodies never retained |
| localhost_variant | localhost, `::1`, 0.0.0.0 | |
| localhost_encoding | 127.1, decimal/hex, nip.io | |
| alt_scheme | gopher / file / dict | Often blocked |
| dns_rebinding | rebind.localtest.me | **manual-only** |
| blind_oob | collaborator placeholder | **manual-only** |

Live confirmation still requires `ssrf-check` with `lab_canary_hits` on a
loopback canary, or manual in-scope proof. DNS-rebinding and OOB are never
automated by this toolkit.

## Safety contract

- Offline only (`requests_sent` false)
- `finding_confirmed` stays false on the plan and every idea
- Secrets redacted via `core/redaction.py`
- Synthetic fixture: `tests/fixtures/ssrf_analysis.har`
