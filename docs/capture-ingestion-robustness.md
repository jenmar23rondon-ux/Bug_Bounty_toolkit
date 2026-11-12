# Capture ingestion robustness

First increment of the evidence-intelligence program. This change makes incomplete,
malformed and mixed local captures parse without aborting the whole file and without
inventing fields. It does not import Nuclei, ZAP, FFUF or SQLMap into a hypothesis
schema, and it does not rank which hypothesis to review. Those are later PRs.

Offline only. No third-party traffic, no new runtime dependency, version stays `0.2.2`.

## Audit

Base: `main` after PR #111 (`3ad3f6a`, authorization status lines for textual HTTP/2
and HTTP/3). The audit in `docs/advanced-research-audit.md` asked for the input
contract between capture import, handoff and authorization. The strict replay parser,
HAR per-entry isolation, pairing gates and the confirmation bar already work and are
unchanged for clean HTTP/1.1 captures.

Concrete contract gaps on that base:

| Contract | What disagreed |
|---|---|
| HTTP version | Authorization accepts textual `HTTP/1.0`, `HTTP/1.1`, `HTTP/2` and `HTTP/3` status lines. Discovery (`parse_captured_exchanges`) still required `HTTP/1.x` and raised, so a file with one HTTP/2 item never reached the status parser from PR #111. The evidence raw parser accepted `HTTP/2` with a looser status regex than authorization. |
| Whole-file failure | HAR already isolates a bad entry. Burp and raw discovery raised on the first bad message and dropped every sibling. |
| Duplicate headers | Request replay raises. Response discovery raises on duplicate framing headers. Evidence and the authorization parser otherwise keep one value (last-wins, except Location which is first-wins). The same two `Location` values were `/login` for authorization and `/home` for evidence. Two `Cookie` values collapsed to one session. |
| Encoding | Discovery rejected non-identity `Content-Encoding`. HAR base64 had to be UTF-8 or the entry was dropped. Invalid base64 became an empty body on the evidence HAR path (`errors="replace"` / empty string). `charset` was ignored. `gzip` bytes were not decoded. |
| Missing response | HAR rejected the entry (`response_missing`) and, when it was the only entry, rejected the file. A missing response was not distinguished from an empty body once a record was emitted. |
| Contradictory status | A Burp `<status>` element that disagreed with the response line was ignored. A `Content-Length` that disagreed with the body still classified as `possible_access`. |
| Confirmation | `possible_access` is not confirmation (`access_confirmed` stays false). Ambiguous framing could still raise that outcome. |

## What this PR changes

`bugbounty_toolkit/analysis/capture_ingestion.py` (`bbtk.capture-ingestion/1`) parses
HAR, Burp XML and textual HTTP into exchanges plus enumerated diagnostics. It does
not raise for malformed content. Unknown fields stay unknown.

- Textual `HTTP/2` and `HTTP/3` request and status lines use the same version and
  100–599 token rules as authorization. This is not a binary frame decoder.
  HAR `httpVersion` `HTTP/2.0` / `h2` is recorded as the `HTTP/2` alias and does
  not by itself lower confidence.
- One bad Burp item no longer discards its siblings. Object discovery still uses
  the strict HTTP/1.1 importer for a file that importer accepts. It falls back
  only when that importer raises.
- Disagreeing `Cookie`, `Authorization`, `Location`, `Content-Type`,
  `Content-Encoding` or `Content-Length` values are kept on the exchange and omitted
  from the single-value map. Session state becomes `ambiguous`. Identical duplicates
  are a warning only.
- `gzip` and `deflate` decode when the bytes are valid. `base64` decodes only when
  declared. `charset` is honored when it is a known codec and the bytes decode.
  Failures leave the body unset. `br` is reported as `content_encoding_br_undecoded`
  and is not decoded (no new dependency).
- A missing response stays a request with `response_missing`. No status or body is
  synthesized. Relative targets are not given an `https` scheme.
- A Burp status element that disagrees with the status line clears the status
  (`contradictory_status`). `Content-Length` must match the wire body or the
  exchange is `partial`.
- `assess_pair_authorization` now lowers `possible_access` when either capture is
  not `observed`, and lowers a login-redirect denial when `Location` values
  disagree. Clean captures keep the previous outcome. Nothing sets
  `access_confirmed` or `vulnerabilities_confirmed`.

The strict replay parser (`parse_raw_http_request`, `parse_captured_exchanges`)
still refuses to build a replayable request from HTTP/2, duplicate headers or a
broken content length.

## Independent evaluation

`python -m labs.capture_ingestion_eval.evaluate`

21 parse cases and 14 authorization cases, all synthetic and separate from the
frozen DEV (6), FINAL (45) and STRESS (6) corpora. The legacy arm is the strict
importers plus the uncapped classifier. Review-time proxy is unitless: 30 for an
unstructured crash, 25 for a false `possible_access`, 20 for a silent header
choice, 15 for a dropped recoverable exchange, 5 for an explained file refusal,
2 for an explained partial, 1 for a clean accept.

| Metric | Before | After |
|---|---:|---:|
| Parse success | 0.1429 | 1.0 |
| Diagnostic rate | 0.0769 | 1.0 |
| Authorization precision (`possible_access`) | 0.25 | 1.0 |
| Authorization recall | 0.5 | 1.0 |
| False `possible_access` | 3 | 0 |
| Authorization accuracy | 0.5714 | 1.0 |
| Review-time proxy | 488 | 57 |

`possible_access` remains an unconfirmed hypothesis. These figures are not a
real-world detection rate.

Frozen DEV / FINAL / STRESS captures, labels and `MANIFEST.sha256` are not edited.
Pairing precision and recall stay 1.0 and forbidden pairs stay 0 on those splits.
FINAL outcome accuracy stays 0.9111. The new cases were not used to change those
labels.

## Limitations

- Not an HTTP/2 or HTTP/3 frame decoder. `:authority` is not turned into `Host`.
- `Content-Encoding: br` is diagnosed, not inflated.
- Evidence import of a clean textual message still uses the historical parser, so
  a legacy record is unchanged. Ambiguous and compressed messages use this contract
  for the record body and `validation_status`. The signed HAR `capture_import`
  account is unchanged.
- Authorization on the original wire bytes does not upgrade a gzip body into
  `possible_access`. Call `assess_ingested_pair` to assess the decoded body.
  A mismatched `Content-Length` or disagreeing sensitive header cannot raise
  `possible_access` on either path.
- A wholly unreadable file (bad XML, DTD, empty input, HAR file-fatal codes,
  size limit) is still refused. DTD and entities are not expanded.
- Object discovery still caps exchanges and does not confirm IDOR/BOLA.

## Proposed next PR

Offline importers for Nuclei, ZAP, FFUF and SQLMap structured results into one
schema: `origin`, `evidence`, `hypothesis`, `status`, `traceability`. Reuse the
existing Nuclei and FFUF row readers in `evidence_engine` rather than adding a
second parser. An external alert must be unable to land in `confirmed`; the
status machine should start at `candidate` or `needs_review`, and a missing
origin or contradictory evidence should abstain. The prioritization engine
(which hypothesis to open first, with an explanation and an abstain path) is the
PR after that, once this schema exists.
