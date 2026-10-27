# Optional passive Burp evidence bridge

This bridge transfers **manually selected, already captured** HTTP/1.x messages.
It has no listener, network client, scanner registration, replay, cookie substitution,
ID mutation, access-control execution or AI assessment. It does not change scope,
execution budgets, approvals, redaction, tool-policy gates or denial assessment.
Version remains 0.2.2. PR #52 is already present at the audited base.

## Install and use

1. Create an owner-only directory **outside every Git checkout** (`mkdir -m 700 /tmp/bbtk-private`).
2. In Burp's legacy Extender settings configure Jython 2.7, then load
   `labs/burp_passive_bridge_eval/extension/BurpExtender.py` as a Python extension.
   This is the legacy Extender API, not a Montoya extension. POSIX filesystem
   support is required; unsupported permissions/filesystems fail closed.
3. Select messages in Burp history/site map. Choose **bbtk: export selected privately**.
   Enter the authorized bbtk project slug and exact allowed origins. Both that
   selection and Burp's configured scope must permit the destination.
4. Review selected/unique/duplicate/rejected counts and explicitly authorize export.
   Choose a new absolute file under the private directory. Existing files are refused.
5. Import explicitly; the origin arguments are the human-selected **origin-only**
   allowlist for this import, not permission to execute anything:

   ```sh
   python -m bugbounty_toolkit.burp_passive_bridge /tmp/bbtk-private/selection.json \
     --project local-lab --origin https://lab.invalid \
     --attest-authorized-captures --report /tmp/bbtk-private/review.json \
     --private-bundle /tmp/bbtk-private/evidence.json
   ```

   Omit `--private-bundle` for a read-only preview. `--report` is also optional.
   Import repeats project, origin, authority, message framing and size checks using
   `burp_import.parse_captured_exchanges`. Rejected entries never become evidence.
   The optional normalized bundle uses `evidence_engine.import_evidence` on a transient
   private XML adapter. It never invokes assessment, correlation execution or testing.
   Inspect rejected inputs locally; diagnostics intentionally contain no capture text.

The bridge counts incomplete requests and unsupported responses as rejected. A complete
request **without** a response is accepted as request-only evidence, never as a successful
response. The export preview counts candidate entries; import can reject further HTTP
framing/content issues through the authoritative existing parser.

## Private file versus minimized report

The transfer file is **private evidence containing original credentials**, not a public
bridge payload or a report. Raw request/response bytes travel together as base64 in one
entry. Base64 is not encryption. Only the local private file crosses the Burp/bbtk boundary;
there is no public service or shareable capture export. Retain only when necessary,
restrict access and delete according to the investigation's retention policy.

The normalized bundle is also private: the existing redaction engine is reused unchanged,
but arbitrary URLs, content and provenance are not a guarantee of public safety. The
`--private-bundle` destination must also be outside Git in an owned 0700 directory.
The transient XML is 0600 in a 0700 directory and deleted after import, including errors.
It is not a second retained copy of the capture.

The **minimized report and console output** have a fixed allowlist of counts, schema,
review flag and zero network/confirmation counters. They contain no project names,
URLs, timestamps, headers, bodies, fingerprints, local paths or arbitrary strings.
They are intended for sharing; no heuristic redaction is needed to remove absent data.
Private API objects must not be logged or serialized into reports.

## Protocol bbtk.burp-passive/1

UTF-8 JSON envelope: exactly `payload` and `sha256`. Payload: exactly `schema`,
`project`, `entries`. Each entry: `origin` (HTTP(S) origin without credentials),
`timestamp` (timezone-aware ISO 8601 or null), `request` (strict base64),
`response` (strict base64 or null). Duplicate JSON keys and unsupported versions fail
closed. The digest is SHA-256 of payload JSON with sorted keys, ASCII escaping and
compact separators. It detects accidental changes/truncation; **it is not a signature
or proof that Burp produced the file**. A writer can recompute it. Import always
revalidates scope and messages even when the digest matches.

Stable locators are `burp-passive:<payload-sha256>#/entries/<zero-based-index>`.
They are stable for the exact transfer and preserve original indices across rejections.
Changing the transfer changes its digest. Locators identify an exported selection,
not a persistent Burp history database ID. All evidence provenance entries are remapped
after the existing importer runs, including merged provenance. No transient path survives.

Deduplication uses the complete origin/request/response tuple, including credentials,
so two accounts remain separate. Capture timestamps do not prevent deduplication;
the first selected occurrence's timestamp wins. Export stores unique messages once.
Repeated imports are stateless: outputs are exclusive and cannot overwrite; this is
not a global evidence database or cross-export deduplication service.

Limits: one file per manual export/import; 1–100 selected entries; 1,000,000 decoded
bytes per request/response; 16 MiB whole file. No automatic batch splitting or directory
watching. Source files must be owned regular 0600 files; private parent directories
must be owned 0700. Python publication reuses the secure no-follow, atomic private
file primitives. The Java extension requires POSIX permissions, rejects symlink
ancestors and Git paths, and publishes via an exclusive hard link; failure leaves no
partial destination. No Windows compatibility is claimed.

## Limitations and evidence

Burp itself was not installed in the evaluation environment. Tests use a mocked legacy
API and synthetic captures; a real Burp/Jython installation still needs a manual smoke
check. The legacy API does not supply capture timestamps on selected message objects:
the extension records null, never the export time. The simulated adapter preserves
provided capture timestamps. Requests/responses must be UTF-8, uncompressed HTTP/1.x
compatible with the existing importer; binary/non-UTF-8, HTTP/2-only framing, chunked
or compressed responses are explicitly rejected rather than silently transformed.

A compromised local exporter or another process under the same OS user is outside this
integrity model. The private directory must remain trusted during export. SHA-256
locators are private provenance and should not be posted as a secret-derived oracle.

See [evaluation](../labs/burp_passive_bridge_eval/README.md) for reproducible metrics,
measured baseline, adversarial corpus, quality checks and operator action counts.
