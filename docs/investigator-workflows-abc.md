# Workflows A, B, and C

These workflows are the chain measured by
`labs/investigator_workflow_efficacy/`. Expected dispositions were written into
`dev/cases.json`, `final/cases.json`, and `stress/cases.json` from the lab
server behavior, before the bbtk arm was scored. They are fixture labels for
this lab only. They do not replace IRB, security-research v2, or any other
FINAL set.

## Shared chain

1. **Scope** — literal `127.0.0.1` only.
2. **Lab** — stdlib server bound to loopback. It refuses any other bind.
3. **Capture** — proxy-less `urllib` GET. A socket guard counts non-loopback connects and blocks them.
4. **Import** — keep the response bytes and a sha256 of the body.
5. **Integrity** — the hash is the evidence id for the dossier draft.
6. **Discovery** — manual checklist or an unchanged bbtk function.
7. **Candidates** — disposition `review`, `reject`, or `abstain`. Never `confirmed`.
8. **Negative controls** — 403, escaped HTML, shared/public visibility, documentation paths, and duplicate bodies.
9. **Deterministic eval** — the same function on the same bytes. No model calls.
10. **Evidence review** — minimized JSON (status codes and body hash, no marker values).
11. **Contradictions** — the manual checklist abstains when a body says `contradiction: denied`. The lineage function does not read that string; the stress case records the difference instead of changing the function.
12. **Dossier** — `verify_research_dossier` on a candidate ledger row.
13. **Report draft** — recommendation text only.
14. **Human review** — `build_workflow` leaves `control_review` without a reviewer, so the graph stops at `requires_human_review`.
15. **Finish/reject** — not executed. The ledger state stays `candidate`.

## A — IDOR/BOLA

Owner and actor synthetic bearers (`SYNTH_OWNER_TOKEN`, `SYNTH_ACTOR_TOKEN`)
request the same lab id. A cross-account 200 that repeats the owner marker on a
private object is a review candidate. 403 is a negative control. `public` or
`shared` visibility is a legitimate share. HTTP 500 is abstain.

## B — Reflected and DOM XSS

Reflected cases send `q=<marker>`. Live `<` in HTML text is a review candidate.
`html.escape` output is a negative control. A truncated response is abstain.
DOM cases are static source: `location.hash` assigned to `innerHTML` is a sink
candidate. `textContent` without `innerHTML` is a negative control for the
manual checklist. Browser execution is `NOT_MEASURED`. An HTML comment that
says to ignore instructions does not change the disposition and must not
confirm a finding.

## C — Disclosure with audience

The response carries `X-BBTK-Audience` and `X-BBTK-Path` because the capture
records who received the bytes. A public password-shaped field is a review
candidate. `/docs/` examples are negative controls. The caller's own password
field is a negative control for the manual checklist. Truncation and HTTP 204
are abstain. The public canary `BBTK_CANARY_IWE_STRESS01` is a review
candidate whose value must not appear in shareable output.

## Real-world

See `labs/investigator_workflow_efficacy/real_world/PROTOCOL.md`. Opt-in,
private, anonymized aggregates only, never started by the evaluator.
