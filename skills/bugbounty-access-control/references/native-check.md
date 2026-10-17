# Native Known-Resource A/B Check

`access-check` uses the toolkit HttpClient, not nuclei/ffuf. It is a single controlled comparison, not discovery or an authorization oracle. It needs the actual program's policy, scope, automation allowance and reviewed read semantics. A GET can have side effects; validate its meaning first.

## Private Inputs

Keep the case and separate account captures under ignored `registros/<program>/private/`. Paths in the case are relative to that case file. This synthetic example assumes two own private JSON items, both normally readable, with different controlled private proof values already present in them:

```json
{
  "owner_request": "owner.http",
  "actor_request": "actor.http",
  "base_url": "http://localhost:3000",
  "session_headers": ["Authorization"],
  "resource": {"path_segment": 2},
  "accounts_authorized": true,
  "resource_private": true,
  "expected_cross_access": "deny",
  "checks": {
    "success_pointer": "/success",
    "success_value": true,
    "resource_pointer": "/data/id",
    "owner_resource": "B",
    "actor_resource": "A",
    "private_pointer": "/data/proof",
    "owner_marker": "owned-B-proof-7e2519",
    "actor_marker": "owned-A-proof-6f4308"
  }
}
```

`owner.http` is the exact captured `GET /api/items/B` with B's session; `actor.http` is `GET /api/items/A` with A's session. Both have the real captured Host. Do not paste actual tokens into chat, examples or command arguments. `base_url` must preserve that origin's scheme, host and port; host overrides are rejected. The engine sets `Accept-Encoding: identity` in all three requests because the standard client does not decompress gzip/br captures. A server that ignores that request may yield an invalid control, not evidence of protection. Unencodable/control-character headers are rejected before any sends.

`path_segment` is zero-based after the initial slash: `/api/items/B` uses index 2. Alternatively use `"resource": {"query_parameter": "id"}` for `/api/item?id=B` vs `id=A`. Both requests must differ only in this declared URL resource reference, apart from their headers. Duplicate query names, session-bearing queries and request bodies are unsupported. All session carrier headers must be listed and present in both contexts, including Cookie/CSRF/signature headers when used. The two contexts must differ; the actor's full header set replaces the owner's, not just one token. Different session strings alone do not prove distinct principals: the user must associate the captures with their actual accounts and intended resource ownership, and candidate review must validate that mapping.

Check locations use [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901), including `~0`/`~1` escapes and array indices. A control requires HTTP 200, exact typed success value, its expected resource and its expected private marker, without the other account's marker. Resource IDs and private markers are separate checks. Proof markers must be different 12-128 character ASCII identifier strings and must NOT occur in either outgoing request; an email/ID reflected from input is not proof. The executor does not create resources or plant markers. If valid known private proof is unavailable, use a reviewed manual check, not invented values or assertions.

## Run One Case

```bash
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3
```

After the user's actual authorization covers the run, the non-dry invocation sends at most three requests, in this order: B's normal read, A's normal read, A's session reading B's resource. One client enforces the policy/user rate across the whole group. Failing a control stops after one or two requests; the cross is not sent. There are no retries, redirects, inverse cross, anonymous requests or write operations. A budget below three is rejected before traffic.

## Optional Numeric Range

Use range mode only if the actual program policy explicitly permits identifier enumeration and the interval contains known disposable/test-account resources. Add `"identifier_enumeration_authorized": true` to the private case only after checking that policy; the CLI refuses `--range` if the field is missing or not the boolean `true`. This is an explicit researcher attestation, not an independent policy lookup.

When the response exposes a stable test-account identity field, the private case may include `identity_check` with a JSON pointer and A's known value, for example `{"identity_check":{"pointer":"/data/account_id","actor_value":"test-account-A"}}`. Keep that value in the ignored private case; evidence records only whether the returned identity differed.

```bash
bugbounty access-check my-program --case-file registros/my-program/private/case.json --range 1-10 --max-tests 12 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --range 1-10 --max-tests 12
```

The configurable cap defaults to 25 IDs and can be lowered with `--max-range`. Non-loopback runs without an opt-in cannot raise that cap, use concurrency, or reduce the default ten-second interval. `--allow-public-range` opts in to up to 100 IDs, four workers and a one-second minimum interval; it prints `[!] Public range relaxed: more requests than default`. Set `--max-range`, `--max-tests`, concurrency and interval deliberately; the budget includes both controls. If all controls and generated destinations are loopback, a local lab may set `--max-range` up to 100, `--concurrency` up to 4, and `--min-interval` down to 0.01 seconds without the public flag. For example, `--range 1-30 --max-range 30 --max-tests 32 --concurrency 4 --min-interval 0.01` is allowed only when the private case and scope resolve entirely to localhost/loopback. The two normal controls run first, and every generated URL is preflighted against scope. Workers submit bounded windows; after a stop signal, already-started requests may finish and are recorded as not evaluated. No value outside the supplied interval is tried. Dry-run sends nothing.

Evidence stores the candidate's zero-based offset, status and predicate booleans, but no probed ID, URL, response body or private value. Map the offset to the original local interval when needed. A range candidate is only a triage signal (for example, a returned resource or configured identity differs from the actor); it does not require the private proof marker used by the single crossed-read check and never confirms IDOR. Verify account ownership, intentional sharing and program rules manually before drawing a conclusion. A fully rejected interval is still only a result for that test.

## Loopback Write Lab

Writes are disabled in the default access-check. `--lab-write` accepts only matched JSON `POST`, `PUT` or `PATCH` captures whose URLs match, whose bodies differ only at `resource.json_body_pointer`, and whose case sets `disposable_test_resources: true`. The selected values must match `checks.owner_resource` and `checks.actor_resource`. The engine rebuilds the actor JSON tree, changes only that pointer to the owner's known ID, and uses the actor's complete captured headers. It first validates both control responses, then makes one crossed request. By default all destinations must be localhost or a loopback IP; proxy use is disabled for loopback.

Public writes are an explicit opt-in: add `--allow-public-writes` to `--lab-write`. The flag has no effect on read or range modes and is rejected without `--lab-write`. The CLI prints `[!] Public writes enabled: requests may modify remote state`. It relaxes only the loopback guard; scope, same-origin, same-method, valid JSON, disposable-resource and control checks remain enforced. A public write can persistently change remote state, including during the two control writes, so only use resources that are genuinely disposable and only if the user's authorization and the program's automation rules explicitly permit state-changing tests. The case's `disposable_test_resources: true` is an attestation, not authorization verification.

`--lab-write-range START-END` is an advanced mode requiring `--lab-write`, `identifier_enumeration_authorized: true`, matching JSON POST/PUT/PATCH captures and disposable resources. It validates the owner and actor write controls, then submits actor-session writes with each ID inserted at the declared JSON pointer. It stops after a candidate or error; already-started requests in the current concurrency window may still complete. Request budgets include the two controls. Public write ranges require `--allow-public-writes`; relaxing public sweep limits additionally requires `--allow-public-range`. Without that second flag, public ranges remain capped at 25 IDs, sequential and at least ten seconds apart. With it, the maximum is 100 IDs, four workers and a one-second minimum, with a warning. Each successful control or probe may mutate state; plan cleanup and inspect the disposable resources afterward. No inverse request or retry is sent.

Example case fragment: `"resource": {"json_body_pointer": "/mutation/item/id"}` and `"disposable_test_resources": true`. Keep the captured JSON bodies in the ignored private case files; do not place credentials inline in a plan or command.

The complete response is analyzed in memory up to the configured capture limit. Truncation, transport failure, redirects and 429 stop the test as inconclusive. A crossed 401/403 or application failure with no configured private evidence is `rejected_in_this_test`; undocumented error codes are not attributed to a cause. Both owner resource and private marker in the cross produce `candidate`, including a leak hidden behind an error status. Partial private evidence or unfamiliar success schema is inconclusive, not secure. A successful process is not necessarily a successful comparison; read the evidence.

Saved evidence contains step labels, HTTP codes, durations, truncation and predicate booleans, not session headers, URLs, IDs, proof values or response previews. It is minimized evidence, not a raw traffic capture. Keep original local case/captures if manual validation is needed. No finding is automatically confirmed or submitted. Review ownership, intentional sharing and expected permissions; an explicitly permitted repeat is a new budgeted run, not an automatic follow-up.

The shared JSON plan adapter accepts `action: "access-check"`, `case_file`, optional `range`, `max_range`, `concurrency`, `min_interval`, `rate`, `timeout` and `max_tests`. It does not accept inline cookies/headers or write modes/public opt-ins; use the direct CLI for `--lab-write` and `--lab-write-range`. Plan paths are relative to the toolkit checkout; capture paths inside the case remain relative to the case.
