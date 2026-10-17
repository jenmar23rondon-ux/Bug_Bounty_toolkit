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

`path_segment` is zero-based after the initial slash: `/api/items/B` uses index 2. Alternatively use `"resource": {"query_parameter": "id"}` for `/api/item?id=B` vs `id=A`. Both requests must differ only in this declared URL resource reference, apart from their headers. Duplicate query names, session-bearing queries and request bodies are unsupported. All session carrier headers must be listed and present in both contexts, including Cookie/CSRF/signature headers when used. The two contexts must differ; the actor's full header set replaces the owner's, not just one token.

Check locations use [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901), including `~0`/`~1` escapes and array indices. A control requires HTTP 200, exact typed success value, its expected resource and its expected private marker, without the other account's marker. Resource IDs and private markers are separate checks. Proof markers must be different 12-128 character ASCII identifier strings and must NOT occur in either outgoing request; an email/ID reflected from input is not proof. The executor does not create resources or plant markers. If valid known private proof is unavailable, use a reviewed manual check, not invented values or assertions.

## Run One Case

```bash
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3 --dry-run
bugbounty access-check my-program --case-file registros/my-program/private/case.json --rate 0.1 --max-tests 3
```

After the user's actual authorization covers the run, the non-dry invocation sends at most three requests, in this order: B's normal read, A's normal read, A's session reading B's resource. One client enforces the policy/user rate across the whole group. Failing a control stops after one or two requests; the cross is not sent. There are no retries, redirects, inverse cross, anonymous requests, ID enumeration or write operations. A budget below three is rejected before traffic.

The complete response is analyzed in memory up to the configured capture limit. Truncation, transport failure, redirects and 429 stop the test as inconclusive. A crossed 401/403 or application failure with no configured private evidence is `rejected_in_this_test`; undocumented error codes are not attributed to a cause. Both owner resource and private marker in the cross produce `candidate`, including a leak hidden behind an error status. Partial private evidence or unfamiliar success schema is inconclusive, not secure. A successful process is not necessarily a successful comparison; read the evidence.

Saved evidence contains step labels, HTTP codes, durations, truncation and predicate booleans, not session headers, URLs, IDs, proof values or response previews. It is minimized evidence, not a raw traffic capture. Keep original local case/captures if manual validation is needed. No finding is automatically confirmed or submitted. Review ownership, intentional sharing and expected permissions; an explicitly permitted repeat is a new budgeted run, not an automatic follow-up.

The shared JSON plan adapter accepts `action: "access-check"`, `case_file`, and optional `rate`, `timeout`, `max_tests`. It does not accept inline cookies/headers for this action. Its plan paths are relative to the toolkit checkout; capture paths inside the case remain relative to the case.
