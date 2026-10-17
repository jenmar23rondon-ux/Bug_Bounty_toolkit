# One Controlled Permission Comparison

This is the manual fallback for requests that do not fit [native access-check](native-check.md). Prefer the native engine for a reviewed pair of GET/JSON controls with known private markers; it enforces the three-step comparison in one process. Do not silently adapt unsupported captures or automatically replay their write operations.

## Inputs

Record the program/policy, exact in-scope read, allowed automation, interval, total request budget, own test accounts/roles, known resource owner and whether that resource is private or intentionally shared. Use a harmless unique test marker already placed in the owner's resource when available. IDs for a user, basket, complaint and list are different identifiers: do not substitute one ID across unrelated endpoint types.

Keep A and B session material in separate local files under ignored `registros/<program>/`. For JSON APIs inspect the documented/captured application-success fields as well as HTTP status. Do not put secrets, ownership markers or response contents in command arguments. The executor supports raw HTTP text files; select/export the exact item from XML history first, not the whole history.

## Minimal Sequence

| Step | Session | Resource | Purpose |
| --- | --- | --- | --- |
| Owner control | B | B's own known private resource | Confirm the resource exists and normal read succeeds |
| Actor control | A | A's own analogous resource | Confirm the actor session and endpoint work |
| Crossed read | A | The same B resource | Compare with the expected denied permission |

Validate both controls before sending the cross. The owner can instead be A with B as actor; labels are not privileges. For a vertical test, use the authorized privileged account/resource as owner control and the low-privilege account as actor. An admin's normal success is not a bypass.

An unauthenticated comparison is a separate requested row: remove all authentication carriers, including authorization headers, cookies and any session query/body fields. Do not label a replay unauthenticated if a fallback credential remains. A new shared/public-resource read is a separate control if intentional sharing is unclear.

Change only the intended identity or resource reference, not multiple unrelated fields. Replace the complete acting session context, including session-bound CSRF/signature fields; never combine an owner's bearer token with an actor's cookie. If a fresh signature cannot be obtained within the existing plan, stop as inconclusive rather than bypassing it. Compare the effective parsed request, not just a raw-file diff.

## Replays And Timing

Dry-run each selected request before execution:

```bash
bugbounty request my-program --raw-request registros/my-program/private/owner-control.http --base-url "https://authorized.example" --rate 0.1 --dry-run
```

Set `--base-url` to the capture's actual authorized scheme, host and port, not the example origin above. A relative raw request with only a Host header otherwise defaults to HTTPS; an HTTP lab needs its original `http://localhost:<port>` origin. Do not silently change protocol or redirect a captured session to another host.

Execute the individual request only within the user's existing authorization, inspect its result, wait the required interval, and then prepare the next step. `--rate 0.1` limits a running client's cadence but does NOT insert a ten-second wait between fresh CLI processes. Use a wait tool or explicit sleep for the remaining interval between invocations; respect a stricter program rate. Count every live request, including controls and separately authorized repetitions. No automatic retries or automatic inverse cross are part of this workflow.

GET/HEAD can still trigger actions: verify endpoint semantics. Read-only POST can be used only after its exact operation/body is reviewed as a read. Do not replay arbitrary captured POST/PUT/PATCH/DELETE, change roles, modify carts, reset accounts or delete resources as part of this read comparison.

## Evidence And Verdict

Record `step | actor | resource-owner | expected | HTTP | application-success | verdict | evidence-path`. Keep headers, token values, private IDs and actual personal contents local/redacted. Raw files and redaction are best effort; inspect before sharing.

- `candidate`: both controls are valid, the actor should be denied and the cross returns attributable private resource data. Stop with the minimum evidence, not further data collection. Confirmation requires reviewing intended sharing, resource ownership, permissions and any permitted reproducibility check.
- `rejected_in_this_test`: valid controls followed by a denial/no private resource. A crossed 401/403 is expected negative evidence, not proof that the baseline actor session was invalid. Do not claim all access control is secure.
- `inconclusive`: invalid controls, ambiguous success semantics/ownership, redirects, truncation, anti-automation response or network failure. Do not attribute an undocumented application code to session expiry or authorization enforcement.

HTTP 200 containing an email can be reflected input, public metadata or cached/template text. Neither it nor identical bodies/lengths prove IDOR. Distinct responses alone do not prove enforcement. The executor's `body_preview` is redacted and capped at 8000 characters even when `body_truncated` is false; that flag describes the transport capture limit, not the preview limit. A marker missing from a preview is not proof that the complete response lacks it. Use existing complete local evidence when available, otherwise report that comparison as inconclusive without resending automatically. Preserve uncertainty and do not infer the unsent inverse test.
