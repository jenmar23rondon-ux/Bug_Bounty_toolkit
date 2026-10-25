# IDOR/BOLA Playbook

Use this workflow only for assets explicitly in scope and accounts/resources you own or have written authorization to test. The toolkit compares supplied evidence; a `candidate` is not confirmation and reports are never submitted automatically.

## 1. Select a known resource endpoint

Choose a read-only GET endpoint that returns one private resource and contains a stable resource identifier, such as `/api/orders/12345`. Confirm the normal response using the resource owner's account. Prefer a resource with a harmless, unique marker already present, such as a test title or description. Do not create, edit, or delete data for a read comparison.

Check the program policy before using any ID range. A range is optional and should be small, contiguous, predictable, and limited to identifiers the program explicitly authorizes you to test. Start with the known owner's ID and only a few adjacent test IDs. Do not infer permission to enumerate from the fact that IDs are numeric.

## 2. Capture one request per account in Burp

Use two authorized test accounts, A (resource owner) and B (actor). In Burp, capture a GET from A to A's own resource, then a GET from B to B's own resource. Save each as a raw HTTP request. Keep the method, origin, path shape, non-session headers, and query parameters the same; only the resource identifier and account session should differ. Protect the captures as credentials and do not commit them.

## 3. Generate the private case offline

The example below assumes JSON responses with `success`, `data.id`, and a unique `data.marker`. Replace paths and markers with values confirmed in your own responses. The importer reads local files only and sends no requests:

```bash
bbtk import case my-program \
  --owner registros/my-program/private/captures/account-a.txt \
  --actor registros/my-program/private/captures/account-b.txt \
  --base-url https://target.example \
  --resource-pointer /data/id \
  --success-pointer /success --success-value true \
  --private-pointer /data/marker \
  --private-marker OWNER_MARKER_ALREADY_IN_A \
  --actor-marker ACTOR_MARKER_ALREADY_IN_B \
  --attest-authorized-accounts --attest-private-resource --dry-run
```

Review the redacted summary, then repeat without `--dry-run` to write `registros/my-program/private/case.json`. Existing files require `--force`. The case declares researcher attestations; the importer cannot prove account identity, response-pointer meaning, marker existence, or program authorization. Keep the generated case and raw requests private.

## 4. Run a known-resource comparison first

Before testing a range, validate the two owner controls and the single crossed read:

```bash
bbtk access-check my-program \
  --case-file registros/my-program/private/case.json \
  --max-tests 3 --dry-run
```

After reviewing the plan and confirming program policy, run the same command without `--dry-run`. Inspect the saved evidence. A `candidate` means the configured private-resource predicates matched in that response; it does not prove impact or establish a reportable vulnerability by itself.

## 5. Optional, explicitly authorized range

Range checks require a separate case declaration. Only after confirming that the program permits identifier enumeration, edit the private case file to add:

```json
"identifier_enumeration_authorized": true
```

Then select a narrow range that includes the known owner ID. Example for a program that explicitly allows this small interval:

```bash
bbtk access-check my-program \
  --case-file registros/my-program/private/case.json \
  --range 12345-12349 --max-range 5 --max-tests 7 \
  --min-interval 10 --concurrency 1 --dry-run
```

Review the exact scope and request budget. Remove `--dry-run` only after confirming the policy allows those specific IDs and the configured rate. Public targets remain capped at 25 IDs, one worker, and a ten-second minimum interval by default. `--allow-public-range` is an explicit higher-traffic opt-in; it allows up to 100 IDs, four workers and at least one second between starts. Do not use that opt-in unless the program explicitly permits it. The toolkit stops a range after a candidate, rate limit, transport problem, redirect, or truncated response.

## 6. Interpret the result

- `candidate`: the response matched the configured private-resource evidence. Reproduce it manually before reporting.
- `rejected_in_this_test`: the tested request was denied or the application reported failure under the configured predicates. This is limited to the supplied account, resource, and request.
- `inconclusive`: controls or response evidence were insufficient; it is neither proof of protection nor proof of a vulnerability.
- `public_endpoint`: the case explicitly declared the resource public; this is informational, not an IDOR finding.
- `anonymous_access`: an anonymous response matched private evidence under a case declaring the resource private. Validate the resource's intended access policy before treating it as a finding.

None of these labels is automatic confirmation. The toolkit does not infer business impact, test every role, or establish that the target is in scope.

## 7. Confirm manually in Burp

Use Repeater with the same captured request and change only the resource identifier from A's resource to the known test resource. Keep account B's session. Compare the status, response resource ID, and unique private marker against A's and B's normal controls. Re-run the same test once to rule out stale or cached data. Stop if the target returns 429, unexpected errors, or data outside the explicitly authorized test resources. Do not alter or delete another user's data.

## Final report checklist

- [ ] The exact host and endpoint are in the program's current scope.
- [ ] Program policy permits this test and any identifier range used.
- [ ] Both accounts and resources are authorized test fixtures.
- [ ] A and B controls returned their expected own-resource markers.
- [ ] The crossed result was reproduced manually in Burp with only the resource reference changed.
- [ ] Evidence is redacted and contains no cookies, bearer tokens, or unrelated user data.
- [ ] The report explains realistic impact, exact reproduction steps, and the control responses.
- [ ] The classification is described as observed evidence, not as automatic proof.
- [ ] The report is reviewed by you and submitted manually through the program's reporting channel.
