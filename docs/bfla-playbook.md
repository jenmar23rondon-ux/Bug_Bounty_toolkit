# BFLA function-matrix playbook

`access-check --function-matrix` provides bounded, read-only triage for Broken Function Level Authorization (BFLA). It compares exact GET captures for authorized accounts assigned to different roles. It does not discover routes, guess roles, alter a session, enumerate identifiers, or send writes.

## Before preparing captures

- Confirm the program permits the specific automated checks and that every account is yours or explicitly authorized.
- Select a function that is expected to be restricted and an endpoint that is known to be read-only. A GET method alone does not guarantee that an endpoint has no side effects; the case therefore requires the researcher's `read_only_attested: true` declaration.
- Capture the same exact endpoint and query once with each account in Burp. Keep captures outside version control because they contain live session credentials.
- Identify an application-level success predicate and a unique, pre-existing marker in the function response. Use a different marker for each function. Identify an application-level denial predicate as well.
- Ensure the configured scope contains the captured destination. Do not put session values in the query string.

## Case file

The case is an investigator attestation. The toolkit validates structure, scope and the supplied positive controls; it cannot establish that a program policy or role declaration is true.

```json
{
  "type": "function-access-case",
  "base_url": "https://authorized.example",
  "accounts_authorized": true,
  "session_headers": ["Authorization"],
  "accounts": {
    "admin_test": "admin",
    "reader_test": "reader"
  },
  "functions": [
    {
      "name": "report_export",
      "allowed_roles": ["admin"],
      "requests": {
        "admin_test": "captures/admin-report-export.txt",
        "reader_test": "captures/reader-report-export.txt"
      },
      "success_pointer": "/success",
      "success_value": true,
      "denial_value": false,
      "marker_pointer": "/report/proof",
      "marker": "private-report-fixture-6d42",
      "restricted": true,
      "read_only_attested": true
    }
  ]
}
```

Each raw capture must be a GET with the same origin, endpoint and query for that function, and a distinct session for every account. The success and denial values must be different JSON scalars. The marker must already exist in a response available to the allowed role.

## Run

Preview the validated request count without sending traffic:

```bash
bbtk access-check my-program \
  --case-file registros/my-program/private/function-case.json \
  --function-matrix --max-tests 2 --dry-run
```

After reviewing the plan, run it with the same arguments and omit `--dry-run`. The toolkit sends permitted-role controls first for each function. It only tests restricted roles for a function after every permitted-role control matches the configured application success and marker. A failed control, redirect, truncation, 429, or transport error stops that function's remaining checks. The matrix has a hard ceiling of 100 GET requests and also obeys program scope, configured rate limits, timeout and request budget.

## Interpret results

- `legitimate_access`: an account assigned an allowed role matched the explicit success and marker predicates.
- `possible_bfla`: an account assigned a restricted role matched both predicates after the allowed-role controls passed. This is a candidate for manual validation, never confirmation.
- `denied`: each tested restricted role matched the declared application denial predicate and did not return the marker.
- `insufficient_evidence`: captures, controls, response predicates or request completion did not settle the comparison.

HTTP status is recorded for review but never decides the classification. A 200 without the configured function marker is not access evidence; a non-200 response containing the exact marker can still be a candidate. The deterministic assessor can evaluate the case and native evidence together without contacting Ollama:

```bash
bbtk ai hypotheses my-program --input registros/my-program/unified-evidence.json \
  --case-file registros/my-program/private/function-case.json \
  --access-evidence /path/reported/by/access-check.json \
  --dry-run
```

The `access_control_assessment` in that output is deterministic and never sets `confirmed` to true. Before reporting, replay the exact comparison manually in Burp, check that the marker is private and belongs to the intended function, verify the role policy, and follow program disclosure rules.

This mode is read-only by design. Role-based write checks are not supported by this matrix; use only the existing disposable-resource write workflow for explicitly authorized BOLA state-change validation.
