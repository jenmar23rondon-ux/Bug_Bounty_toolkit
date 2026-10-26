# External tool policy gate

External binaries (`subfinder`, `amass`, `httpx`, `nuclei`, `paramspider`, `arjun`, `ffuf`)
run only through `bugbounty_toolkit.core.secure_subprocess`.

## Guarantees

- Explicit executable allowlist (basename + PATH resolution)
- Structured argv only — `shell=True` is never used
- Wall-clock timeout and stdout/output-file byte caps
- Process-group termination on timeout, cancel, or output limit
- Optional POSIX RLIMIT caps for address space, CPU seconds, and process count
- Redacted argv in logs/records (headers/cookies/tokens stripped)
- Output confined under the program directory when path roots are configured

## Authorization, scope, and budget

Commands that can contact remote systems must attest:

1. Human authorization (`RecordStore.require_authorization` / CLI executor context)
2. In-scope targeting (`ScopeValidator` / `ensure_in_scope`)
3. An execution budget (`ExecutionBudget`) that has not been cancelled or exhausted

If any attestation is missing, the gate rejects the invocation **before** `exec`.
Tool-specific rate-limit flags (for example httpx `-rl` or nuclei `-rl`) are helpful
hints only; they are not treated as absolute safety guarantees.

## Failure modes

Stable codes include `policy_executable_not_allowed`, `policy_args_invalid`,
`policy_path_rejected`, `policy_missing_approval`, `policy_scope_unproven`,
`policy_budget_exhausted`, `timeout`, `output_limit`, and `cancelled`.

## Out of scope for this gate

Internal scanner logic (Nuclei template selection, ffuf match filters, APK
decompilers) is not rewritten here; adapters wrap their process launch through
the contract. Built-in HTTP clients continue to use `HttpClient` + scope + budget.
