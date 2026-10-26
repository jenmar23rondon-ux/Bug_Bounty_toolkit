# Object Handoff Playbook (offline)

1. Capture authorized traffic (Burp/HAR) for at least two distinct sessions that touch similar object endpoints.
2. `bbtk object-discover <program> --input captures.har --attest-authorized-captures`
3. `bbtk object-candidates <program> --graph .../graph.json --verify-input captures.har`
4. `bbtk object-handoff <program> --graph .../graph.json --verify-input captures.har --dry-run`
5. Review proposals (resource type, endpoint template, provenance locators). Discard anything outside scope.
6. Re-run handoff with `--materialize-dir` + `--output` to write private raw HTTP pairs.
7. Run the suggested `import discover-idor ... --attest-authorized-accounts` command.
8. Complete **all** approve-idor attestations, then `approve-idor --approve` only after human ownership/privacy review.
9. Never treat handoff scores as confirmed vulnerabilities. Use `bbtk lab object-discover` for synthetic ranking metrics only.
