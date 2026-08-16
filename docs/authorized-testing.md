# Authorized Testing Policy

This toolkit is designed for public bug bounty programs and private security tests where the operator has explicit permission.

## Required Before Running Scans

- Read the program policy on HackerOne, Bugcrowd, Intigriti, or the customer-provided rules of engagement.
- Add only authorized root domains or hosts to `registros/<program>/scope.txt`.
- Respect rate limits, forbidden vulnerability classes, excluded assets, and reporting requirements.
- Use dedicated test accounts when checking IDOR, authorization, business logic, or data exposure.
- Stop immediately if testing could affect other users, availability, payment systems, or production data outside the policy.

## Evidence Rules

- Keep timestamps, affected URLs, request IDs, screenshots, and scanner outputs.
- Do not store secrets in Git.
- Do not access, copy, modify, or delete data beyond the minimum needed to prove impact under the program policy.
- Mark duplicate or already-reviewed items with `bbtk mark-reviewed`.
