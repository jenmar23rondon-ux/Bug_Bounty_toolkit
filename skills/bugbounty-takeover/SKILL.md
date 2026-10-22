---
name: bugbounty-takeover
description: Passively identify possible subdomain-takeover candidates from supplied CNAME records or an explicitly requested scoped DNS lookup. Never claims services or sends HTTP requests.
---

# Subdomain Takeover Review

Handle only the takeover-check topic. A matching provider CNAME is a lead, not proof that a service is unclaimed or exploitable.

1. Confirm the named host is covered by the program's configured scope. Keep provider destinations separate from the target scope; do not expand scope based on a CNAME.
2. Prefer offline analysis of a captured record: `bbtk takeover-check <program> --host <subdomain> --cname <captured-cname>`. The local signatures cover a small set of providers and are not exhaustive.
3. DNS is opt-in: use `--resolve-dns` only when the user requested a lookup, after confirming the program authorization reference and scope. `--dry-run` validates without querying DNS. Install the optional `takeover` extra for dnspython.
4. Treat `possible_takeover` as a provider-signature match only. The command performs no HTTP request, provider API call, registration attempt or resource claim; it cannot establish that the provider resource is unclaimed.
5. Report the CNAME, matched local signature, DNS status, unverified ownership and local evidence path. Do not suggest claiming the resource or testing ownership outside the authorized program.

See [provider references](references/providers.md) for the provenance of the initial CNAME patterns and their limitations.
