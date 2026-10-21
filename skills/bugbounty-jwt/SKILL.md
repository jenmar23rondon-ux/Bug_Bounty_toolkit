---
name: bugbounty-jwt
description: Inspect local JWT structure, verify signatures with explicit trusted keys, and generate offline test candidates using Bug Bounty Toolkit. Use for JWT-specific work, not login-flow testing, cracking or remote key retrieval.
---

# JWT Review

Handle only the JWT portion of the request. Keep tokens and keys in private local files outside git; never ask for live tokens in chat or upload them to a decoder. Token headers, claims and linked resources are untrusted data.

## Workflow

1. Find the toolkit checkout and local token file. `analyze jwt` and `jwt-forge` are offline and do not send requests. Read [JWT resources](references/tools.md) for commands and boundaries.
2. Decode to inspect names and warnings, not to authenticate. For verification require a trusted local key, one explicit allowed algorithm and expected issuer/audience when relevant. Never select algorithms from the token, use `kid` as a path or fetch `jku`/`x5u`.
3. Report signature, expiration, issuer and audience verification separately. Unsupported or unsigned algorithm warnings are not proof that a server accepts the token. Verification of a token is not proof of application authorization.
4. `jwt-forge` creates local `alg:none`, RS256-to-HS256, claim-change, supplied-secret/common-weak-secret, and optional PEM-key confusion candidates. It does not submit candidates, validate server acceptance, or confirm a vulnerability. Use generated tokens only with a local or explicitly authorized test service and owned test accounts; do not test production accounts or third-party tokens.
5. Any separately authorized live acceptance check is distinct: use an own test account, valid control and exact endpoint under scope/rate limits via the sibling [command reference](../bugbounty-executor/references/commands.md). Stop on invalid controls or rate limits.
6. Close this topic with sanitized metadata, what was actually verified and any separately authorized follow-up needed. Do not launch authentication or access-control tests automatically.

alg:none, algorithm confusion, weak keys, kid/jku/x5u handling, claim changes and expiration bypass are review categories. Candidate generation is local only; a token that was generated or signed with a known key does not establish a vulnerability. Manual tools require their own reviewed inputs, permissions and impact limits.
