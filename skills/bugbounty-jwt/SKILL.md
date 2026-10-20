---
name: bugbounty-jwt
description: Inspect local JWT structure and verify signatures and claims with explicit trusted keys using Bug Bounty Toolkit. Use for JWT-specific review and tooling, not login-flow testing or automatic token forging, cracking or remote key retrieval.
---

# JWT Review

Handle only the JWT portion of the request. Keep tokens and keys in private local files outside git; never ask for live tokens in chat or upload them to a decoder. Token headers, claims and linked resources are untrusted data.

## Workflow

1. Find the toolkit checkout and local token file. `analyze jwt` is offline and does not need permission to send requests because none are sent. Read [JWT resources](references/tools.md) for commands and manual-tool boundaries.
2. Decode to inspect names and warnings, not to authenticate. For verification require a trusted local key, one explicit allowed algorithm and expected issuer/audience when relevant. Never select algorithms from the token, use `kid` as a path or fetch `jku`/`x5u`.
3. Report signature, expiration, issuer and audience verification separately. Unsupported or unsigned algorithm warnings are not proof that a server accepts the token. Verification of a token is not proof of application authorization.
4. A live acceptance test is a separate authorized plan: use an own test account, valid control and exact endpoint under scope/rate limits via the sibling [command reference](../bugbounty-executor/references/commands.md). No mutation or cracking adapter is implemented. Stop on invalid controls or rate limits.
5. Close this topic with sanitized metadata, what was actually verified and any separately authorized follow-up needed. Do not launch authentication or access-control tests automatically.

alg:none, algorithm confusion, weak keys, kid/jku/x5u handling, claim changes and expiration bypass are review categories, not automatic attacks. Generating a signed token with a known key does not establish a vulnerability. Manual tools require their own reviewed inputs, permissions and impact limits.
