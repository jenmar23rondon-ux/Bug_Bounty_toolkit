# Security Policy

## Scope and authorization

Bug Bounty Toolkit is for testing assets where the operator has explicit authorization. Installing or using the toolkit does not grant permission to test any target. Review the program's current scope, exclusions, automation rules, and rate limits before sending traffic. State-changing checks require disposable resources and may still leave remote changes.

## Reporting a vulnerability in this project

Please do not publish exploit details, credentials, target data, or an unpatched vulnerability in a public issue. Use GitHub's private vulnerability reporting for this repository if it is enabled. Otherwise, contact the repository maintainer privately through GitHub and include a concise impact description and safe reproduction steps.

Do not include live tokens, cookies, personal data, or third-party traffic captures in a report. Redaction is best effort; inspect attachments before sharing them.

## External tools

Legacy wrappers for third-party CLIs are supervised by `bugbounty_toolkit.core.secure_subprocess`: allowlisted executables, no shell, timeouts, output caps, and process-tree cleanup. Remote-facing invocations still require program authorization, in-scope targets, and an execution budget. See `docs/external-tool-policy.md`.

## Safe testing

Use the local unit and loopback integration tests for development. Never use project test fixtures or examples as permission to probe a public service. The toolkit does not submit vulnerability reports automatically.
