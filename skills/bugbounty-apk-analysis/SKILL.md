---
name: bugbounty-apk-analysis
description: Inspect a supplied Android APK locally for embedded endpoints, secret patterns, Firebase references, email addresses and browsable deep links. Never executes the APK or contacts discovered hosts.
---

# APK Static Analysis

Handle only the supplied APK and the requested Android application review. Use the shared [command reference](../bugbounty-executor/references/commands.md) for toolkit setup and reports.

Run `bbtk apk-scan <program> --apk <path> --dry-run` to validate the archive and configured scope, then run the same command without `--dry-run` to produce local JSON evidence. This is static analysis: the scanner reads ZIP members in memory, does not extract or install the APK, does not execute its code, and never sends HTTP requests to discovered URLs. It labels referenced HTTP(S) destinations as in-scope or out-of-scope; those labels do not trigger network access.

Findings are grouped as endpoints, secret-pattern candidates, Firebase references, manifest deep links and emails. Secret values and email local parts are masked in JSON and console output. Pattern matches are leads, not proof that a key is active or exploitable. Review the APK's provenance and each result locally before sharing evidence.

Binary Android manifests are parsed with Python's standard library. `--decompile` is a separate opt-in that runs locally installed `jadx` or `apktool` in a temporary directory with a 120-second limit; if neither exists or parsing fails, the ZIP-only scan remains available. Do not install a decompiler just for a scan without reviewing its source and package provenance.

`--ai-review` optionally asks Ollama at `127.0.0.1:11434` for a heuristic second opinion. The model receives only finding counts and secret-pattern categories, not secret values, APK bytes, source text, URLs or file paths. Ollama cannot validate a credential; it never confirms a finding. No external model or remote fallback is used.

The input is bounded to 512 MiB, with per-member and aggregate scan limits. Large or unreadable entries are recorded as skipped. No discovery, APK installation, signing, credential verification or requests to referenced services are part of this skill.
