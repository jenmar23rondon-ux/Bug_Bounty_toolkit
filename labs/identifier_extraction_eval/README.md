# Identifier extraction eval

Offline adversarial lab for `bugbounty_toolkit.analysis.identifier_candidates`.

## What it measures

- Precision / recall / F1 of object-identifier candidates
- Recall by encoding (path, query, matrix, JSON, JSON array, XML, form, declared)
- False inclusion of secrets (JWT, CSRF, signatures, passwords)
- Scalar type preservation and locator validity
- Correct rejection of malformed / hostile inputs (duplicate keys, XXE, invalid UTF-8)

## How to run

```bash
python -m labs.identifier_extraction_eval.run_lab
```

No network traffic is performed. The lab never auto-confirms findings and does not
alter Object Discovery ranking or the PR #52 denial assessment.
