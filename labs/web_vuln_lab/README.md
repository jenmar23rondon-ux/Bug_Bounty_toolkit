# Local XSS and SQLi lab

This standard-library fixture server is deterministic and binds only to loopback. It does not use a database, execute SQL, launch a browser, contact external hosts, or require real credentials.

## Run

From the repository root, run `bash labs/web_vuln_lab/run.sh` or `./labs/web_vuln_lab/run.ps1`. The server uses `127.0.0.1:8181`; set `WEB_VULN_LAB_PORT` to select another local port.

Run the complete test flow with:

```bash
python -m unittest discover -s tests -p test_end_to_end_web_vuln.py -v
```

The test starts an ephemeral loopback server, sends bounded requests through the toolkit's scope-aware HTTP client and XSS/SQLi engines, imports their redacted evidence, builds API workflow and hypotheses, routes the hypotheses to installed skills without executing a plan, and writes a draft report. Ollama is mocked in this deterministic test; it never contacts the model service.

## Fixtures

| Route | Behavior | Expected interpretation |
|---|---|---|
| `/xss/reflected?q=...` | Returns supplied value as HTML text | Reflection candidate only; no JavaScript execution is asserted |
| `/xss/escaped?q=...` | HTML-escapes the supplied value | Escaping control; output remains unconfirmed |
| `/xss/ambiguous?q=...` | Reflects the value as JSON | Reflection outside HTML is not XSS confirmation |
| `/sqli/vulnerable?q=...` | Simulates a SQL syntax error string after a quote | Error-signature candidate only; no SQL engine is used |
| `/sqli/protected?q=...` | Returns fixed output regardless of input | Negative control modeling parameterized handling |
| `/sqli/ambiguous?q=...` | Returns a generic 500 response | Ambiguous server error, not a SQLi signature |

The fixture intentionally models signals for testing classification. It does not demonstrate a real exploit or prove that the toolkit would find a vulnerability in a production application. XSS reflection is never execution, and SQL error text is never database access or SQLi confirmation. Do not expose this lab on a public interface.
