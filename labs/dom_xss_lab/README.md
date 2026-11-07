# DOM XSS lab

Loopback-only fixture for `bbtk xss --dom`. The server never reflects the query
string in the HTTP body and never opens an outbound socket.

| Path | Sink | Expected `--dom` result |
| --- | --- | --- |
| `/vulnerable` | `location.hash` or `q` assigned to `innerHTML` | Confirmed only when that assignment runs the probe's own marker or exact alert |
| `/safe` | same sources assigned to `textContent` | Reflection without execution stays `reflected_not_executed` and is not confirmed |
| `/unrelated-alert`, `/prefixed-alert`, `/wrong-marker`, `/alert-only` | Negative controls | Unrelated alerts, other marker strings, and an attributed alert without a sink are not confirmed |

```bash
python -m unittest tests.test_dom_xss_inscope tests.test_dom_xss_lab -v
```

The listener refuses any non-loopback bind. Do not expose it beyond the lab.
