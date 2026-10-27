# DOM-only XSS loopback evaluation

This feature is an opt-in synthetic laboratory check, **not a scanner for public
bug bounty targets**. The routes must contain literal loopback IP addresses;
`localhost` and public hostnames are rejected. Supply a fresh disposable local
web application and only test resources you control.

After installing the optional browser dependency:

```bash
python -m pip install -e '.[xss]'
python -m playwright install chromium
```

Start your own local fixture web server. Create `routes.txt` containing its
address, for example `http://127.0.0.1:8181/dom`, and `parameters.txt`
containing `q`. Preview:

```bash
bbtk init dom-lab --authorization 'Disposable local fixture' --automation-allowed
bbtk scope add dom-lab 127.0.0.1
bbtk xss dom-lab --routes routes.txt --parameters parameters.txt --dom-local --max-tests 4 --run-max-requests 12 --dry-run
```

Remove `--dry-run` only when the preview matches your local fixture. The
fixture is responsible for reading the browser's `location.search` and
`location.hash`. Neither source requires reflection in the HTTP response.

Each parameter/source receives a plain-marker control and an execution-marker
probe. The feature measures browser observations, not reportable vulnerabilities:

- `source_marker_present`: the marker was present in the browser URL, **not**
  proof that application JavaScript read it.
- `sink_reached`: the marker reached an instrumented DOM sink; this alone does
  not establish XSS.
- `execution_observed`: a harmless marker executed in the disposable browser.
- `inconclusive`: no decisive browser observation.

The legacy reflected-XSS flow is unchanged. Browser requests still use the
existing scope, rate limiter, and shared request/time/concurrency budget.
`--max-tests` limits browser probes, not HTTP subresources. External HTTP(S)
requests are aborted by the existing same-origin route guard; WebSockets are
blocked and service workers disabled for this local-only mode.

**Limitations:** browser instrumentation is partial and can miss sinks invoked
before a hook is installed, isolated frames, asynchronous code after the page
load event, and client-side flows not exercised by the fixture. A DOM sink
observation or the absence of one does not prove (in)security. No claim is made
about real-world detection efficacy.

## Evidence-quality v2 extension

`run_dom_local` results now also carry an additive `dom_state` from
`xss.evidence_record.assess_dom_result`. Legacy `classification` values are
unchanged. See [xss-evidence-quality-v2.md](xss-evidence-quality-v2.md).
