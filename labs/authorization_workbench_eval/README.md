# Authorization workbench evaluation

Run from the repository root with the dashboard/dev extras installed:

```sh
python -m labs.authorization_workbench_eval.run
python -m unittest tests.test_authorization_workbench -v
python -m labs.authorization_workbench_eval.browser_eval --executable /path/to/chrome
```

Browser evaluation optionally accepts `--screenshot /local/output.png`. All page requests are
fulfilled by the local in-process ASGI client; non-loopback page requests are aborted and fail
the evaluation. It starts no HTTP server. The projection harness forbids socket connects.

`fixtures.py` constructs authorized synthetic allowed/denied, HTTP-200 application error,
HTTP-403 JSON, public/shared resources, different roles, missing response, large fields,
arrays, dynamically generated private/JWT canaries, and malicious HTML captures. Denied
lab assessments are produced through the public `assess_access_control_data` interface;
the workbench only displays saved results. Adversarial tests mutate references and exercise
symlinks, oversized input, excessive nesting, malformed metadata, duplicates, path/key/value
leakage, empty/null/absent/unavailable semantics, and global-vs-per-capture assessment boundaries.
No canary value is printed or stored in committed fixtures/reports.

See `docs/authorization-workbench.md` for the pinned-source baseline, limitations and metric
interpretation. Metrics include oracle checks, not a claim of exhaustive correctness or a
human usability study. `results.json` records one final machine run; timings vary.
