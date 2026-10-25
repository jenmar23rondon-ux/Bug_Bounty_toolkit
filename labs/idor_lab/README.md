# Local IDOR/BOLA Lab

This isolated, deterministic service is intentionally vulnerable and binds only to `127.0.0.1`. It uses the Python standard library; no Flask or other web dependency is needed.

## Run it

From the repository root, start the service in a terminal:

```bash
bash labs/idor_lab/run.sh
```

On Windows PowerShell:

```powershell
./labs/idor_lab/run.ps1
```

The scripts bind to `127.0.0.1:8099` by default and stop the child process when the script exits. Set `IDOR_LAB_PORT` to use another local port. The service refuses non-loopback bind addresses. Login requests accept the fixture users `owner` and `actor`; `POST /login` returns their fake token in the `Authorization` response header. Never substitute real credentials or tokens into these fixtures.

For the complete automated flow, run:

```bash
bbtk lab idor
```

It starts the service on a free loopback port, runs the real CLI import/access-check/report commands against a temporary records directory, and cleans up the server and generated files afterward. Preview the steps without starting the service or making requests:

```bash
bbtk lab idor --dry-run
```

The end-to-end test can also be run directly:

```bash
python -m unittest discover -s tests -p test_end_to_end_idor.py -v
```

## Deliberate flaw and negative control

The owner account owns order `1001`; the actor owns order `1002`. Both normal account controls return HTTP 200 with `success: true`, their own resource ID and a distinct marker. The deliberate BOLA is that the actor token can also read owner order `1001`. The bounded local range test should classify that response as `candidate`, never `confirmed`.

`GET /api/public/status` is public and returns a benign status. Supplying its fixture-only `id` query returns a public marker so the access-check control can demonstrate the `public_endpoint` classification. It must not become an IDOR candidate. `?debug=1` is accepted by the orders endpoint as a harmless query variant and does not change authorization.

The lab also exposes `GET /api/protected-orders/<id>`, which enforces ownership and returns 403 for the other account; `/api/ambiguous-orders/<id>`, which returns HTTP 200 with `success: false` and a generic “Access denied” body on a cross-account read; and `/api/error-orders/<id>`, which returns 500 on that cross-account read. These controls demonstrate that HTTP 200 is not proof of access, and that generic errors are not vulnerability evidence. The automated scenario checks the one-way BOLA, the inverse actor direction, protected access, the 200 denial page, the error response and public endpoint. Every route is bound to the same loopback-only fixture and contains no real account data.

## Fixture contents

`captures/owner.txt` and `captures/actor.txt` are raw HTTP/1.1 requests to each account's own order. They contain only the fixed dummy tokens declared in `app.py`. The tests copy them to a temporary directory, substitute an ephemeral loopback port, and generate the private case there. No network request leaves loopback, and no test contacts an external service.

The test adds `identifier_enumeration_authorized: true` only to its temporary generated case because this disposable fixture explicitly allows testing the two known IDs. `import case` does not make that policy declaration for real programs.
