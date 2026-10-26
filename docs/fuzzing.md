# Bounded discovery and wordlists

Use the discovery commands only for hosts and paths explicitly included in the program's current scope. Read its automation limits before selecting a list or request rate. The toolkit does not download wordlists, use credential-guessing collections, or treat an HTTP status as proof that a route works.

## Register and inspect local lists

Find common local collections and preview registrations before changing the user-level registry:

```bash
bbtk wordlists scan --dry-run
bbtk wordlists scan
bbtk wordlists list
bbtk wordlists inspect /path/to/SecLists/Discovery/Web-Content/api/api-endpoints.txt --rate 1
bbtk wordlists recommend --context api
bbtk wordlists prepare --category endpoints --max-entries 500 --rate 1 --dry-run
```

`prepare` creates a deduplicated, capped copy outside the repository. Review its category, source fingerprints, output fingerprint, request estimate, and expected duration. It will not overwrite a prepared list without `--force`. Large input files are streamed; the full source collections do not belong in Git.

Useful contexts include API endpoints, directories, files, parameters, extensions, and technology-specific paths. XSS and SQLi lists remain categorized for their separate checks. Lists whose path indicates passwords or credentials are excluded from discovery recommendations. The manager does not attempt authentication.

## Review and run ffuf

Place `FUZZ` only in the path or query value of a fixed in-scope URL. First inspect the exact plan:

```bash
bbtk fuzz my-program \
  --url "https://target.example/FUZZ" \
  --wordlist /path/to/api-endpoints.txt \
  --max-tests 40 --max-seconds 60 --threads 2 --rate 1 --timeout 10 \
  --dry-run
```

The request cap includes one random missing-route baseline and at most `max-tests - 1` wordlist requests. All selected URLs are checked against scope before the run. Review the selected-list SHA-256 and planned maximum, then use the same command with `--confirm` and without `--dry-run` only if the program permits it. Redirect following, recursion and auto-calibration are disabled. The toolkit adds no retry loop. A baseline 429 stops before ffuf starts; a later 429 is recorded and needs human review. Stop the run with Ctrl+C if the target behaves unexpectedly; the parent process enforces a wall-clock timeout.

The CLI reserves a bounded request upper limit for ffuf in the shared execution budget. ffuf does not report into the native HTTP counter, so the report keeps that upper bound separate from the exact native baseline count. It does not describe the planned external ceiling as a measured external request count.

## Interpret and follow up

Responses are compared with the missing-route baseline by status, body length, word count, line count, and redirect location. The comparison is heuristic; wildcard pages and content-dependent 404s can still produce false candidates. `endpoint_candidate` means only that the response differed from the baseline. Authentication pages, denials, generic responses, server errors, redirects and rate limits are labeled separately.

The toolkit saves raw ffuf output, a minimized evidence record, response groups and the input hash. It imports the result into the Unified Evidence Engine and API Workflow, indexes it in the local Evidence Graph, and records it in Investigation Memory. A numeric or UUID resource-shaped route may create a low-confidence authorization-review hypothesis and a non-executing skill plan. That plan requires a researcher-reviewed private `case.json`; discovery never guesses or enumerates object IDs and never runs `access-check` automatically.

Use the local dashboard to review wordlist metadata, the latest discovery summary, request ceilings and predicate-only access matrices. It does not expose raw response bodies, resource markers or IDs in the matrix view, and it has no active-check route.

Before reporting a possible authorization issue, validate both known-resource controls and the cross-account request with authorized accounts, then reproduce it manually in Burp. See the [IDOR/BOLA playbook](idor-playbook.md). A candidate is not a confirmed vulnerability or an impact/severity assessment.


## Context-aware plans from local captures

When you already have an authorized HAR export, build a plan that ties capture evidence to local wordlists before calling ffuf:

```bash
bbtk fuzz-plan my-program --har captures.har --dry-run
bbtk fuzz-plan my-program --har captures.har --category api --max-tests 40 --dry-run
bbtk fuzz-plan my-program --har captures.har --output plan.json
```

The planner reuses resilient HAR import, the offline wordlist registry and Investigation Memory. It never downloads lists or starts fuzzing. Approved targets still go through `bbtk fuzz --dry-run` then `--confirm`. See [context-aware fuzzing](context-aware-fuzzing.md).

## Opt-in content-aware ranking

By default `bbtk fuzz-plan` still ranks local lists by filename category and size. Pass `--ranking content` to also sample a bounded head of each registered list and prefer content fit over merely smaller files:

```bash
bbtk fuzz-plan my-program --har captures.har --ranking content --dry-run
```

Content mode is offline and deterministic. It never executes list entries, never downloads files, never follows symlinks, and never recommends credential or injection-payload lists. When a list cannot be inspected safely it falls back to the filename heuristic. Explanations (category fit, matched tokens, estimated coverage/duplication/request cost, sample SHA-256, uncertainty) are attached under `content_ranking` in the plan JSON. Filename mode remains the default until measured FINAL metrics justify a default change.

See `labs/content_wordlist_eval/` for the synthetic DEV/FINAL corpus and frozen ground truth.
