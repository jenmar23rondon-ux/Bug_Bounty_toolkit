# Offline authorization code audit (FastAPI / Express subset)

`bugbounty_toolkit/analysis/offline_authorization_audit.py` statically reviews a **local, authorized**
source tree and emits *hypotheses* about routes where no object-level authorization was observed.
Conceptually inspired by GitHub Security Lab's Taskflow Agent; no code was copied.

```bash
python -m bugbounty_toolkit.analysis.offline_authorization_audit path/to/local/repo --output audit.json
python -m labs.offline_authz_code_eval.run
```

## Safety properties
- Reads only regular files under the given root; symlinks escaping it, `node_modules`, virtualenvs and files >1 MB are skipped.
- Python is parsed with `ast`; JavaScript with a small masking lexer + bracket matcher. Nothing is imported,
  executed, installed, cloned, or sent over the network. No AI provider is involved; no patches are proposed or applied.
- Every route record has `human_review_required: true` and `finding_confirmed: false`. The tool never edits sources or finding state.
- `to_ledger_candidates(report, reviewer=..., reviewed=True)` exports `possible_authorization_gap` routes as
  `candidate` entries only after explicit human review; otherwise it raises `PermissionError`.

## Output fields (per route)
`route_ref`, `http_method`, `path`, `source_file`, `source_lines`, `framework`, `resource_parameter`,
`authn_observed`, `authn_scopes` (global / router / route / function), `function_authz_observed`,
`object_authz_observed` (`observed | not_observed | unknown | not_applicable`), `analysis_coverage`,
`unresolved_calls`, `possible_authorization_gap` (`true | false | null` = abstain), `evidence_refs` (file:line),
`limitations`, `human_review_required`, `finding_confirmed`.

## Supported subset
- FastAPI: `@app|router.<get|post|put|patch|delete>("path", dependencies=[...])`, `FastAPI(dependencies=...)`,
  `APIRouter(dependencies=...)`, `include_router(..., dependencies=...)`, parameter `Depends/Security`,
  `@app.middleware("http")`, helpers resolved by unique name across the root (depth ≤ 4).
- Express: `app|router.<verb>("path", ...mw, handler)`, order-sensitive `.use()`, `express.Router()` mounts,
  local `function` / arrow helpers, local middleware factories.

## Semantics
- A check counts only if a reachable conditional leads to a deny (`raise`, `throw`, 401/403/404). Its condition
  is classified: ownership comparison (owner/user_id/tenant… vs user/principal/req.user…) → object authz;
  role/permission/admin → function-level authz; user/token/session → authentication. Ownership-scoped query
  filters (`filter_by(owner_id=user.id)`, `where: {ownerId: req.user.id}`) also count as object authz.
- Helper *names* (`authorize`, `check_permission`) prove nothing: bodies are inspected; empty helpers, `if False`
  blocks and code after an unconditional `return` are ignored.
- Unresolved / ambiguous / dynamic calls that receive user identity or look auth-related, unresolved
  `Depends(...)`, unknown middleware and unknown router objects → `object_authz_observed: unknown`,
  `possible_authorization_gap: null` (abstention).
- `possible_authorization_gap: true` means only "no object-level check observed in the analysed path"; it is not
  evidence of exploitability.

## Limitations
Heuristic token lists; no data-flow / type inference; helpers resolved by simple name; JS template literals,
regex literals and TypeScript are not fully supported; cross-file Express router mounts are flagged
(`router_mount_not_observed_in_file`) rather than resolved; the lab corpus is small and author-written, so the
metrics below are a development benchmark, not a generalisation estimate.

## Metrics (`labs/offline_authz_code_eval`, 24 routes, 2 malformed files)
| metric | before (main: no static path) | naive name-grep baseline | after |
|---|---|---|---|
| route extraction recall / precision | n/a | — | 1.0 / 1.0 |
| object-authz check recall | n/a | — | 1.0 (10/10) |
| gap hypothesis recall | n/a | 0.5 | 1.0 (11/11) |
| false gap warnings | n/a | 8 | 0 |
| correct abstentions | n/a | 0/3 | 3/3 |
| valid file:line refs | n/a | — | 79/79 |
| unauthorized files read / target executions / network | n/a | — | 0 / 0 / 0 |
| time / peak memory | — | — | ~0.03 s / ~0.5 MiB |
