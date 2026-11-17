# Recon run

`bbtk run` is the scoped pipeline around passive recon. It does not submit findings, and it does not treat leads as confirmed vulnerabilities.

```bash
bbtk init acme --authorization "written program approval" --automation-allowed
bbtk scope import acme tests/fixtures/recon/hackerone.json
bbtk run acme --target example.com --dry-run
bbtk run acme --config config/recon.example.yml
bbtk run acme --resume
bbtk run acme --refresh --diff
```

`--dry-run` prints the plan and contacts nobody. A live run queries the same allowlisted passive providers as `bbtk recon`. `dnsx` and `httpx` run only with `--active --confirm`. `--nuclei` adds the same conservative Nuclei invocation as `bbtk recon` (no update check, no interactsh, and the `dos`, `intrusive`, and `fuzz` tags excluded).

## Resume and diff

A live run writes `reports/run-state.json` after passive collection and again after a completed active stage and the report. `--resume` reuses observations from a completed stage and does not repeat those provider requests. `--refresh` collects again. If the saved target does not match, the command stops instead of mixing two programs.

When a run finishes it stores `reports/run-latest.json` and keeps the previous copy at `reports/run-previous.json`. `--diff` prints hosts, URLs, and leads that were added or removed. The first run has no baseline.

## Config

`config/recon.example.yml` and `config/recon.example.toml` are flat files. Unknown keys, a non-boolean `active`, and a bad severity fail with the file name and the setting. `confirm` is rejected so a config file cannot turn active probing on by itself. `--passive-only` ignores `active` and `nuclei` from the file. `--log-level` is `debug`, `info`, `warning`, or `error`. Warning hides stage lines. The final summary is still printed.

## Scope import

`scope import` still accepts toolkit YAML with `allowed` and `excluded` lists. It also accepts:

- HackerOne structured-scope JSON (`asset_identifier`, `asset_type`, `eligible_for_submission`)
- Bugcrowd target-group JSON (`target_groups` or a `targets` list)
- CSV with a target column and an optional in-scope column

CIDR ranges, mobile-app identifiers, source-code assets, and public-suffix wildcards are skipped and named. They are not expanded into hosts. Exclusions win when the same asset is both allowed and excluded.

## Leads and exports

Hosts are grouped by name, by an IP address recorded next to that name, and by a technology hint such as a WordPress path or a `jenkins` label. Leads cover admin-looking paths, staging or development labels, sensitive ports listed by InternetDB, and a technology version or CVE identifier recorded by a source. Ports are not probed. Every lead stays `confirmed: false`.

Default files under the program `reports/` directory:

| File | Contents |
| --- | --- |
| `recon.md`, `recon.html`, `recon.json` | Asset inventory |
| `run.json` | Stats, groups, leads, diff, and the inventory |
| `recon.sarif.json` | SARIF 2.1.0 review notes (`level: note`) |
| `dashboard.html` | Offline summary page |
| `run-state.json` | Resume checkpoint |
| `run-latest.json` | Diff baseline |

Pass `--format` more than once to write a subset. The checkpoint and the diff baseline are still written on a live run so `--resume` and `--diff` keep working.

## Docker

```bash
docker build -t bbtk .
docker run --rm bbtk doctor
```

The image does not install ProjectDiscovery tools. Active probing stays unavailable until you supply those binaries yourself and pass `--active --confirm`.
