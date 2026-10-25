# Bundled Examples and Local Wordlist Collections

Files in this repository are small examples, not copies of complete third-party collections. Keep large SecLists, Assetnote, fuzzdb and custom collections on the local machine; the toolkit can register and inspect them without copying them into Git.

Official source: https://github.com/danielmiessler/SecLists

Typical paths in SecLists:

- `Discovery/Web-Content/api/api-endpoints.txt`
- `Discovery/Web-Content/common.txt`
- `Discovery/Web-Content/burp-parameter-names.txt`
- `Discovery/Web-Content/raft-medium-directories.txt`

Verify paths against your installed version. The adapter checks every generated URL against scope before starting ffuf.

## Local collection workflow

```bash
bbtk wordlists scan --dry-run
bbtk wordlists scan
bbtk wordlists register seclists /usr/share/seclists
bbtk wordlists list
bbtk wordlists inspect /usr/share/seclists/Discovery/Web-Content/common.txt --rate 1
bbtk wordlists recommend --category api
bbtk wordlists prepare --category endpoints --max-entries 1000 --rate 1 --dry-run
```

`scan` checks known directories and configured environment variables (`SECLISTS_DIR`, `ASSETNOTE_WORDLISTS_DIR`, `FUZZDB_DIR`, `BBTK_WORDLISTS_DIR`); it does not download or recursively read collections. `register` stores a local path in the per-user registry. `inspect` counts entries, duplicates, invalid lines and estimates request count and minimum time using bounded streaming. `prepare` combines matching files, removes exact duplicate lines using disk-backed temporary SQLite state, applies the entry cap, and writes under the user cache by default. Existing outputs require `--force` before replacement.

The estimate is a planning aid, not a promise of run duration or exact request count. Scope exclusions, response latency and ffuf behavior can change the number and duration of requests. Review the prepared list, scope, program automation rules, rate and budget before fuzzing.
