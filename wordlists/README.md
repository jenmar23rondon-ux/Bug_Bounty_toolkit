# Wordlists

These files are small local examples, not copies of the complete SecLists lists.
Replace them with the version reviewed for your authorized program or pass another path with `--wordlist`.

Official source: https://github.com/danielmiessler/SecLists

Typical paths in SecLists:

- `Discovery/Web-Content/api/api-endpoints.txt`
- `Discovery/Web-Content/common.txt`
- `Discovery/Web-Content/burp-parameter-names.txt`
- `Discovery/Web-Content/raft-medium-directories.txt`

Verify paths against your installed version. The adapter checks every generated URL against scope before starting ffuf.
