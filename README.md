# Bug Bounty Toolkit

Bug Bounty Toolkit is a local Kali Linux CLI for authorized bug bounty and offensive security workflows. It automates reconnaissance, vulnerability scanning, fuzzing, parameter discovery, evidence tracking, review history, and report generation for public programs such as HackerOne, Bugcrowd, and Intigriti.

> Use this project only on assets where you have explicit authorization. The toolkit includes scope validation and persistent records so repeated reviews are traceable and controlled.

## Core Capabilities

- Automated reconnaissance with `subfinder`, `amass`, and `httpx`.
- Vulnerability scanning orchestration with `nuclei`.
- Directory and endpoint fuzzing with `ffuf`.
- Parameter discovery with `paramspider` and `arjun`.
- Persistent records in `registros/` to avoid reviewing the same asset, endpoint, or finding twice.
- Local evidence folders for requests, responses, scanner output, notes, screenshots, and artifacts.
- Review checklist for IDOR, authorization bypass, injection, XSS, command injection, security misconfigurations, subdomain takeover, CORS issues, business logic, exposed secrets, and information disclosure.
- Automated Markdown and PDF reporting for validated findings.

## Project Layout

```text
bug-bounty-toolkit/
|-- bugbounty_toolkit/
|   |-- cli.py
|   `-- core/
|       |-- checks.py
|       |-- records.py
|       |-- reporting.py
|       |-- runner.py
|       `-- scope.py
|-- config/
|   `-- toolkit.example.yml
|-- docs/
|   |-- authorized-testing.md
|   `-- vulnerability-checklist.md
|-- registros/
|   `-- .gitkeep
|-- templates/
|   `-- finding_report.md
|-- pyproject.toml
|-- requirements.txt
|-- LICENSE
`-- README.md
```

## Install on Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m pip install -e .
```

Install external tools separately:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
pipx install arjun
pipx install git+https://github.com/devanshbatham/paramspider
```

Make sure Go binaries are in your `PATH`:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## Quick Start

```bash
bbtk init hackerone-example --platform hackerone --authorization "https://hackerone.com/example/policy"
bbtk scope add hackerone-example example.com
bbtk recon hackerone-example --target example.com
bbtk scan nuclei hackerone-example
bbtk fuzz hackerone-example --url https://app.example.com/FUZZ --wordlist /usr/share/wordlists/dirb/common.txt
bbtk params hackerone-example --url https://app.example.com/account
bbtk checklist hackerone-example
bbtk report hackerone-example --finding-id FINDING-001
```

All program data is stored under:

```text
registros/<program>/
|-- toolkit.sqlite3
|-- scope.txt
|-- evidence/
|-- reports/
|-- raw/
`-- reviewed/
```

## Review Tracking

The toolkit records:

- reviewed domains, subdomains, URLs, endpoints, parameters, and findings;
- command executions and output files;
- evidence paths and timestamps;
- findings status: `new`, `triaged`, `validated`, `reported`, `resolved`, `duplicate`, `out-of-scope`;
- report generation history.

Example:

```bash
bbtk mark-reviewed hackerone-example --kind endpoint --value https://app.example.com/api/user?id=1001 --note "Checked IDOR with authorized test accounts"
bbtk status hackerone-example
```

## Vulnerability Review Areas

The built-in checklist covers:

- IDOR and object-level authorization.
- Role-based authorization bypass.
- SQL injection, XSS, and command injection review.
- Exposed admin panels, default credentials, CORS misconfiguration, and subdomain takeover indicators.
- Business logic issues such as price manipulation and rate-limit abuse.
- Sensitive information exposure in JavaScript, repositories, errors, headers, and public artifacts.

## Safety Model

- Scope must be added before scans run.
- Commands refuse targets outside configured scope.
- Every run is logged with timestamp, command, target, return code, and output location.
- The toolkit does not attempt destructive exploitation.
- Human validation is required before reporting a finding.

## License

MIT License. See [LICENSE](LICENSE).
