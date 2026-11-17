# Quick Start

Bug Bounty Toolkit is an authorized-testing CLI. Use it only against assets and test accounts covered by written program permission.

## Kali Linux / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dashboard,dev]"
bbtk --version
bbtk doctor
bbtk lab idor
bbtk lab web-vuln
```

For a local research dashboard, initialize a program record first, then start the UI:

```bash
bbtk init my-program --authorization "local authorized program reference"
bbtk dashboard my-program
```

Open `http://127.0.0.1:8765/`. Stop it with Ctrl+C. The dashboard is bound to loopback, imports through the redacting Evidence Engine, and does not run checks, commands, or Ollama requests.

## Windows PowerShell

Native Windows support is partial. Commands that use `core/private_files.py`
require POSIX no-follow directory descriptors and fail closed on Windows;
this includes private artifact/discovery workflows. Use Linux or WSL with a
Linux filesystem for those paths. Passing `doctor` is not proof of full Windows
compatibility. Do not remove these filesystem protections to work around an
unsupported platform.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dashboard,dev]"
bbtk --version
bbtk doctor
bbtk lab idor
bbtk lab web-vuln
```

Start the local dashboard after initializing a program:

```powershell
bbtk init my-program --authorization "local authorized program reference"
bbtk dashboard my-program
```

Open `http://127.0.0.1:8765/`. Stop it with Ctrl+C. PowerShell execution policy may require activating the environment with `Set-ExecutionPolicy -Scope Process Bypass` for that terminal, or invoke `.\.venv\Scripts\bbtk.exe` directly.

## Passive recon

Initialize a program and an explicit scope before discovery. `--dry-run` prints the provider plan and does not contact anyone. Live passive recon queries allowlisted third parties only. `dnsx`, `httpx`, and `nuclei` stay off unless you opt in.

```bash
bbtk init acme --authorization "written program approval" --automation-allowed
bbtk scope add acme example.com
bbtk scope add acme '*.example.com'
bbtk scope add acme --exclude admin.example.com
bbtk recon acme --target example.com --dry-run
bbtk recon acme --target example.com
bbtk recon acme --target example.com --active --confirm
bbtk run acme --target example.com --dry-run
bbtk run acme --config config/recon.example.yml --dry-run
bbtk scope import acme tests/fixtures/recon/hackerone.json
```

`bbtk run` is the resumable pipeline: passive collection, optional active tools, correlation, unconfirmed scoring, and reports. `--resume` skips stages already stored in `reports/run-state.json`. `--diff` compares the new inventory with `reports/run-latest.json`. Active tools still require `--active --confirm`. A config file cannot set `confirm`. See [recon run](recon-run.md).

Set `SECURITYTRAILS_API_KEY` or `VIRUSTOTAL_API_KEY` in the environment to add those two providers. Keys are sent as headers and are not written into reports. Shodan InternetDB is used when the target is an in-scope IPv4 address.

## Optional local Ollama review

Ollama integration is optional. Install and start Ollama separately, then select a model that is already installed locally. For this project, `qwen2.5-coder:7b` is the preferred evaluation model; the toolkit never downloads models. A model response remains a second opinion and cannot confirm a vulnerability.

## Authorized target setup

Read the target program's current policy, exclusions, automation limits and reporting rules. Initialize a distinct program record, configure exact in-scope hosts and limits, and use the relevant topic skill. Begin with the local labs and dry-run previews. Review evidence and manually reproduce any candidate before reporting; the toolkit does not submit reports.

See [authorized testing rules](authorized-testing.md), the [bounded fuzzing and wordlist guide](fuzzing.md), the [IDOR playbook](idor-playbook.md), and the [known limitations](../README.md#known-limitations).
