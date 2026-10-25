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

## Optional local Ollama review

Ollama integration is optional. Install and start Ollama separately, then select a model that is already installed locally. For this project, `qwen2.5-coder:7b` is the preferred evaluation model; the toolkit never downloads models. A model response remains a second opinion and cannot confirm a vulnerability.

## Authorized target setup

Read the target program's current policy, exclusions, automation limits and reporting rules. Initialize a distinct program record, configure exact in-scope hosts and limits, and use the relevant topic skill. Begin with the local labs and dry-run previews. Review evidence and manually reproduce any candidate before reporting; the toolkit does not submit reports.

See [authorized testing rules](authorized-testing.md), the [bounded fuzzing and wordlist guide](fuzzing.md), the [IDOR playbook](idor-playbook.md), and the [known limitations](../README.md#known-limitations).
