# Release Readiness Checklist

This checklist prepares a release; it does not publish a package, create a Git tag, or create a GitHub release.

## Quality gates

Run the same checks as CI from a clean checkout:

```bash
python -m pip install -e ".[dashboard,xss,sqli,jwt,http,dev]"
python -m pip check
bbtk --version
bbtk doctor
ruff check bugbounty_toolkit tests scripts skills labs
ruff format --check bugbounty_toolkit tests scripts skills labs
mypy --strict
coverage run -m unittest discover -s tests -v
coverage report
```

Also run every module-specific coverage command listed in `.github/workflows/python.yml` and `.github/workflows/release.yml`.

## Platform checks

- Kali/Linux: create a fresh Python 3.10+ virtual environment, install the selected extras, run `pip check`, both local labs and the full test suite.
- Windows: repeat in PowerShell with `py -3`, validate both `.ps1` lab launchers, CLI parsing, local dashboard startup/shutdown, path handling and the full test suite.
- Ollama: run the optional integration evaluation only when the configured model is installed and the local server is available. Record the exact model, tag, run count, latency, invalid responses and variance. If unavailable, mark the evaluation not run.
- Benchmark: preserve the dataset audit and disclose that the current synthetic v2 minimized Ollama prompts overlap between development and holdout; its deterministic scores are not real-world estimates.
- Skills: confirm the built wheel contains all 12 `SKILL.md` files, references and the executor plan adapter; verify `bbtk doctor` locates the installed skill resources.
- Secrets: inspect staged files, generated reports and package contents. Do not package local records, raw Burp captures, tokens, cookies, private case files or model outputs containing sensitive content.

## Before tagging

Review the changelog, README, optional dependencies, package metadata and version consistency. Build and inspect the wheel and source archive locally. Confirm CI on the intended release commit. Create a version tag only after a separate explicit release decision; do not publish automatically.
