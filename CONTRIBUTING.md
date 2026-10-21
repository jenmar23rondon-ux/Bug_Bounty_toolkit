# Contributing

## Setup

Use Python 3.10 or newer and install the development extras in an isolated environment:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## Validation

Before opening a pull request, run the test suite and the configured quality checks:

```bash
python -m unittest discover -s tests -v
ruff check bugbounty_toolkit tests
mypy --strict
coverage run -m unittest discover -s tests -v
coverage report
```

CI runs `ruff format --check` on its maintained list of source and test files in `.github/workflows/python.yml`; use that same list locally rather than formatting the whole tree. The strict mypy file list is deliberately incremental; new modules should be added to it as their annotations and dependency stubs are ready. The overall coverage gate is 77%, with a separate 90% gate for the core access comparison and write-lab modules.

## Changes

- Add or update focused tests for behavior and error paths.
- Keep network tests mocked or restricted to temporary loopback servers.
- Preserve scope validation, bounded request budgets, rate limits, and secret redaction.
- Do not add credentials, real program traffic, or generated reports containing sensitive data.
- Update the README and changelog for user-visible behavior changes.
