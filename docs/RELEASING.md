# Releasing Bug Bounty Toolkit

This document describes how to cut a versioned release. Creating a tag or GitHub Release is a **human decision**; CI must never publish without an explicit, authorized tag push.

Related: [release-checklist.md](release-checklist.md) (quality gates) and [SECURITY.md](../SECURITY.md).

## Preconditions

1. `main` contains only reviewed, merged work you intend to ship.
2. Local and CI quality gates match `.github/workflows/python.yml` (ruff, mypy, coverage gates, full unittest suite).
3. Playwright Chromium is installed in CI so XSS browser confirmation tests do not silently skip.
4. `CHANGELOG.md` has a dated section for the version about to ship; `Unreleased` is empty or holds only post-cut notes.
5. Package version matches everywhere:
   - `pyproject.toml` → `[project].version`
   - `bugbounty_toolkit/__init__.py` → `__version__`
   - Any version assertions in tests (for example `tests/test_maintenance.py`)
6. Wheel and sdist build cleanly (`python -m build`) and contain no secrets, local captures, tokens, cookies or private program data.
7. Tag `v0.2.1` (and any earlier tags) remain untouched unless a separate, explicit decision says otherwise.

## Cut checklist (human OK required)

1. Confirm the release prep PR is reviewed and merged to `main`.
2. Confirm CI is green on the intended release commit.
3. Re-read `CHANGELOG.md` for the version section and README highlights.
4. Build and inspect artifacts locally:

   ```bash
   python -m pip install -e ".[dashboard,xss,sqli,jwt,http,dev]"
   python -m playwright install chromium   # if exercising browser confirmation locally
   python -m pip check
   bbtk --version
   ruff check bugbounty_toolkit tests scripts skills labs
   ruff format --check bugbounty_toolkit tests scripts skills labs
   mypy --strict
   coverage run -m unittest discover -s tests -v
   coverage report
   python -m build
   # Inspect dist/*.whl / dist/*.tar.gz for secrets before tagging
   ```

5. Obtain explicit authorization to publish (tag + GitHub Release). Prep PRs alone are not authorization.
6. Create an annotated tag that matches the package version (example for 0.2.2):

   ```bash
   git checkout main
   git pull
   git tag -a v0.2.2 -m "Bug Bounty Toolkit 0.2.2"
   git push origin v0.2.2
   ```

7. Pushing `v*` runs `.github/workflows/release.yml`, which re-runs gates, verifies the tag equals `pyproject.toml` version, builds artifacts and creates a GitHub Release with `gh release create`.
8. Verify the published Release assets and notes. Do not move or delete prior tags.

## What must not be automated without human OK

- Creating or moving tags
- Publishing GitHub Releases
- Uploading to package indexes
- Changing historical changelog sections or prior tag targets

## Rollback notes

- Prefer a new patch release over rewriting history.
- Do not delete or retarget an already-published tag without a documented incident decision.
- If `release.yml` fails after the tag exists, fix on `main` and cut a new patch; do not force-push the tag.
