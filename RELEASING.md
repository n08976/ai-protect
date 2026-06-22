# Releasing ai-protect to PyPI

Publishing is automated via **PyPI Trusted Publishing** (OIDC) — there is no API
token to create, store, or rotate. The `.github/workflows/release.yml` workflow
builds the distributions and uploads them when a GitHub Release is published.

## One-time setup (maintainer, ~2 minutes)

Because `ai-protect` doesn't exist on PyPI yet, register a **pending** trusted
publisher so the first release can create the project:

1. Sign in at <https://pypi.org> → **Account settings** → **Publishing** →
   **Add a pending publisher** (<https://pypi.org/manage/account/publishing/>).
2. Fill in exactly:
   | Field | Value |
   | --- | --- |
   | PyPI Project Name | `ai-protect` |
   | Owner | `n08976` |
   | Repository name | `ai-protect` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |
3. (Optional but recommended) In the GitHub repo → **Settings → Environments**,
   create an environment named `pypi` and add required reviewers so a human
   approves each publish.

## Cut a release

1. Bump `__version__` in `ai_protect/__init__.py` (PyPI versions are immutable —
   you can never re-upload the same version).
2. Commit + merge to `main`.
3. On GitHub: **Releases → Draft a new release**, create a tag like `v0.1.0`,
   write notes, **Publish release**.
4. The `publish to PyPI` workflow runs: builds an sdist + wheel, asserts the
   wheel ships only `ai_protect`, runs `twine check`, then uploads via OIDC.
5. Verify at <https://pypi.org/project/ai-protect/> and `pip install ai-protect`.

## Dry-run the build without publishing

Trigger the workflow manually (**Actions → publish to PyPI → Run workflow**).
The `publish` job is gated to `release` events, so a manual run builds, verifies,
and `twine check`s the artifacts but does **not** upload.

## Test on TestPyPI first (optional)

Add a TestPyPI pending publisher with the same fields, then temporarily point the
publish step at `repository-url: https://test.pypi.org/legacy/` to rehearse the
full flow before a real release.
