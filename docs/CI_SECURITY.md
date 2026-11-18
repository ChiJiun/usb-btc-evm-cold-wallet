# CI and repository security controls

Issue #4 enables a defense-in-depth CI baseline for this prototype.  The
workflow is intentionally read-only and does not receive deployment secrets.

## Required CI gate

The authoritative workflow is `.github/workflows/ci.yml`.  It runs:

- pytest on CPython 3.12 and 3.13 using a hash-locked dependency set;
- `pip check` and `pip-audit`;
- Gitleaks over repository history;
- GitHub dependency review on pull requests;
- two clean wheel builds with a fixed `SOURCE_DATE_EPOCH`, requiring identical
  SHA-256 output.

Third-party GitHub Actions are pinned to full commit SHAs and checkout disables
credential persistence.  The stable status check for branch protection is
`CI / Required`.

## Dependency lock

`requirements/ci.lock` pins the complete CI dependency graph and records
SHA-256 hashes for source distributions plus Linux x86_64 wheels relevant to
CPython 3.12/3.13.

Regenerate it only as an intentional dependency change:

```bash
python -m pip install -e ".[dev]"
python scripts/refresh_ci_lock.py
```

Review the resulting dependency and hash diff before merging.  Dependabot is
configured for both Python dependencies and GitHub Actions.

## Main branch protection

After the workflow exists on GitHub and has completed successfully at least
once, protect `main` with these minimum settings:

- require a pull request before merging;
- require the `CI / Required` status check and require the branch to be up to
  date before merging;
- require conversation resolution;
- block force pushes and branch deletion.

For a single-maintainer repository, zero required approving reviews is
reasonable; the security boundary here is the required CI gate, not a fake
self-approval.

GitHub native secret scanning and push protection should also be enabled in the
repository security settings.  Gitleaks remains in CI as an independent
history scan.

Do not weaken these controls merely to merge a failing change.  Investigate the
failing job or update the locked dependency/action pins in a reviewed PR.
