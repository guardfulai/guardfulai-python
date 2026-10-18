# Releases

Publishing changes public registry state and requires explicit maintainer authorization
for the exact source commit, version and artifact hashes. Account configuration and
repository visibility are separate owner actions. No live API requests are needed.

## Prepare locally

1. Update the version in `pyproject.toml` and the changelog, run `uv lock`, then
   `make setup`. Review all changes and run `make check package-check`.
2. Commit reviewed public source on `main`. Run the source/history audit again.
   Keep `dist/provenance.json` and its wheel/sdist hashes for release authorization.
   Artifacts contain only approved source; no private evidence belongs in this repository.
3. Obtain authorization for the source commit, version and the two artifact hashes.
   Version 0.1.0 is the initial release. A missing registry project does not reserve its name.

## One-time account setup

1. In GitHub, create `guardfulai/guardfulai-python` without generated initial files,
   under the approved visibility. Enable Actions. After the authorized initial push creates `main` and its CI checks,
   protect `main` using those checks; allow the initial bootstrap push first.
2. In repository Settings → Environments, create `pypi`, allow `v*` tags and add
   the release owner as required reviewer. Enable private vulnerability reporting
   in the repository security settings when available.
3. In PyPI account Publishing settings, configure a pending GitHub publisher:
   project `guardfulai`, owner `guardfulai`, repository `guardfulai-python`, workflow
   `publish.yml`, environment `pypi`. For an existing owned project, add the same
   publisher under that project's Publishing settings. Keep account credentials private.

See [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) and
[GitHub environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## Authorized release

Run `uv run --frozen --no-sync python scripts/release.py --version VERSION --github-user USERNAME --publish`
from the clean, reviewed public checkout, replacing VERSION with the accepted version
and USERNAME with the explicitly authorized maintainer's GitHub login. Alternatively,
set `GUARDFULAI_GITHUB_USER` and omit `--github-user`.

Use an SSH origin for `guardfulai/guardfulai-python`; an existing SSH host alias is
preserved and must resolve to `git@github.com`. Fetch and push URLs must match.
Git author/committer names must equal that login. The helper selects only that
GitHub CLI user's stored credential and verifies both API and SSH authentication
before any remote mutation. Ambient tokens and another active CLI account cannot
substitute for the requested identity. It does not alter account settings, Git
configuration, keys or remotes. Missing or mismatched identity stops the command.
This validates local artifacts, pushes reviewed main, creates/pushes its immutable tag,
and dispatches the exact workflow with accepted hashes. It never force-pushes.
Approve the waiting `pypi` environment deployment only for that accepted release.
Follow the workflow run printed by GitHub CLI; do not dispatch a second run while
one is active. The workflow validates and tests the same commit, compares artifact
hashes, then publishes those exact bytes with OIDC and attestations.

Run `uv run --frozen --no-sync python scripts/release.py --version VERSION --verify`
to compare PyPI artifacts with local acceptance, check publisher attestations, and
install the exact wheel and sdist independently. Verification uses registry downloads
and mocked tests; it does not call the service. Keep the resulting evidence.

## Recovery

A tag alone is not publication. Resume the existing tag only when it points to the
same accepted commit; never move it. On a workflow failure, inspect the failed job
and rerun that workflow after repairing platform configuration. Source changes need
fresh local acceptance. If any file reached PyPI, compare its digest before retrying;
never overwrite different bytes or silently skip an existing release. A partial upload
requires explicit recovery for the missing files, retaining matching accepted bytes.
A conflict in package ownership requires owner resolution, not an automatic rename.

Do not announce availability until registry hashes, attestations and clean installation
pass. Do not treat local checks as hosted CI or registry acceptance.
