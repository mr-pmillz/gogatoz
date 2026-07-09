---
title: Release Process
description: Git flow branching model and release automation for GoGatoZ.
---

GoGatoZ follows a **gitflow** branching model with fully automated releases.
The version number lives in the branch name — there is no version constant to
bump in code.

## Branch Model

| Branch | Cut from | Merges into | Purpose |
|--------|----------|-------------|---------|
| `main` | — | — | Production-ready code. Every commit is releasable; tags live here. |
| `develop` | `main` | `main` (via `release/*`) | Integration branch for the next release. |
| `feature/*`, `fix/*` | `develop` | `develop` | Day-to-day work. |
| `release/vX.Y.Z` | `develop` | `main` **and** `develop` | Stabilise a release. |
| `hotfix/vX.Y.Z` | `main` | `main` **and** `develop` | Urgent production fix. |

### Branch policy enforcement

A `branch-policy.yml` workflow validates every PR:

| Source branch | Allowed target |
|---------------|----------------|
| `feature/*`, `fix/*` | `develop` only |
| `release/*`, `hotfix/*`, `develop` | `main` |
| Any | `develop` |
| Anything else | `main` **blocked** |

## Versioning

GoGatoZ does not keep a version constant in source. The version is resolved at
build time from one of three sources (in order):

1. **GoReleaser ldflags** — injected during the release build
   (`cmd.version`, `cmd.commit`, `cmd.date`).
2. **Module build info** — set automatically by `go install github.com/mr-pmillz/gogatoz@vX.Y.Z`.
3. **Fallback** — `dev` / `none` / `unknown` for plain `go build`.

The version is chosen exactly once: when you name the release branch
(`release/v0.8.0`).

## Cutting a Release

### 1. Prepare `develop`

Merge all feature/fix PRs destined for this release into `develop`. Verify CI
is green.

### 2. Create the release branch

```bash
git checkout develop
git pull origin develop
git checkout -b release/v0.8.0
git push -u origin release/v0.8.0
```

### 3. Stabilise

Only release-blocking fixes go on the release branch — no new features.
CI runs on every push to `release/**`.

### 4. Open a PR into `main`

```bash
gh pr create --base main --head release/v0.8.0 \
  --title "Release v0.8.0" \
  --body "Stabilised release branch for v0.8.0."
```

The branch policy check will pass because `release/*` is allowed to target
`main`. CI (build, lint, test, coverage) runs on the PR.

### 5. Merge

Merge the PR via GitHub (squash or merge commit — your call). This triggers
the full automation chain:

1. **`tag-release.yml`** detects the merged `release/*` branch, extracts the
   semver from the branch name, and pushes an annotated `v0.8.0` tag using a
   GitHub App token (so the push re-triggers other workflows).
2. **`release.yml`** fires on the new `v*` tag:
   - GoReleaser cross-compiles binaries for Linux, macOS, and Windows
     (amd64 + arm64).
   - Multi-arch container images are pushed to
     `ghcr.io/mr-pmillz/gogatoz`.
   - `git-cliff` generates release notes from conventional commits.
   - A GitHub Release is published with the binaries and changelog.
   - Build provenance is attested for both archives and container images.
3. A follow-up **changelog** job regenerates the full `CHANGELOG.md` and
   commits it to `main`.
4. The changelog commit triggers **`docs.yml`**, which rebuilds and redeploys
   the documentation site.

### 6. Back-merge `main` into `develop`

Sync the changelog commit and any release-branch fixes back to `develop`:

```bash
git checkout develop
git pull origin develop
git merge origin/main
git push origin develop
```

## Hotfix Process

For urgent production fixes that cannot wait for the next release:

```bash
git checkout main
git pull origin main
git checkout -b hotfix/v0.8.1
# fix, commit, push
gh pr create --base main --head hotfix/v0.8.1 \
  --title "Hotfix v0.8.1" \
  --body "Fixes critical issue XYZ."
```

Merge the PR — the same automation chain fires (`tag-release.yml` →
`release.yml` → changelog → docs). Then back-merge `main` into `develop`.

## Emergency Manual Tag

If the automation fails, you can always tag manually:

```bash
git tag -a v0.8.0 -m "Release v0.8.0"
git push origin v0.8.0
```

This works because `release.yml` triggers on any `v*` tag push regardless of
how it was created.

## One-Time Setup

Before this flow works, the repository needs:

1. **GitHub App** — create a GitHub App with **Contents: write** permission,
   install it on the repository, and add its credentials as repository secrets:
   - `GOGATOZ_APP_ID` — the App's numeric ID.
   - `GOGATOZ_APP_PRIVATE_KEY` — the App's PEM private key.
2. **Branch protection bypass** — add the GitHub App to the branch/tag
   protection bypass list so it can push tags and commits to protected `main`.
3. **Changelog token** — the `GOGATOZ_CHANGELOG_TOKEN` secret (a PAT or App
   token) used by `git-cliff` to link PRs and authors in the changelog.

## CI Pipeline

The CI workflow (`ci.yml`) runs on:

- Pushes to `main`, `develop`, `release/**`, and `hotfix/**`.
- PRs targeting `main` or `develop`.

Jobs: **build** → **lint** (golangci-lint v2) → **test** (race detector +
coverage).
