---
name: bump-deps
description: Apply a round of Dependabot dependency bumps (npm, GitHub Actions, Go modules) without merging the Dependabot branch. Extracts just the intended changes onto the current branch, avoiding reverts of unrelated work that merged since the PR was opened. Use when processing Dependabot PRs or any grouped dependency update.
allowed-tools: Read, Grep, Glob, Edit, Bash(git *), Bash(cd docs *), Bash(npm *), Bash(node *), Bash(rg *), Bash(jq *)
---

# Bump Dependencies

## Golden rule: never merge the Dependabot branch

Dependabot branches are cut from whatever the default branch was when the PR
opened. That base is often behind the current branch, so merging the branch
also **reverts** unrelated work that merged in between. Always apply **just the
intended change to current `HEAD`** — extract the new values from the branch,
don't merge it.

```bash
git fetch origin --prune
# see what a dependabot branch actually changes:
git diff main..origin/dependabot/<ecosystem>/<branch-suffix> -- <relevant-paths>
```

## Ecosystems

### npm (docs/)

1. **Extract version bumps** from the Dependabot branch diff against
   `docs/package.json`. Only take the version range changes, not the lockfile.
2. **Apply to `docs/package.json`** on current HEAD — edit the version ranges
   in place.
3. **Regenerate lockfile**: `cd docs && npm install` (never copy the
   Dependabot lockfile — it's based on a stale tree).
4. **Verify build**: `cd docs && npm run build` — the Astro site must compile
   cleanly.
5. **Commit** as `chore(deps): bump docs npm dependencies` grouping all npm
   bumps together.

### GitHub Actions

1. **Extract SHA + tag bumps** from the Dependabot branch diff against
   `.github/workflows/`.
2. **Apply each SHA swap** in place — the format is
   `uses: owner/action@<sha> # ratchet:owner/action@<tag>`.
   Update BOTH the SHA and the ratchet tag comment when the tag changes.
3. **Check for other workflow files** using the same action at the old SHA —
   Dependabot may only update one workflow but the pin may appear in others.
   Sync ALL occurrences.
4. **Commit** as `ci(deps): bump github actions` grouping all action bumps
   together.

### Go modules

1. **Extract module bumps** from the Dependabot branch diff against `go.mod`.
2. **Apply**: `go get <module>@<version>` for each, then `go mod tidy`.
3. **Verify**: `go build ./...` and `go test ./...`.
4. **Commit** as `chore(deps): bump go modules`.

## Flag semantic jumps

Compare OLD and NEW versions and call out anything beyond a patch bump:
- Minor version bumps (e.g. `v9.0.0` → `v9.0.1` is fine; `v9.0.0` → `v9.1.0`
  needs a look)
- Major version bumps — these almost always need review
- New transitive dependencies added

Surface these to the user; don't bury them.

## Gotchas

- `gh` API returns 404 for this repo — use `git fetch` + `git diff` to read
  Dependabot branch content, not `gh pr view`.
- Dependabot targets `develop` as default branch for PRs but the repo's
  main integration branch is `main`.
- Do NOT push or close PRs yourself unless asked — the user pushes and manages
  PR lifecycle.
- Group commits by ecosystem: one for npm, one for GitHub Actions, one for Go.
  Don't mix ecosystems in a single commit.
