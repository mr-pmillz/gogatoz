# P0 depx integration — TDD evidence

## Source and user journeys

No external plan file was used. The journeys were derived from the P0 feature
request and the StepSecurity threat-intelligence review:

1. As a defender, I can audit dependency metadata with ProjectDiscovery depx
   without installing or executing a package.
2. As a GitLab operator, I can include dependency findings in `enumerate` and
   export the same findings as JSON, SARIF, or GitLab SAST.
3. As a security reviewer, I receive a HIGH finding for mutable project or
   component include refs and clear full-commit-SHA remediation.
4. As a lab maintainer, I can validate the integration against local GitLab
   using only fabricated, inert metadata and no real malicious package.
5. As a scanner user, untrusted GitLab archives remain bounded and confined;
   links, traversal, devices, and other filesystem-capable tar types are
   rejected.
6. As a release owner, I can require a configurable minimum package age and
   detect dormant-package resurrection or coordinated release bursts without
   downloading a package artifact.
7. As a GitLab operator, I can audit every publishing branch/tag gate and
   monitor ref SHA movement, tag recreation, short-lived CI branches, release
   bursts, and publishing-workflow changes.

## RED/GREEN checkpoints

All checkpoints are reachable from `feat/techniques` at the time of this
report.

| Behavior | RED checkpoint | GREEN checkpoint | Evidence |
|---|---|---|---|
| Native depx audit and finding mapping | `1d6c6b7` | `f1c3bea` | New native integration tests failed before `pkg/depscan` and the bridge existed, then passed with the in-process adapter. |
| CLI, enumeration, source paths, SARIF, and GitLab SAST | `c8fe5fa` | `f76af6b` | Command/enumerator/reporter tests failed before the flags and report mapping existed, then passed across supported formats. |
| Mutable include release refs | `2a2804b` | `c66a6ca` | Governance tests failed for tags, branches, selectors, short SHAs, and dynamic refs, then passed while full 40/64-character SHAs remained accepted. |
| GitLab POSIX PAX archive metadata | `b2e18f0` | `dd53721` | RED: `unsupported archive entry: "GlobalHead.0.0" has tar type 103`; GREEN permits only `TypeXGlobalHeader` metadata and retains all link/type rejections. |
| SBOM discovery inside GitLab archives | `f81cf3f` | `df42676` | RED: `audit paths = [.../repository], want extraction root plus explicit SBOM path`; GREEN passes depx the root plus bounded, regular SBOM files and removes temporary paths from output. |
| Threat-feed IP and hash indicators | `bc0d7ca` | `820c484` | Exact IP and token-bounded hash tests failed while the parsed feed fields were unused, then passed through `CAMPAIGN_MATCH`. |
| Dependency report formats | `59926dc` | `8f6025d` | CycloneDX, SPDX 2.3, and GitLab Dependency Scanning 15.2.4 command tests failed before native depx/report integration, then passed. |
| Release branch and tag governance | `2a9c1c1` | `9d04eb2` | Publishing-job tests failed before protected branch/tag evaluation existed, then passed for broad, weak, and reviewed release paths. |
| Release ref lifecycle monitoring | `c422216` | `bd7f967` | Ref-state tests failed before the monitor existed, then passed for rewrites, tag retarget/recreation, short-lived CI branches, and bursts. GitLab snapshot and command integration continued in `5ee8dc2`/`8151774` and `5f1a6db`/`717f32e`. |
| Package release intelligence | `e7f5820` | `d7d7132` | Native component/cooldown tests failed before release metadata enrichment, then passed for npm, PyPI, RubyGems, dormancy, bursts, and fail-open warnings. |
| GitLab dependency report release findings | `7ceed1d` | `b1f8549` | Report tests failed before release-intelligence findings were assigned an exact package/version location, then passed against the official schema. |

Coverage was raised in `51ac468` with native-adapter, close, and bounded-writer
tests. Documentation was recorded in `968a238`.

## Test specification

| # | What is guaranteed | Test file or command | Type | Result |
|---:|---|---|---|---|
| 1 | Malicious and quarantined depx verdicts map to CRITICAL GoGatoZ findings with source metadata | `pkg/depscan/depscan_test.go` | Unit | PASS |
| 2 | Native depx consumes a synthetic gzipped inventory in-process and audits an inert lockfile | `pkg/depscan/native_test.go` | Integration | PASS |
| 3 | Concurrent scans serialize access to the native depx service | `pkg/depscan/depscan_test.go` | Race/unit | PASS |
| 4 | Archive traversal, links, compressed/expanded size overflow, and entry-count overflow are rejected | `pkg/depscan/archive_test.go` | Security unit | PASS |
| 5 | GitLab PAX global metadata is accepted without allowing another non-file tar type | `pkg/depscan/archive_test.go` | Regression | PASS |
| 6 | GitLab repository scanning uses bounded archives, discovers SBOMs, and reports repository-relative paths | `pkg/depscan/gitlab_test.go` | Integration | PASS |
| 7 | `deps audit` validates options and emits text, JSON, SARIF, GitLab SAST, GitLab Dependency Scanning, CycloneDX, and SPDX | `cmd/deps_test.go` | Command integration | PASS |
| 8 | `enumerate --dependencies` works even when no `.gitlab-ci.yml` exists | `pkg/enumerate/enumerator_test.go` | Integration | PASS |
| 9 | Dependency taxonomy is emitted in both SARIF and GitLab SAST | `cmd/sarif_test.go`, `cmd/glsast_test.go` | Reporter unit | PASS |
| 10 | Mutable tags/branches/selectors/short SHAs are findings; full commit SHAs are not | `pkg/analyze/governance_test.go` | Unit | PASS |
| 11 | Live local GitLab returns one synthetic `MALICIOUS_DEPENDENCY` at `bom.cdx.json` | `release-metadata-service` Tier 2 QA command | E2E | PASS |
| 12 | The safe CTF fixture has four inert files, a disabled workflow, no external threat references, and zero pipelines | GitLab API safety assertions | E2E/security | PASS |
| 13 | Cooldown analysis uses depx's native exact-version component export and bounded metadata-only registry requests | `pkg/depscan/release_intel_test.go` | Unit/integration | PASS |
| 14 | Publishing branch/tag governance reaches SARIF and GitLab SAST taxonomy | `pkg/enumerate/release_governance_test.go`, reporter tests | Unit | PASS |
| 15 | Ref monitoring distinguishes fast-forward movement, rewrite, tag lifecycle, short-lived CI branches, and release-workflow changes | `pkg/refwatch/monitor_test.go`, `cmd/watch_test.go` | Unit/command integration | PASS |
| 16 | Baseline-only live ref monitoring keeps JSON stdout empty and parseable while status stays on stderr | `release-metadata-service` Tier 2 QA command | E2E | PASS |

## Validation results

Final commands run:

```text
go build ./...                                      PASS
go test -race -count=1 ./...                       PASS
golangci-lint run -c .golangci-lint.yml ./...      PASS (0 issues)
go mod verify                                      PASS (all modules verified)
cd internal/depxbridge && go build ./...            PASS
cd internal/depxbridge && go test -race -count=1 ./...  PASS
cd internal/depxbridge && golangci-lint ...         PASS (0 issues)
npm run build  # gogatoz/docs                       PASS (36 pages)
npm run build  # hackers-guide-to-cicd              PASS (41 pages)
```

The non-destructive CTF Tier 2 matrix passed GitLab/flagserver health, the
four-file/zero-pipeline fixture safety assertions, all seven `deps audit`
formats, the live GitLab dependency scan, and a baseline-only ref-watch poll.
Cooldown enrichment remained disabled, so the matrix made zero public-registry
queries and downloaded no package artifact.

## Coverage and known gaps

- `pkg/depscan`: **82.9% statements** (`go test -coverprofile ... ./pkg/depscan`)
- `internal/depxbridge`: **87.0% statements**
- `govulncheck` was not installed, so it was reported as skipped rather than
  installed over the network. Module checksum verification passed.
- depx v0.1.1 discovers lockfiles recursively but accepts SBOMs as explicit
  file paths. GoGatoZ supplements this only for bounded GitLab archives; users
  of standalone `deps audit` should pass an SBOM path explicitly.
- The CTF inventory is synthetic and selected with `DEPX_SOURCE_URL`; it is not
  production threat intelligence and contains no real package URL or reference.

## Merge evidence

The RED/GREEN checkpoint commits above intentionally remain unsquashed on the
active branch. If they are later squashed, copy this section into the PR body or
squash commit message so the test-first sequence remains reviewable.
