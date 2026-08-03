# Runner and token reconnaissance TDD evidence

## Source

The user journeys were derived during this implementation; no external plan
file was used.

## User journeys

1. As an assessor without runner-admin access, I can recover bounded runner
   metadata from jobs I am already authorized to read.
2. As an assessor, I can distinguish direct runner API evidence from job API
   and trace evidence.
3. As a token holder, I can map read and inferred write capabilities without
   changing GitLab state.
4. As a token holder, I can add project role and protected-branch context to
   the capability map.

## RED and GREEN evidence

| Behavior | RED evidence | GREEN evidence |
|---|---|---|
| Bounded multi-job runner discovery and fallback after runner API denial | `go test ./pkg/enumerate -run 'TestDiscoverRunnersFromLogs|TestScanOne_RunnerAPIDenied' -count=1` failed on the missing discovery API, limits, metadata fields, and fallback result | The same focused tests pass; `go test -race ./pkg/enumerate` also passes |
| Read-only scope, role, and branch inference | `go test ./pkg/validate -count=1` failed on the missing probe options, status model, and project inference | `go test -race ./pkg/validate` passes |
| CLI target mapping | `go test ./cmd -run 'TestValidate_' -count=1` failed on the missing target flag and probe injection point | `go test -race ./cmd ./pkg/validate` passes |
| Runner sampling flags | `go test ./cmd -run TestEnumerate_LogScrape_Flags_Map_To_Options -count=1` failed on the missing runner sampling flag variables | The focused command test and package race suite pass |

## Guarantees

| # | Guarantee | Test |
|---|---|---|
| 1 | Runner discovery obeys configured pipeline, job, and trace-size bounds | `TestDiscoverRunnersFromLogs_BoundedAndMergesMetadata` |
| 2 | Job API and trace metadata are merged and deduplicated with provenance | `TestDiscoverRunnersFromLogs_BoundedAndMergesMetadata` |
| 3 | Runner API denial falls back to historical job evidence | `TestScanOne_RunnerAPIDeniedFallsBackToJobLogs` |
| 4 | Project capability probing sends only GET requests | `TestProbeTokenWithOptions_ReadOnlyProjectInference` |
| 5 | Protected-branch rules prevent overclaiming default-branch push access | `TestProbeTokenWithOptions_ReadOnlyProjectInference` |
| 6 | Missing PAT scope introspection produces `unknown` write capabilities | `TestProbeToken_UnknownScopesDoNotOverclaimWrites` |
| 7 | `validate --target` trims and forwards a project path | `TestValidate_TargetFlagMapsToReadOnlyProbe` |

## Coverage and known gaps

The final focused coverage run measured 83.1% statement coverage for
`pkg/enumerate/logrunner.go` and 81.8% for `pkg/validate/validate.go`. The final
verification gate passed:

- `go build ./...`
- `go test -race -count=1 ./...`
- `golangci-lint run -c .golangci-lint.yml ./...` (`0 issues`)
- the GoGatoZ documentation build (37 pages)
- the Hacker's Guide documentation build (41 pages)

Live QA used `root/runner-observability`, an inert local GitLab fixture created
through `setup-lab.sh`. The bot received HTTP 403 from the instance runner API,
then GoGatoZ recovered a high-confidence shell runner from both `job_api` and
`job_trace`. The fixture's CI was separately checked for package managers,
downloads, includes, artifacts, and variables; none are present. A second setup
run was idempotent.

Runner evidence is limited to jobs visible to the token and cannot reveal
runners that have no accessible historical jobs. Group-specific protected-branch
grants remain unknown when membership cannot be established safely.
