# pkg/enumerate

Core enumeration pipeline for GoGatoZ. Scans GitLab projects concurrently to discover CI/CD security issues by fetching project metadata, parsing `.gitlab-ci.yml` with transitive include resolution, running static analysis rules, correlating findings with runner risk signals, optionally scraping job logs, and generating structured reports (JSON, JSONL, text).

## Files

| File | Purpose |
|------|---------|
| `enumerator.go` | Core orchestrator: `EnumerateProjects()` entry point, worker pool, single-project scanner `scanOne()`, Result/Options structs |
| `adjust.go` | Post-analysis: `adjustFindingsForRunnerRisk()` bumps severity with executor-aware risk classes (shell=3, docker=2, kubernetes=1, ephemeral=0); `addExecutorFindings()` emits RUNNER_EXECUTOR_RISK findings; helper functions for executor risk classification |
| `adjust_protected.go` | Post-analysis: `adjustFindingsForProtectedBranches()` downgrades severity using `ProtectionLevel` classification (None/Heuristic/Structural/BranchGated) via structural rules evaluation and protected branch API data |
| `repo.go` | Repository utilities: `GetDefaultBranch()`, `FileExists()`, `ListRefs()` with pagination |
| `org/org.go` | Group enumeration: `ListGroupProjects()` with pagination |
| `report/report.go` | Report building and rendering: `Build()` aggregates results, renders as text/JSON/JSONL |
| `report/pterm.go` | PTerm-based text report renderer: `RenderPTerm()` with colored severity tables and bullet lists |

## Exported API

**Entry Point:**
- `EnumerateProjects(ctx, cl, idents, opts) ([]Result, error)` — scans projects concurrently, returns results per project (or per ref)
- `EnumerateProjectsStream(ctx, cl, idents, opts, emit) error` — streaming variant; calls `emit(Result)` per project without accumulating results in memory. `EnumerateProjects` is a thin wrapper around this.

**Types:**
- `Result` — JSON-serializable: ProjectID, PathWithNS, WebURL, DefaultBranch, ScannedRef, HasCIPipeline, CISummary, Findings ([]analyze.Finding), runner enrichment fields, ProtectedBranches, LogFindingsCount, DurationMS, Error
- `Options` — concurrency (int), Timeout (per-project), FollowIncludes, IncludeDepth, AllowRemoteIncludes, RemoteAllowlist, RemoteMaxBytes/Timeout/CacheTTL, Refs, MaxRefs, FetchProtected, FetchRunners, RunnerScope, AllowAdmin, LogScrape, LogMaxPipelines/Jobs, SkipAnalyze, Progress callback

**Utility Functions:**
- `GetDefaultBranch(ctx, cl, projectID)`, `FileExists(ctx, cl, projectID, ref, path)`, `ListRefs(ctx, cl, projectID, limit)`
- `org.ListGroupProjects(ctx, client, groupID, recursive)`
- `report.Build(results, opts)`, `report.RenderText/RenderJSON/RenderJSONL`

## Internal Patterns

- **Worker pool**: N goroutines (configurable concurrency, default 8) consume jobs channel, output to results channel. `sync.WaitGroup` coordination.
- **Streaming callback**: `Options.Progress` fires per completed project for real-time output (JSONL, stdout).
- **Per-project timeout**: Derived from parent context per project via `context.WithTimeout`. Prevents single project from blocking scan.
- **Ref multiplexing**: If `Options.Refs` set, scans each ref separately — one Result per (project, ref) pair.
- **Severity adjustment pipeline**: (1) analyze.Run() → base findings, (2) addExecutorFindings() → emit RUNNER_EXECUTOR_RISK findings (shell=CRITICAL, docker=MEDIUM), (3) adjustFindingsForRunnerRisk() → boost severity by executor risk class (shell→CRITICAL, docker→bump one level), (4) adjustFindingsForProtectedBranches() → downgrade severity by protection level (CRITICAL→HIGH→MEDIUM→LOW, never to INFORMATIONAL). Order matters.
- **False positive filtering**: Optional post-analysis step via `--filter-false-positives`. Applied in `cmd/enumerate.go` after `enumerateFunc()` and before `persistEnumerateResults()`. Uses `analyze.ApplyFPRules()` to mark findings; marked findings are persisted to DB with FP metadata.

## Testing

- Table-driven tests in `adjust_test.go` (15 scenarios: executor risk classes, bump logic, shell/docker/k8s behavior, legacy fallback, executor findings), `adjust_protected_test.go` (13 tests: ProtectionLevel classification, jobHasAlwaysRule, structural/heuristic/branch-gated downgrade, edge cases), `refs_test.go` (dedup/cap)
- `report/report_test.go` — aggregation, severity bucketing, and text template rendering with recommendations
- `enumerator_test.go` — dedup, progress callback, CI file parsing, project-not-found, context cancellation, default concurrency (uses `httptest` mock server)
- `org/org_test.go` — pagination, empty groups, 404 handling, nil client
- Findings structs created inline; pipeline Documents built directly
- Mock pattern: `httptest.NewServer` + `gitlabx.New(srv.URL, "tok")` with SDK pagination headers

## Dependencies

**Imports:**
- `pkg/gitlabx` — all external API calls (projects, runners, protected branches, repo files)
- `pkg/pipeline` — `Parse()`, `ResolveIncludesWithOptions()` for CI config resolution
- `pkg/analyze` — `Run()` for static analysis, `Finding`/`Severity` types
- `pkg/attack/secretsdump` — `ScrapeJobLogs()` for log-based secret discovery

**Depended on by:**
- `pkg/api` — API server invokes `EnumerateProjects()` via HTTP endpoints
- `cmd/enumerate.go` — CLI command

## Gotchas

1. **Per-project timeout is derived, not global** — total scan time ≈ timeout * (projects / concurrency)
2. **Non-fatal errors accumulated** — protected branch, runner, log scraping failures appended to `Result.Error` string with `;` separator
3. **Severity adjustment is ordered** — executor findings first, then runner risk boost, then protected branch downgrade (can downgrade a boosted severity)
4. **Empty Refs = default branch only**; non-empty Refs = only those refs (ignores default branch)
5. **Protected branch detection uses tiered classification** — ProtectionStructural (rules:if gates on CI_COMMIT_REF_PROTECTED), ProtectionBranchGated (verified against API protected branch list), ProtectionHeuristic (substring fallback). Structural/BranchGated gets full downgrade; Heuristic only downgrades HIGH→MEDIUM.
6. **Result ordering is non-deterministic** — reflects worker completion order. Report.Projects sorted by finding count desc, then path asc.
7. **Runner/protection adjustment only for specific finding IDs** — SELF_HOSTED_EXPOSED, MR_TAGGED_RUNNER, PRIVILEGED_RUNNER_RISK, PWN_REQUEST_DEPLOYMENT, RUNNER_EXECUTOR_RISK (via isRunnerRelatedFinding helper)
8. **Executor risk classification** — shell=3 (direct host), docker=2 (container escape potential), kubernetes=1 (pod isolation), docker+machine/autoscaler=0 (ephemeral). Only shell/docker emit RUNNER_EXECUTOR_RISK findings. Per-tag executor mapping stored in RunnerTagExecutors.

## Configuration

| Option | Default | Purpose |
|--------|---------|---------|
| `Concurrency` | 8 | Worker goroutines |
| `Timeout` | 0 (none) | Per-project timeout |
| `FollowIncludes` | false | Resolve transitive includes |
| `IncludeDepth` | 2 | Max recursion depth |
| `FetchRunners` | false | Fetch runner inventory |
| `RunnerScope` | "project" | Runner query scope |
| `LogScrape` | false | Scrape job logs for secrets |
| `SkipAnalyze` | false | Parse + summarize only |
