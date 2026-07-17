# Feature Expansion: 6 New Analysis Capabilities

**Date:** 2026-07-16  
**Branch:** feat/research  
**Status:** Design approved, pending implementation

## Overview

Six new analysis features for GoGatoZ, all implemented on a single branch. Each integrates into the existing `enumerate` → `report` pipeline where possible, with new subcommands only where the workflow is fundamentally different (drift detection, group dashboard).

## Feature 28: CI/CD Variables Inheritance Analysis

### Problem

GitLab CI/CD variables inherit through a chain: instance → group → project → job (YAML). Variables can be masked, protected, or scoped to environments. An attacker who can trigger MR pipelines may be able to shadow protected variables with attacker-controlled values, or exploit unmasked/unprotected secrets. GoGatoZ currently only checks for plaintext secrets in YAML variables and injection patterns in scripts — it doesn't model the full inheritance chain from the API.

### Design

**Data collection** — New `pkg/enumerate/variables.go`:
- `VariableInfo` struct: `Key`, `Protected` (bool), `Masked` (bool), `EnvironmentScope` (string), `Source` (string: "project", "group", "job")
- `FetchProjectVariables(ctx, client, projectID)` → `[]VariableInfo` using `GL.ProjectVariables.ListVariables`
- `FetchGroupVariables(ctx, client, groupID)` → `[]VariableInfo` using `GL.GroupVariables.ListVariables`
- Values are never stored — only metadata (key name, protection flags, scope)

**Analysis** — New `pkg/analyze/variables.go`:
- `detectVariableInheritanceRisk(doc *pipeline.Document, projectVars, groupVars []VariableInfo) []Finding`
- Finding: `VAR_INHERITANCE_SHADOW` (Medium) — a YAML job variable shadows a protected group/project variable. Evidence includes the variable key and which scope shadows which.
- Finding: `VAR_UNMASKED_SECRET` (High) — a project/group variable key matches secret patterns (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`, `*CREDENTIAL*`) but `Masked` is false. This means the value is visible in job logs.
- Finding: `VAR_UNPROTECTED_SECRET` (High) — a variable is masked but not protected, meaning it's accessible from unprotected branches and MR pipelines. Masked-only is insufficient when the threat model includes MR-based exfiltration.
- Finding: `VAR_MR_OVERRIDE_RISK` (Medium) — a CI variable referenced in scripts (via `$VAR` or `${VAR}`) exists at project/group level but is not protected, so an MR pipeline can override it with a malicious value.

**Integration:**
- New `--fetch-variables` flag on `enumerate` (default: false, requires `api` scope on token)
- `enumerate.Options.FetchVariables` bool field
- `enumerate.Result.ProjectVariables` and `GroupVariables` fields (`[]VariableInfo`)
- Findings flow through existing report pipeline
- New report section: "Variable Inheritance" in pterm/HTML output showing variable scope table

**Persistence:**
- New `store.VariableMetadata` GORM model: `EnumerateResultID`, `Key`, `Protected`, `Masked`, `EnvironmentScope`, `Source`

### Finding Registry Entries

| ID | Severity | CWE | ATT&CK | OWASP CICD |
|----|----------|-----|--------|------------|
| VAR_INHERITANCE_SHADOW | Medium | CWE-807 | T1574.001 | CICD-SEC-4 |
| VAR_UNMASKED_SECRET | High | CWE-312 | T1552.001 | CICD-SEC-2 |
| VAR_UNPROTECTED_SECRET | High | CWE-668 | T1552.001 | CICD-SEC-2 |
| VAR_MR_OVERRIDE_RISK | Medium | CWE-807 | T1574.001 | CICD-SEC-4 |

---

## Feature 25: Environments/Deployments Analysis

### Problem

GitLab environments define deployment targets with optional protection rules (required approvals, branch restrictions). A project with unprotected environments can be exploited: an MR pipeline can trigger a deployment to production without approval. GoGatoZ's `PWN_REQUEST_DEPLOYMENT` finding checks whether a job references an environment, but doesn't verify whether that environment actually has protection rules via the API.

### Design

**Data collection** — New `pkg/enumerate/environments.go`:
- `EnvironmentInfo` struct: `ID` (int64), `Name`, `Tier` (string: production/staging/testing/development/other), `ExternalURL`, `State` (available/stopped), `AutoStopIn` (string), `ProtectedBranches` ([]string), `RequiredApprovalCount` (int), `LastDeployedAt` (*time.Time)
- `FetchEnvironments(ctx, client, projectID)` → `[]EnvironmentInfo` using `GL.Environments.ListEnvironments` with pagination
- For each environment, fetch protection rules via `GL.ProtectedEnvironments.GetProtectedEnvironment` (requires Maintainer+ access)

**Analysis** — New `pkg/analyze/environment.go`:
- `detectEnvironmentRisks(doc *pipeline.Document, envs []EnvironmentInfo) []Finding`
- Finding: `ENV_UNPROTECTED_DEPLOY` (High) — a job deploys to an environment that has no protection rules (no branch restrictions, no approval requirements). The environment tier is included in evidence — production/staging without protection is more severe.
- Finding: `ENV_NO_APPROVAL_GATE` (Medium) — a production-tier environment exists but `RequiredApprovalCount` is 0. This means any pipeline reaching the deploy stage can deploy without human review.
- Finding: `ENV_MR_DEPLOY_RISK` (High) — a job that runs on MR pipelines (rules include `merge_request_event` or `CI_MERGE_REQUEST_IID`) deploys to an environment. Combined with `ENV_UNPROTECTED_DEPLOY` this is a direct exploitation path.
- Finding: `ENV_STALE_DEPLOYMENT` (Low) — an environment with `State: available` hasn't had a deployment in 90+ days. May represent an abandoned attack surface with outdated code.

**Integration:**
- New `--fetch-environments` flag on `enumerate` (default: false)
- `enumerate.Options.FetchEnvironments` bool field
- `enumerate.Result.Environments` field (`[]EnvironmentInfo`)
- Enriches existing `PWN_REQUEST_DEPLOYMENT` findings: if environment protection data is available, the finding description is upgraded with actual protection status

**Interaction with Feature 28:**
- Environment-scoped variables (from Feature 28) cross-reference environment names from this feature. A variable scoped to a non-existent environment is flagged.

### Finding Registry Entries

| ID | Severity | CWE | ATT&CK | OWASP CICD |
|----|----------|-----|--------|------------|
| ENV_UNPROTECTED_DEPLOY | High | CWE-284 | T1195.002 | CICD-SEC-5 |
| ENV_NO_APPROVAL_GATE | Medium | CWE-862 | T1195.002 | CICD-SEC-5 |
| ENV_MR_DEPLOY_RISK | High | CWE-284 | T1195.002 | CICD-SEC-3 |
| ENV_STALE_DEPLOYMENT | Low | CWE-1188 | T1190 | CICD-SEC-7 |

---

## Feature 24: CI/CD Config Drift Detection

### Problem

CI/CD configurations change over time. Security regressions can be introduced by removing security scanning jobs, adding new remote includes, weakening pipeline rules, or modifying script content. There's no way to compare a CI config against a known-good baseline or previous version to detect these changes.

### Design

**New subcommand** — `cmd/drift.go`:
- `gogatoz drift --project <id-or-path> [--ref <current-ref>] [--baseline-ref <previous-ref>] [--save-baseline] [--compare-baseline] [--format text|json|jsonl] [-o output]`
- Two operating modes:
  1. **Git history mode** (`--baseline-ref`): Fetches `.gitlab-ci.yml` at two refs via `GL.RepositoryFiles.GetFile`, parses both, computes structural diff
  2. **Baseline mode** (`--save-baseline` / `--compare-baseline`): Stores current config in SQLite as a baseline, or compares current config against stored baseline

**Diff engine** — New `pkg/drift/`:
- `differ.go`:
  - `DriftReport` struct: `ProjectPath`, `CurrentRef`, `BaselineRef`, `Timestamp`, `Changes []Change`, `SecurityImpact []SecurityChange`
  - `Change` struct: `Type` (added/removed/modified), `Category` (job/variable/include/stage/rule/script), `Name`, `OldValue`, `NewValue`, `Detail`
  - `Diff(baseline, current *pipeline.Document) DriftReport` — structural comparison:
    - Jobs: added, removed, modified (compares script content, rules, tags, image, environment, variables)
    - Includes: added/removed includes (tracks type and location)
    - Variables: added/removed/modified global and job-level variables
    - Stages: added/removed stages
    - Workflow rules: changed workflow-level rules
  
- `security.go`:
  - `SecurityChange` struct: `Severity`, `Category`, `Description`, `Change`
  - `AssessSecurityImpact(changes []Change) []SecurityChange` — classifies each change:
    - Critical: security scanning job removed (SAST/DAST/secret detection/dependency scanning patterns)
    - High: new remote/project include added (supply chain risk), script content changed in deployment jobs
    - Medium: job rules weakened (fewer restrictions), protected branch rules removed
    - Low: variable added/removed, stage reordering, image tag changes

- `baseline.go`:
  - GORM model: `ConfigBaseline{ID, ProjectID, ProjectPath, Ref, ConfigHash (SHA-256), ConfigYAML (text), ResolvedYAML (text, optional), SavedAt}`
  - `SaveBaseline(db, projectID, path, ref, yaml)` and `LoadBaseline(db, projectID)` operations
  - Hash comparison for quick "has anything changed?" check before full diff

**Include resolution for drift:**
- Both baseline and current configs can optionally have includes resolved (`--follow-includes` flag)
- Diff operates on the resolved document for comprehensive comparison
- Unresolved comparison is faster and catches direct config changes

**Output formats:**
- Text: colored diff output using pterm, security changes highlighted by severity
- JSON/JSONL: machine-readable drift report with all changes and security assessments

**No new finding IDs in the main analyzer** — drift detection is a separate workflow, not part of the standard enumerate pipeline. The drift command produces its own report format. However, the security assessment reuses severity levels and categorization from the analyzer.

---

## Feature 23: Group-Level Security Dashboard

### Problem

GoGatoZ produces per-project reports. Organizations need a group-level view showing security posture across all projects: which projects are high-risk, what the common findings are, how runner exposure distributes, and what the overall security score is.

### Design

**New subcommand** — `cmd/dashboard.go`:
- `gogatoz dashboard --group <id-or-path> [--from-db] [--from-jsonl <file>] [--scan] [--format text|json|html] [-o output]`
- Three data source modes:
  1. **Live scan** (`--scan`, default if no other source): Runs enumerate on all group projects, builds dashboard from results
  2. **From database** (`--from-db`): Loads most recent scan session for the group from SQLite
  3. **From file** (`--from-jsonl`): Reads enumerate JSONL output file

**Dashboard model** — New `pkg/dashboard/`:
- `dashboard.go`:
  - `Dashboard` struct: `GroupName`, `GroupID`, `GeneratedAt`, `ProjectCount`, `ScannedCount`, `Scorecards []ProjectScorecard`, `Aggregate AggregateMetrics`, `TopFindings []FindingFrequency`, `RiskDistribution RiskDistribution`
  - `ProjectScorecard`: `ProjectPath`, `Score` (0-100), `RiskTier` (Critical/High/Medium/Low/Clean), `FindingsBySeverity map[string]int`, `HasCI` (bool), `HasSecurityJobs` (bool), `HasProtectedBranches` (bool), `RunnerExposure` (string)
  - `AggregateMetrics`: `MeanScore`, `MedianScore`, `P10Score` (worst decile), `CICoverage` (% with CI), `SecurityJobCoverage` (% with security scanning), `ProtectedBranchCoverage` (%), `TotalFindings`, `TotalCritical`, `TotalHigh`
  - `FindingFrequency`: `FindingID`, `Count`, `ProjectCount`, `Severity`
  - `RiskDistribution`: `Critical`, `High`, `Medium`, `Low`, `Clean` (project counts per tier)
  - `Build(results []enumerate.Result, groupName string, groupID int64) Dashboard`

- `scorer.go`:
  - Scoring algorithm: starts at 100, deductions per finding severity:
    - Critical: -15 per finding (floor 0)
    - High: -8 per finding
    - Medium: -3 per finding
    - Low: -1 per finding
    - Bonuses: +5 for having security scanning jobs, +5 for protected default branch, +5 for all runners using Docker executor
  - Risk tier thresholds: Critical (0-20), High (21-40), Medium (41-60), Low (61-80), Clean (81-100)

- `pterm.go`:
  - Group header with score and risk tier
  - Summary cards row (total projects, scanned, CI coverage, mean score)
  - Project scorecard table sorted by score (ascending = worst first): project path, score, tier, critical/high/medium/low counts, CI, security jobs, protected branches
  - Top findings table: finding ID, severity, count, affected projects
  - Risk distribution bar

- `html.go` + `html_template.html`:
  - Self-contained HTML (same approach as existing report: Bootstrap 5 + Chart.js + DataTables)
  - Group header with overall score gauge
  - Risk distribution doughnut chart
  - Score distribution histogram
  - Project scorecard DataTable (sortable, searchable, CSV export)
  - Top findings horizontal bar chart
  - Coverage metrics cards (CI %, security jobs %, protected branches %)
  - Per-severity finding trend (if historical data available from DB)

---

## Feature 22: SBOM Extension (pkg/pbom/)

### Problem

The existing PBOM package generates CycloneDX output for container images and CI includes, but lacks SPDX support. It's also a standalone command — PBOM data isn't integrated into the enumerate/report pipeline, so there's no unified view of supply chain artifacts alongside security findings.

### Design

**SPDX output** — New `pkg/pbom/spdx.go`:
- `SPDX` struct following SPDX 2.3 JSON schema: `SPDXVersion`, `DataLicense` ("CC0-1.0"), `SPDXID`, `Name`, `DocumentNamespace`, `CreationInfo`, `Packages`, `Relationships`
- `ToSPDX(toolVersion string) SPDX` method on `PBOM`:
  - Container images → SPDX packages with `pkg:docker/...` external refs
  - CI includes → SPDX packages with type-specific external refs (git URL for project includes, HTTP URL for remote includes)
  - Relationships: `DESCRIBES` from document to each package, `DEPENDENCY_OF` for includes
- `cmd/pbom.go`: Add `spdx` to accepted `--format` values

**Enumerate integration:**
- New `--generate-pbom` flag on `enumerate` (default: false)
- `enumerate.Options.GeneratePBOM` bool field
- When set, `scanOne()` runs `pbom.NewGenerator(...).Generate(doc)` after parsing and before analysis
- `enumerate.Result.PBOM *pbom.PBOM` field (included in JSONL output when present)
- PBOM data available to the report builder

**Report integration:**
- Existing "Supply Chain" section in report enriched with PBOM summary when available:
  - Total container images, unique registries, images without digest pinning
  - Total CI includes by type, unpinned project includes (no ref specified)
- New analyze rules leveraging PBOM data:
  - `SBOM_UNPINNED_IMAGE` (Medium) — image uses `:latest` or has no tag. This extends the existing `UnpinnedPackageInstallID` concept to container images specifically.
  - `SBOM_NO_DIGEST` (Low) — image reference has no `@sha256:` digest for reproducibility.

### Finding Registry Entries

| ID | Severity | CWE | ATT&CK | OWASP CICD |
|----|----------|-----|--------|------------|
| SBOM_UNPINNED_IMAGE | Medium | CWE-829 | T1195.002 | CICD-SEC-9 |
| SBOM_NO_DIGEST | Low | CWE-345 | T1195.002 | CICD-SEC-9 |

---

## Feature 19: GitLab Pages CI/CD Analysis

### Problem

GitLab Pages jobs deploy static content via CI pipelines. Pages can expose sensitive information (coverage reports, API docs, internal documentation) publicly, and MR-triggered pages jobs can be exploited for content injection. The existing false-positive rule for `ARTIFACTS_NO_EXPIRE` on pages jobs shows the parser already identifies pages jobs, but no security analysis is performed.

### Design

**Analysis** — New `pkg/analyze/pages.go`:
- `detectPagesRisks(doc *pipeline.Document) []Finding`
- Detection logic:
  1. Identify pages jobs: `job.Name == "pages"` OR `job.Stage == "pages"` OR job has `artifacts.paths` with `public/` (GitLab Pages convention)
  2. Check MR trigger rules: if pages job runs on `merge_request_event` or has no branch restrictions → `PAGES_MR_DEPLOY_RISK`
  3. Check artifact paths for sensitive patterns: `coverage/`, `api/`, `docs/internal/`, `storybook/`, `.env`, `config/` → `PAGES_SENSITIVE_PATH`
  4. Flag pages deployment in public projects with no access control → `PAGES_PUBLIC_DEPLOY`

**Finding details:**
- `PAGES_PUBLIC_DEPLOY` (Medium) — Pages job in a project that appears to deploy content publicly. Evidence: job name, artifact paths. Remediation: enable Pages access control or verify content is intended to be public.
- `PAGES_MR_DEPLOY_RISK` (High) — Pages job can be triggered from MR pipelines, allowing content injection via MR. An attacker can deploy arbitrary content to the project's Pages URL. Evidence: job name, triggering rules. Remediation: restrict pages job to protected branches only.
- `PAGES_SENSITIVE_PATH` (Medium) — Pages artifacts include paths that commonly contain sensitive information. Evidence: job name, matched paths. Remediation: review published paths, exclude sensitive directories.

**Integration:**
- Added to `steps` table in `analyze.Run()` — no opt-in flag needed (pure YAML analysis)
- Works with existing false-positive system: `pagesArtifactsRule()` already handles the `ARTIFACTS_NO_EXPIRE` case for pages jobs

### Finding Registry Entries

| ID | Severity | CWE | ATT&CK | OWASP CICD |
|----|----------|-----|--------|------------|
| PAGES_PUBLIC_DEPLOY | Medium | CWE-200 | T1530 | CICD-SEC-7 |
| PAGES_MR_DEPLOY_RISK | High | CWE-284 | T1195.002 | CICD-SEC-3 |
| PAGES_SENSITIVE_PATH | Medium | CWE-200 | T1530 | CICD-SEC-7 |

---

## CTF Lab Testing Strategy

Each feature will be QA'd against the CTF lab using the `ctf-qa-validation` skill. For features that need new test targets:

- **Variables (#28):** Test against existing `MrPMillz/vuln` repo which has CI variables (`MY_SECRET`, `EXFIL_SECRET`). Add masked/unmasked/protected variable combinations to test detection.
- **Environments (#25):** Create a new `vuln-environments` repo in the CTF lab with configured environments (production with no protection, staging with approval gates).
- **Drift (#24):** Test against any existing repo by comparing current ref against an older commit. Create a `vuln-drift` repo with intentionally regressed CI config (security job removed between commits).
- **Dashboard (#23):** Test using the existing `MrPMillz/` group which has 27+ vuln repos — natural group-level aggregation test.
- **SBOM (#22):** Test against existing repos — the PBOM generator already works. Verify SPDX output format and unpinned image detection.
- **Pages (#19):** Create a `vuln-pages` repo with a pages job that deploys from MR pipelines with sensitive artifact paths.

---

## Implementation Order

Dependencies flow as follows:

1. **Feature 19 (Pages)** — No dependencies, pure YAML analysis. Simplest to implement.
2. **Feature 22 (SBOM)** — Extends existing pkg/pbom/, no dependencies on other new features.
3. **Feature 28 (Variables)** — New API integration, independent of others.
4. **Feature 25 (Environments)** — Can cross-reference variable scope from Feature 28, but works independently.
5. **Feature 24 (Drift)** — New subcommand, uses existing pipeline parser.
6. **Feature 23 (Dashboard)** — Aggregates enumerate results; benefits from all other features being complete so the dashboard shows the full picture.

---

## Files Created/Modified Summary

### New files (24 files):
- `pkg/analyze/pages.go` + `pages_test.go`
- `pkg/analyze/environment.go` + `environment_test.go`
- `pkg/analyze/variables.go` + `variables_test.go`
- `pkg/enumerate/variables.go` + `variables_test.go`
- `pkg/enumerate/environments.go` + `environments_test.go`
- `pkg/pbom/spdx.go` + `spdx_test.go`
- `pkg/drift/differ.go` + `differ_test.go`
- `pkg/drift/security.go` + `security_test.go`
- `pkg/drift/baseline.go` + `baseline_test.go`
- `pkg/dashboard/dashboard.go` + `dashboard_test.go`
- `pkg/dashboard/scorer.go` + `scorer_test.go`
- `pkg/dashboard/pterm.go`
- `pkg/dashboard/html.go` + `html_template.html`
- `cmd/drift.go`
- `cmd/dashboard.go`

### Modified files (12 files):
- `pkg/analyze/codes.go` — 9 new finding IDs
- `pkg/analyze/taxonomy.go` — 9 new taxonomy entries
- `pkg/analyze/analyze.go` — 3 new steps in `Run()`
- `pkg/enumerate/enumerator.go` — wire variables, environments, PBOM collection
- `pkg/enumerate/result.go` or equivalent — new fields on `Result`
- `pkg/enumerate/report/report.go` — new report sections
- `pkg/enumerate/report/pterm.go` — render new sections
- `pkg/enumerate/report/html.go` + `html_template.html` — new HTML sections
- `pkg/enumerate/report/exploit.go` — new exploitable mappings
- `pkg/store/models.go` — new persistence models
- `cmd/enumerate.go` — new flags
- `cmd/pbom.go` — SPDX format option
