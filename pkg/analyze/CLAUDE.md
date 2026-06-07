# pkg/analyze

## Purpose

Vulnerability analysis engine for GoGatoZ. Performs multi-pass security rule evaluation against parsed GitLab CI/CD pipeline configurations to identify misconfigurations, risky patterns, and potential attack vectors. Covers: include risks, runner exposure, variable injection, artifact poisoning, plaintext secrets, fork MR risks, dispatch/TOCTOU, Pwn Request deployments, privileged containers, workflow rules, supply chain attacks (script injection, self-merge, cache poisoning), Living-off-the-Pipeline (LOTP) tool execution, cache key injection, GitLab OIDC token exposure, and downstream trigger chain abuse.

## Files

| File | Purpose |
|------|---------|
| `analyze.go` | Main entry point with `Run()` function; defines `Finding` struct and `Severity` constants; orchestrates all analysis checks; `effectiveScripts()` helper for before/script/after aggregation; attaches recommendations by finding ID |
| `rules.go` | Expression evaluator for GitLab `rules:if` conditions; minimal parser supporting `==`, `!=`, `=~`, `!~`, `&&`, `||`, `!` operators |
| `injection.go` | Detects variable injection, fork MR risks, and artifact poisoning; defines unsafe CI variables and command sinks |
| `dispatch.go` | Detects TOCTOU risks in manual/triggered jobs, Pwn Request deployments, and privileged runner usage |
| `falsepositive.go` | False positive rules engine: `FPRule` struct, `DefaultFPRules()`, `ApplyFPRules()`, `FilterTruePositives()` |
| `falsepositive_test.go` | Table-driven tests for all FP rules, immutability, and filtering |
| `supply_chain.go` | Supply chain attack detection: script injection risk, self-merge possible, cache poisoning risk |
| `supply_chain_test.go` | 27 table-driven tests for three supply chain detection rules |
| `lotp.go` | Living-off-the-Pipeline tool catalog (60+ tools); `LOTPTool` struct; `DetectLOTPTools()` |
| `lotp_rules.go` | LOTP-derived detection rules: `detectLOTPToolExec`, `detectCacheKeyInjection`, `detectOIDCTokenMRRisk`, `detectTriggerChainRisk` |
| `lotp_rules_test.go` | Table-driven tests for all 4 LOTP-derived rules and `DetectLOTPTools` |

## False Positive Detection

`falsepositive.go` provides a rules engine for marking enumerate findings as false positives without deleting them.

**Exported API:**
- `FPRule` — struct with ID, Description, Match func
- `DefaultFPRules()` — returns built-in rules (FP_GITLAB_CI_FLAG, FP_PAGES_ARTIFACTS)
- `ApplyFPRules(findings, rules)` — returns new slice with FP fields populated (immutable)
- `FilterTruePositives(findings)` — returns only non-FP findings

**Adding new rules:** Create a function returning `FPRule`, register it in `DefaultFPRules()`, update `TestDefaultFPRules_count` expected count.

## Exported API

**Types:**
- `Severity` (string) — constants: `SeverityInformational`, `SeverityLow`, `SeverityMedium`, `SeverityHigh`, `SeverityCritical`
- `AllSeverities` — ordered slice (descending): CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- `Finding` — struct with fields: `ID`, `Severity`, `Title`, `Description`, `Evidence` (truncated ~160-200 chars), `JobName`, `Recommendation`
- `Option` — functional option for `Run` (see `WithRedactedSecrets`)

**Functions:**
- `Run(doc *pipeline.Document, opts ...Option) ([]Finding, error)` — main analysis orchestrator; returns slice of findings. By default, `PLAINTEXT_SECRET`/`PLAINTEXT_SECRET_JOB` evidence shows the **real** variable value (unredacted)
- `WithRedactedSecrets() Option` — masks plaintext secret values in evidence as `KEY=<redacted>` (variable name still shown). Used by `enumerate --redacted`
- `EvaluateIf(expr string, ctx map[string]string) bool` — evaluates rules:if expressions
- `detectScriptInjectionRisk(doc, findings)` — scan script blocks for external script references
- `detectSelfMergePossible(doc, findings)` — check approval rules configuration
- `detectCachePoisoningRisk(doc, findings)` — detect shared caches without branch isolation

**Finding IDs (selected):**

| ID | Severity | Source | Description |
|----|----------|--------|-------------|
| `SCRIPT_INJECTION_RISK` | HIGH | `supply_chain.go` | MR-triggered jobs call external scripts (./scripts/*.sh, bash, make, etc.) |
| `SELF_MERGE_POSSIBLE` | HIGH | `supply_chain.go` | Project allows self-merge (0-1 required approvers, no CODEOWNERS) |
| `CACHE_POISONING_RISK` | MEDIUM | `supply_chain.go` | MR-triggered jobs use shared cache without branch isolation |
| `LOTP_TOOL_EXEC` | HIGH/MEDIUM | `lotp_rules.go` | MR-triggered job runs a LOTP tool (npm, make, pip, gradle, etc.) whose config file can be weaponized |
| `CACHE_KEY_INJECTION` | HIGH/MEDIUM | `lotp_rules.go` | Cache key derived from attacker-controllable `$CI_*` variable |
| `OIDC_TOKEN_MR_RISK` | HIGH | `lotp_rules.go` | MR-triggered job defines `id_tokens:` — fork authors can harvest OIDC tokens for cloud providers |
| `TRIGGER_CHAIN_RISK` | HIGH/MEDIUM | `lotp_rules.go` | MR-triggered job launches a downstream pipeline via `trigger:` |

**Variables:**
- `ErrPartial` — signals partial analysis completion (defined but currently unused)

## Internal Patterns

**Multi-Pass Rule Evaluation**: `Run()` executes checks in order: workflow rules, include risks, job triggers/runner exposure, risky scripts, artifacts expiration, plaintext secrets, variable injection, fork MR, artifact poisoning, dispatch/TOCTOU, Pwn Request, privileged runners, supply chain (script injection risk, self-merge possible, cache poisoning risk), LOTP tool execution, cache key injection, OIDC token MR risk, trigger chain risk, then post-processing (attach recommendations by finding ID).

**Before/After Script Coverage**: All rules that inspect job scripts use `effectiveScripts(job, doc)` instead of `job.Script` directly. This resolves global vs. job-level before_script/after_script inheritance and ensures injection/LOTP checks cover all script phases.

**Rules:If Expression Evaluator**: Lightweight custom parser in `rules.go`. Tokenization splits by operators at top-level only. Quote-aware splitting via `splitKeepOuter()` avoids splitting inside `"..."`, `'...'`, or `/.../`. Operator precedence: OR over AND (disjunctive normal form). Regex support extracts pattern between `/` delimiters.

**Unsafe Variables & Sinks**: 13+ known attacker-controllable CI variables (e.g., `$CI_MERGE_REQUEST_TITLE`, `$CI_COMMIT_MESSAGE`) plus regex patterns. ~30 code-execution sinks (make, npm, pip, bash, eval, terraform, etc.) plus local script patterns.

**Severity Escalation**: Findings start at base severity and escalate/downgrade based on context (fork protection, tags, artifacts, allow_failure).

## Testing

- Test constants: each `*_test.go` file defines test fixtures as embedded YAML-derived structs
- Table-driven tests: `injection_test.go` has explicit table tests for `extractCIVariables()`, `isUnsafeVariable()`, `containsSink()`
- Assertion helper: `hasFindingID(findings []Finding, id string) bool` used across all tests
- Test files: `analyze_risky_script_test.go` (5 tests), `analyze_includes_test.go` (1 test), `dispatch_test.go` (3 tests), `injection_test.go` (16 tests), `rules_test.go` (2 comprehensive suites), `analyze_artifacts_test.go`, `supply_chain_test.go` (27 table-driven tests)

## Dependencies

**Imports:**
- `pkg/pipeline` — core dependency; uses `Document`, `Job`, `Include`, `IncludeType`. Analyzer takes parsed `*pipeline.Document` as input.

**Depended on by:**
- `pkg/enumerate` — calls `Run()` to analyze resolved CI configs
- `pkg/notify` — imports `Finding` type for webhook envelope
- `pkg/graph` — could use findings for visualization (future)

## Gotchas

1. **Evidence truncation** — Evidence strings truncated to ~160-200 chars via `truncateEvidence()`. Long rules/scripts may be cut off.
2. **Rules:If limitations** — Does NOT support parentheses; evaluates as OR-of-ANDs. Regex errors silently return false. Complex quoting may fail.
3. **Heuristic detection** — `jobRulesAllowBroad()` searches JSON stringified rules for substring matches (not structural). `onlyIsBroad()` checks for literal strings. Not exhaustive.
4. **Finding ID non-uniqueness** — Some IDs (e.g., `VARIABLE_INJECTION`) may be emitted multiple times per run. No deduplication within `Run()`.
5. **Nil document** — Returns nil findings (not an error).
6. **Fork protection detection** — Substring-based; custom variable-based fork checks won't be detected.
7. **LOTP detection is catalog-based** — Only matches tools from the static `lotpCatalog` in `lotp.go`. Dynamically constructed commands (e.g., `CMD=npm; $CMD install`) are not detected. Update the catalog when new LOTP tools are published at https://boostsecurityio.github.io/lotp/
8. **OIDC detection reads `doc.Raw`** — `id_tokens:` is not modeled in the `Job` struct; detection reaches into the raw YAML map via `jobHasIDTokens()`. If a job is rebuilt by `applyExtends`, the raw map still contains the field.
