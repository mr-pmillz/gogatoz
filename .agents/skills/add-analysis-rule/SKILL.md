---
name: add-analysis-rule
description: Add a new analysis or false positive rule to GoGatoZ enumerate pipeline. Use when adding detection for new CI/CD vulnerability patterns or false positive suppression rules.
---

# Add Analysis Rule

## For Vulnerability Detection Rules (pkg/analyze/)

1. **Define the check** in the appropriate file:
   - `analyze.go` — include risks, runner exposure, plaintext secrets, artifacts
   - `injection.go` — variable injection, fork MR risks, artifact poisoning
   - `dispatch.go` — TOCTOU, Pwn Request, privileged runners
   - New file if the rule is a distinct category

2. **Add the finding ID constant** and use it in `Run()` orchestrator in `analyze.go`

3. **Add recommendation text** in the recommendations map at bottom of `analyze.go`:
   ```go
   case "YOUR_FINDING_ID":
       f.Recommendation = "Action to take..."
   ```

4. **Write table-driven tests** with embedded YAML-derived structs as fixtures

5. **Run verification**: `go test ./pkg/analyze/... && make lint`

## For False Positive Rules (pkg/analyze/falsepositive.go)

1. **Create a rule function** returning `FPRule`:
   ```go
   func yourRule() FPRule {
       return FPRule{
           ID:          "FP_YOUR_RULE",
           Description: "Why this is a false positive",
           Match: func(f Finding) bool {
               // Match logic
           },
       }
   }
   ```

2. **Register in `DefaultFPRules()`** — add to the returned slice

3. **Add table-driven tests** in `falsepositive_test.go`:
   - Positive match cases
   - Negative cases (should NOT match)
   - Edge cases (case sensitivity, wrong finding ID)

4. **Update `TestDefaultFPRules_count`** expected count

5. **Run verification**: `go test ./pkg/analyze/... -v`

## Key Conventions

- Finding IDs are UPPER_SNAKE_CASE (e.g., `INCLUDE_REMOTE`, `PLAINTEXT_SECRET`)
- FP rule IDs are prefixed with `FP_` (e.g., `FP_GITLAB_CI_FLAG`)
- Evidence strings are truncated to ~160-200 chars via `truncateEvidence()`
- Severity constants: `SeverityHigh`, `SeverityMedium`, `SeverityLow`
- FP rules use mark-don't-delete pattern: set `FalsePositive: true` + reason, never remove findings
