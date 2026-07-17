# Code Review Fixes & Features — Design Spec

Date: 2026-07-17
Branch: feat/research

## Scope

3 bug fixes, 3 quality improvements, 2 features from comprehensive code review.

## Bug Fix 1: Global Cache Detection Gap

**Files:** `pkg/pipeline/parser.go`, `pkg/analyze/supply_chain.go`, tests

The parser misses global/default cache config. GitLab CI supports cache in `default:` block
(top-level cache is deprecated) and as an array of up to 4 configs per job.

Changes:
- Add `"cache"` to `reservedTopLevel` in parser.go
- Add `Cache []map[string]any` field to `Document` struct
- Parse top-level `cache:` and `default:.cache` into `doc.Cache`, handling both map and array formats
- In `parseJob`, handle `cache` as array (`[]any`) in addition to `map[string]any`
- In `detectCachePoisoningRisk`, when `job.Cache == nil`, fall back to `doc.Cache`
- Update `extractCachePolicy` to handle array-of-caches (check each for push policy)

## Bug Fix 2: ListProjectRunners Missing TagList/Executor

**Files:** `pkg/gitlabx/runners.go`, tests

Switch `ListProjectRunners` from SDK to raw HTTP (same approach as `AccumulateGroupRunners`):
call `GET /api/v4/projects/:id/runners` directly and decode with `parseRunnerPage`.

## Bug Fix 3: jobTriggersOnMR Passes Wrong Argument

**Files:** `pkg/analyze/analyze.go`

Line 186: change `jobTriggersOnMR(job)` to `jobTriggersOnMR(job.Rules)`.

## Quality 1: Reduce Run() Complexity

**Files:** `pkg/analyze/analyze.go`

Extract pre-step checks (steps 0–3: workflow rules, include risks, job trigger risks,
remote scripts, artifacts-without-expiry, plaintext vars) into `runPreChecks()` helper.
Reduces Run() from ~234 lines to ~100 lines.

## Quality 2: Webhook Notification Batching

**Files:** `pkg/notify/notify.go`, `cmd/enumerate.go`

Add `SendFindings(ctx, project, findings, meta)` batch method. Enumerate command sends
one POST per project instead of one per finding.

## Quality 3: BloodHound Edge Property Merging

**Files:** `pkg/bloodhound/writer.go`, tests

Change dedup key from full JSON to `source|target|kind`. When duplicate found, merge
Properties maps (existing values win). Prevents duplicate edges while preserving metadata.

## Feature 1: Artifact Chain Poisoning Detection

**Files:** `pkg/analyze/injection.go`, `pkg/enumerate/report/exploit.go`, tests

After building producer map in `detectArtifactPoisoning`, compute transitive closure:
if B consumes from MR-triggered A, and C consumes from B, C is also at risk.
Emit `ARTIFACT_CHAIN_POISONING` with full chain evidence. Register in `exploitableFindingMap`.

## Feature 2: IsExploitable Auto-Sync Test

**Files:** `pkg/enumerate/report/exploit_test.go`

Test that iterates all `*ID` constants from analyze package and verifies each
exploitable-category finding ID appears in `exploitableFindingMap`. Catches drift.

## Not Bugs (from review)

- **ReceiveTimeout zero-value**: `options.go:110` already defaults to 5m via `defaults()`. No fix needed.
- **envDumpToFileRe regex**: Reviewer quoted wrong regex. Actual code `(\s*>>?\s*)` requires `>`. No fix needed.
