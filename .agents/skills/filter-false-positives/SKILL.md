---
name: filter-false-positives
description: Post-process GoGatoZ enumerate results to identify and filter false positives, deduplicate fork clusters, remove noise projects, and produce adjusted severity reports. Use this skill whenever the user mentions "false positive", "filter findings", "clean up results", "verify findings", "noise removal", "deduplicate", "adjusted report", or asks about finding accuracy after a scan. Also trigger when reviewing large enumerate result sets (50+ projects) or when the user questions whether findings are real.
---

# False Positive Analysis for GoGatoZ Enumerate Results

Large-scale GoGatoZ scans produce findings that include noise — SEO spam repos, duplicated forks, GitLab demos, and detection false positives. This skill provides a systematic workflow to separate signal from noise and produce trustworthy adjusted reports.

## Programmatic Filtering (Recommended)

GoGatoZ has built-in false positive detection via the `--filter-false-positives` flag:

```bash
# During enumeration — marks FP findings before persistence
gogatoz enumerate --filter-false-positives --gitlab-url https://gitlab.com --no-token -i projects.txt

# During reporting — applies FP rules when loading from DB/file
gogatoz report --filter-false-positives --db results.db --session 1
gogatoz report --filter-false-positives --input results.jsonl --format text
```

**How it works:** Findings are marked with `false_positive: true` and `false_positive_reason` — they are NOT deleted. JSON/JSONL output includes all findings with FP metadata for client-side filtering. Text and HTML reports show adjusted counts (excluding FP findings) plus a summary of what was filtered.

**Built-in rules:**

| Rule ID              | Targets                                    | Match Logic                                                                                                                    |
|----------------------|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `FP_GITLAB_CI_FLAG`  | `PLAINTEXT_SECRET`, `PLAINTEXT_SECRET_JOB` | Evidence contains GitLab CI feature flag variable names (SECRET_DETECTION_ENABLED, SAST_DISABLED, DS_EXCLUDED_ANALYZERS, etc.) |
| `FP_PAGES_ARTIFACTS` | `ARTIFACTS_NO_EXPIRE`                      | JobName is `pages` (case-insensitive)                                                                                          |

These rules are defined in `pkg/analyze/falsepositive.go`. To add new rules, add a function returning an `FPRule` and register it in `DefaultFPRules()`.

## Manual Filtering (Advanced)

## Workflow

1. **Load results** — from MCP database, JSONL files, or saved tool-result JSON files
2. **Apply finding-level FP rules** — suppress known false positive patterns
3. **Detect noise projects** — classify repos by noise category
4. **Deduplicate fork clusters** — collapse identical forks into single entries
5. **Produce adjusted report** — raw vs adjusted numbers with classifications

## Step 1: Load Results

Results can come from multiple sources. Use jq or sqlite3 to extract the data.

**From MCP tool-result JSON files:**
```bash
# Combine multiple enumerate batch files
cat file1.json file2.json | jq -s '[.[].results[]]'
```

**From SQLite database (gogatoz-results.sqlite3):**
```bash
sqlite3 gogatoz-results.sqlite3 "
  SELECT er.path_with_namespace, f.finding_id, f.severity, f.evidence
  FROM enumerate_results er
  JOIN findings f ON f.enumerate_result_id = er.id
  WHERE er.session_id >= N
"
```

**From JSONL files:**
```bash
cat enumerate-results.jsonl | jq -s '.'
```

## Step 2: Finding-Level False Positive Rules

Apply these rules to individual findings. When a rule matches, mark the finding as `false_positive` with the reason.

| Finding ID            | Evidence Pattern                                     | Reason                            | Action            |
|-----------------------|------------------------------------------------------|-----------------------------------|-------------------|
| `PLAINTEXT_SECRET`    | `SECRET_DETECTION_ENABLED=<redacted>`                | GitLab feature flag, not a secret | Remove            |
| `PLAINTEXT_SECRET`    | `SECRET_DETECTION_HISTORIC_ENABLED=<redacted>`       | GitLab feature flag               | Remove            |
| `PLAINTEXT_SECRET`    | `SECRET_DETECTION_ENABLE_MR_PIPELINES=<redacted>`    | GitLab feature flag               | Remove            |
| `PLAINTEXT_SECRET`    | `SAST_DISABLED=<redacted>`                           | GitLab feature flag               | Remove            |
| `PLAINTEXT_SECRET`    | `DS_EXCLUDED_ANALYZERS=<redacted>`                   | GitLab config, not a secret       | Remove            |
| `ARTIFACTS_NO_EXPIRE` | evidence contains `"public"` AND job_name is `pages` | GitLab Pages requires artifacts   | Downgrade to INFO |

**jq filter to remove known FP findings:**
```bash
jq '[.[] | .findings = [.findings[] | select(
  (.id == "PLAINTEXT_SECRET" and (.evidence | test("SECRET_DETECTION_ENABLED|SECRET_DETECTION_HISTORIC|SECRET_DETECTION_ENABLE_MR|SAST_DISABLED|DS_EXCLUDED_ANALYZERS"))) | not
)] | .findings_count = (.findings | length)]'
```

## Step 3: Noise Project Detection

Classify projects into noise categories. A project is noise if it matches ANY of these heuristics.

### 3a. SEO Spam Repos

**Detection:** Single user with 5+ repos where names are long keyword phrases (no hyphens between real words, just concatenated keywords). CI config is typically GitLab Pages only.

**jq detection pattern:**
```bash
# Group by user namespace, flag users with 5+ repos
jq 'group_by(.path_with_namespace | split("/")[0]) |
    map(select(length >= 5) | {user: .[0].path_with_namespace | split("/")[0], count: length, paths: [.[].path_with_namespace]})'
```

**Known spam patterns from prior scans:**
- Repos with names >60 chars that are concatenated English words (SEO keyword stuffing)
- Multiple repos from same user with nearly identical names differing by a word or two
- CI config that only deploys static HTML via GitLab Pages

### 3b. Fork Clusters

**Detection:** Multiple repos with the same basename (last path segment) AND identical or near-identical finding sets.

```bash
# Group by repo basename, find clusters
jq 'map({basename: (.path_with_namespace | split("/") | last), path: .path_with_namespace, finding_ids: [.findings[].id] | sort | join(",")}) |
    group_by(.basename) |
    map(select(length > 1)) |
    map({repo: .[0].basename, count: length, unique_finding_sets: ([.[].finding_ids] | unique | length), paths: [.[].path]})'
```

A fork cluster is confirmed when:
- 2+ repos share the same basename
- They have identical finding ID sets (or >80% overlap)

**Action:** Keep only one representative per cluster. Add a `fork_count` field. The representative should be the one with the most stars or the shortest path.

### 3c. GitLab Demo/Tutorial Repos

**Detection:** Path namespace matches known demo patterns.

```bash
# Known demo namespaces
jq '[.[] | select(.path_with_namespace | test("^(gitlab-da/|gl-demo-|gitlab-examples/)"; "i"))]'
```

These are official GitLab demonstration repos. Findings are real but intentional — they exist to showcase features, not as production code. Flag as `demo` rather than removing entirely.

### 3d. Student/Coursework Repos

**Detection:** Path or repo name contains educational indicators.

```bash
jq '[.[] | select(.path_with_namespace | test("assignment|homework|coursework|fintech-hw|final-assignment|short-assignment|onti-|training|tutorial"; "i"))]'
```

These have real findings but low real-world impact. Flag as `student` rather than removing.

## Step 4: Fork Cluster Deduplication

After identifying fork clusters in Step 3b, collapse them:

```bash
# Full dedup pipeline
jq '
  # Group by basename
  group_by(.path_with_namespace | split("/") | last) |
  map(
    if length > 1 then
      # Check if finding sets match
      (map([.findings[].id] | sort | join(",")) | unique) as $sets |
      if ($sets | length) <= 1 then
        # True fork cluster — keep first, annotate
        [.[0] + {fork_cluster: true, fork_count: length, fork_paths: [.[1:][].path_with_namespace]}]
      else
        . # Different findings, keep all
      end
    else . end
  ) | flatten
'
```

## Step 5: Produce Adjusted Report

Generate a report with both raw and adjusted numbers. Use this template:

```markdown
# Adjusted Scan Report

## Summary

| Metric | Raw | Adjusted | Delta |
|--------|-----|----------|-------|
| Total projects scanned | X | X | - |
| Projects with findings | X | Y | -Z removed |
| Total findings | X | Y | -Z removed |
| HIGH severity | X | Y | -Z |
| MEDIUM severity | X | Y | -Z |
| LOW severity | X | Y | -Z |

## Noise Removed

| Category | Projects | Findings Removed | Examples |
|----------|----------|-----------------|----------|
| False positive findings | - | N | SECRET_DETECTION_ENABLED as PLAINTEXT_SECRET |
| SEO spam repos | N | N | user/keyword-stuffed-repo-name |
| Fork clusters | N collapsed to M | N | repo-name (N forks) |
| GitLab demos | N | N | gitlab-da/project |
| Student projects | N | N | user/homework-assignment |

## Verified Findings (High Confidence)

[Table of remaining HIGH severity findings with project, finding type, evidence]

## Uncertain (Needs Manual Review)

[Projects that don't clearly fit noise or verified categories]
```

## Aggregate Statistics jq One-Liner

For quick adjusted stats after filtering:

```bash
jq -s '[.[].results[] | select(.findings_count > 0)] |
  {
    total_projects: length,
    total_findings: [.[].findings_count] | add,
    severity: ([.[].findings[] | .severity] | group_by(.) | map({(.[0]): length}) | add),
    finding_types: ([.[].findings[] | .id] | group_by(.) | map({(.[0]): length}) | add)
  }'
```

## Tips

- Run finding-level FP rules BEFORE noise project detection — this gives accurate finding counts for fork cluster comparison
- When reporting, always show both raw and adjusted numbers for transparency
- Projects classified as "demo" or "student" may still have pedagogical value — note them separately rather than silently dropping
- For scans with 500+ projects, expect 30-50% noise reduction after full filtering
- The `SECRET_DETECTION_ENABLED` false positive alone typically accounts for 5-15% of all PLAINTEXT_SECRET findings on gitlab.com
