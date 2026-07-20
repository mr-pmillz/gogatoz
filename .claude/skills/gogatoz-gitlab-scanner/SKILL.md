---
name: gogatoz-gitlab-scanner
description: Use when the user wants to search GitLab projects or scan them for CI/CD security vulnerabilities. Trigger on keywords like "search gitlab", "scan projects", "enumerate", "CI/CD security", "find vulnerabilities", "gitlab recon".
---

# GoGatoZ GitLab CI/CD Scanner

You have access to two MCP tools from the `gogatoz` server for GitLab CI/CD security reconnaissance. Results are automatically stored in a local SQLite database when configured.

## Tools

### search_projects
Searches GitLab for projects matching filters. Use this first to discover targets.

**Key parameters:**
- `query` — search by project name/path/description
- `visibility` — `public`, `internal`, or `private`
- `topic` — comma-separated topic filter
- `language` — comma-separated language filter
- `path_exists` — only projects containing a specific file (e.g., `.gitlab-ci.yml`)
- `max_pages` — increase for broader discovery (default 1, 0=unlimited)
- `owned` / `membership` — scope to your projects

### enumerate_projects
Scans projects for CI/CD security vulnerabilities. Takes project IDs or paths from search results.

**Key parameters:**
- `projects` — list of project IDs or `group/project` paths (required)
- `follow_includes` — resolve CI include directives transitively (recommended: true)
- `include_depth` — max include depth (default 2)
- `fetch_runners` — get runner info for severity correlation
- `fetch_protected` — get protected branch info for severity adjustment
- `concurrency` — parallel workers (default 8)
- `timeout` — per-project timeout e.g. `30s`

## Efficient Large-Scale Scanning Strategy

### Finding CRITICAL Severity Findings

CRITICAL findings require **shell executor detection**, which needs runner API access. Strategies:

1. **Target self-hosted GitLab instances** — Use `GITLAB_URL` pointed at instances where you have admin/maintainer access (e.g., gitlab.local). Self-hosted instances are far more likely to have shell executors.

2. **Target projects you own/maintain** — Use `owned: true` or `membership: true` to find projects where your token has runner access.

3. **Search for shell executor patterns in CI configs** — Search for projects with `tags:` referencing `shell`, `linux`, `deploy`, `build-server`, `self-hosted` which hint at shell executors.

4. **Target infrastructure-heavy organizations** — Groups running DevOps/infra projects are more likely to have self-hosted runners with shell executors.

### Optimized Search Queries (use in parallel)

For maximum coverage, run **multiple targeted searches in parallel** rather than one generic search:

```
# High-value targets (complex CI/CD, likely real infrastructure)
query="deploy"        + path_exists=".gitlab-ci.yml" + max_pages=10
query="kubernetes"    + path_exists=".gitlab-ci.yml" + max_pages=10
query="terraform"     + path_exists=".gitlab-ci.yml" + max_pages=10
query="infrastructure"+ path_exists=".gitlab-ci.yml" + max_pages=10
query="pipeline"      + path_exists=".gitlab-ci.yml" + max_pages=10

# Secret-likely targets
query="docker"        + path_exists=".gitlab-ci.yml" + max_pages=10
query="ansible"       + path_exists=".gitlab-ci.yml" + max_pages=10
query="helm"          + path_exists=".gitlab-ci.yml" + max_pages=10

# Self-hosted runner hints
query="shell runner"  + path_exists=".gitlab-ci.yml" + max_pages=5
query="self-hosted"   + path_exists=".gitlab-ci.yml" + max_pages=5
```

### Enumerate in Batches

- **Batch size**: 30-50 projects per enumerate call
- **Concurrency**: 4-6 workers to avoid rate limiting on gitlab.com
- **Timeout**: 30s per project
- **Always enable**: `follow_includes: true`, `fetch_protected: true`, `fetch_runners: true`
- **Dedup**: Track scanned project IDs across batches to avoid re-scanning

### Handling Large Result Sets

When enumerate results exceed token limits:
1. Results are saved to a temp file
2. Use `jq` to extract summary stats:
   ```bash
   cat <file> | jq '{total_scanned, with_findings,
     severity: [.results[].findings // [] | .[].severity] | group_by(.) | map({s: .[0], n: length}),
     types: [.results[].findings // [] | .[].id] | group_by(.) | map({id: .[0], n: length}) | sort_by(-.n)}'
   ```
3. Filter for specific severities:
   ```bash
   cat <file> | jq '[.results[] | select(.findings_count > 0) | {p: .path_with_namespace, f: [.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH") | {s: .severity, id: .id, t: .title}]}] | map(select(.f | length > 0))'
   ```

### False Positive Filtering

Two built-in FP rules auto-filter noise:
- `FP_PAGES_ARTIFACTS` — GitLab Pages `artifacts:` without `expire_in` (expected behavior)
- `FP_GITLAB_CI_FLAG` — Variables like `SECRET_DETECTION_ENABLED` (feature flags, not secrets)

After scanning, note which findings are FP-eligible when reporting.

## Severity Scale

| Level         | Color  | Meaning                                |
|---------------|--------|----------------------------------------|
| CRITICAL      | Purple | Verified RCE (shell executor exposure) |
| HIGH          | Red    | Direct exploitation path               |
| MEDIUM        | Yellow | Requires conditions to exploit         |
| LOW           | Green  | Informational risk factor              |
| INFORMATIONAL | Cyan   | Hygiene observation                    |

## Finding Types

| ID                         | What it detects                               | Base Severity                      |
|----------------------------|-----------------------------------------------|------------------------------------|
| `RUNNER_EXECUTOR_RISK`     | Shell/docker executor on job                  | CRITICAL (shell) / MEDIUM (docker) |
| `SELF_HOSTED_EXPOSED`      | Tagged runner with broad triggers             | HIGH (CRITICAL with shell runner)  |
| `INCLUDE_REMOTE`           | Remote URL includes (supply chain risk)       | HIGH                               |
| `INCLUDE_PROJECT_UNPINNED` | Project includes without pinned ref           | HIGH                               |
| `VARIABLE_INJECTION`       | Attacker-controllable CI variables in scripts | MEDIUM-HIGH                        |
| `FORK_MR_UNPROTECTED`      | Fork MR pipeline without protections          | MEDIUM-HIGH                        |
| `ARTIFACT_POISONING_RISK`  | Untrusted artifact consumption                | MEDIUM                             |
| `PLAINTEXT_SECRET`         | Hardcoded credentials in CI config            | MEDIUM                             |
| `MR_TAGGED_RUNNER`         | MR-triggered job on tagged runner             | MEDIUM                             |
| `PWN_REQUEST_DEPLOYMENT`   | MR-triggered deployment without protections   | MEDIUM                             |
| `PRIVILEGED_RUNNER_RISK`   | docker-in-docker on MR jobs                   | MEDIUM                             |
| `INCLUDE_COMPONENT`        | CI/CD component includes                      | MEDIUM                             |
| `FORK_SCRIPT_EXECUTION`    | Fork MR can modify executed scripts           | MEDIUM                             |
| `DISPATCH_TOCTOU_RISK`     | Manual/triggered job with broad scope         | LOW                                |
| `RISKY_REMOTE_SCRIPT`      | curl/wget piped to shell                      | MEDIUM                             |
| `WORKFLOW_BROAD_RULES`     | Top-level workflow permits broad triggers     | INFORMATIONAL                      |
| `ARTIFACTS_NO_EXPIRE`      | Artifacts without expiration                  | INFORMATIONAL                      |

## Pivot (Lateral Movement)

### pivot_scan
Automated lateral movement via CI/CD secrets exfiltration. Chains enumerate → attack → harvest tokens → repeat.

**Key parameters:**
- `targets` — project IDs or paths (required)
- `external_url` — URL reachable from CI runners for callback (required unless dry_run)
- `dry_run` — enumerate only, show exploitable targets without attacking
- `max_depth` — max pivot depth (default 3)
- `max_targets` — max projects to attack (default 50)
- `max_credentials` — max tokens to harvest (default 20)
- `timeout` — overall timeout (default 30m)
- `cleanup` — delete attack branches after harvest

### Pivot Workflow
1. Start with `dry_run: true` to identify exploitable targets
2. If targets found, run with `external_url` pointing to a reachable callback server
3. The tool automatically: enumerates → filters exploitable → attacks with secrets exfil → receives callbacks → extracts tokens → validates → repeats
4. Results show harvested credential metadata (no raw tokens)

### Exploitable Finding Types (for pivot targeting)
Findings that the pivot command can exploit: `SELF_HOSTED_EXPOSED`, `MR_TAGGED_RUNNER`, `RUNNER_EXECUTOR_RISK`, `VARIABLE_INJECTION`, `PLAINTEXT_SECRET`, `FORK_MR_UNPROTECTED`, `ARTIFACT_POISONING_RISK`, `PRIVILEGED_RUNNER_RISK`, `PWN_REQUEST_DEPLOYMENT`.

## Tips

- For thorough analysis, set `follow_includes: true` and `include_depth: 3`
- Enable `fetch_runners: true` to get runner-correlated severity adjustments
- Use `path_exists: ".gitlab-ci.yml"` in search to only find projects with CI configs
- For large scans, set `timeout: "30s"` to avoid hanging on slow projects
- Results include `evidence` and `recommendation` fields — use them to explain findings
- **Dedup across searches**: Different queries will return overlapping projects. Track IDs.
- **Rate limiting**: gitlab.com enforces rate limits. Use concurrency 4-6, not 8+.
- **Pivot requires write access**: The attack phase needs `write_repository` scope to commit CI files.
