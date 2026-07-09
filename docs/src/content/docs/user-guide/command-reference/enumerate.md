---
title: Enumerate Command
description: Analyze GitLab projects for exploitable CI/CD vulnerabilities
---

The enumerate command analyzes GitLab projects for exploitable vulnerabilities in GitLab CI/CD (.gitlab-ci.yml). It performs static analysis of pipeline configuration and can optionally resolve transitive includes to provide a deeper view.

## Basic Usage

```bash
./gogatoz enumerate [options]
```

Authentication:

```bash
export GITLAB_TOKEN=glpat_xxx
export GITLAB_URL=https://gitlab.com   # optional, defaults to https://gitlab.com
```

You can also pass --token and --gitlab-url flags explicitly. See [Concepts: GitLab PATs](/user-guide/concepts/gitlab-pats/) for scopes and setup.

## Options

Project selection:
- --input, -i            Path to a file containing project identifiers (one per line). Each line can be a path-with-namespace like group/project or a numeric project ID. Lines starting with # are ignored.
- --input-format         Input format for --input: auto|text|json|jsonl (auto detects per line; default: auto)
- --group               Group ID or full path to expand into projects
- --groups              Comma-separated group IDs or full paths to expand into projects
- --group-recursive     Recursively include subgroup projects (best-effort; default: false)

Analysis behavior:
- --concurrency, -c      Number of concurrent workers (default: 16)
- --timeout              Per-project timeout, e.g. 10s, 1m (optional)
- --mode                 Enumeration mode: quick|deep|pipeline-only (overrides include/analyzer defaults)
- --follow-includes      Resolve and analyze transitive includes (default: true)
- --include-depth        Maximum include resolution depth (default: 2)
- --deep                 Shorthand to enable deep include resolution (sets --follow-includes and bumps --include-depth to >=3)
- --only-findings        Only include projects that produced one or more findings
- --only-clean           Only include projects with no findings and no errors
- --redacted             Mask plaintext secret values in findings output (default: unredacted — real values are shown). When set, evidence is shown as `KEY=<redacted>` (the variable name is still shown)
- --filter-false-positives  Automatically identify and mark common false positive patterns (default: false)
- --allow-remote-includes  Resolve remote includes (requires --remote-allowlist); disabled by default
- --remote-allowlist       Comma-separated host allowlist for remote includes (e.g., raw.githubusercontent.com,example.com)
- --remote-max-bytes       Max bytes to fetch for a remote include (0 uses default 1MiB)
- --remote-timeout         Per-remote include fetch timeout (e.g., 5s). Empty uses default 10s
- --include-cache-ttl      Enable cross-call cache for remote includes with TTL (e.g., 10m). Empty disables

Non-default refs (deep-dive):
- --ref                    A single Git reference (branch or tag) to scan in addition to the default branch
- --refs                   Comma-separated list of refs to scan per project (in addition to --ref)
- --max-refs               Maximum number of refs to scan per project (0 = all provided)

Log scraping:
- --log-scrape             Scrape recent job logs for key=value findings, best-effort and bounded (default: false)
- --log-max-pipelines      Max pipelines per ref to inspect for logs when --log-scrape is set (default: 3)
- --log-max-jobs           Max jobs per pipeline to scan logs when --log-scrape is set (default: 20)

Inventory:
- --protected-branches     Fetch and include names of protected branches for each project
- --runners                Fetch runner summary (counts and executors); combine with --runners-scope (default: false)
- --runners-scope          Runner scope to query when --runners is set: project|group|instance (default: project)
- --allow-admin-scope      Allow admin-only operations, required for --runners-scope=instance (default: false)

Compliance and reporting:
- --score                  Compute and display compliance score (A-E letter grade; default: false)
- --badge                  Create/update compliance badge on the project, requires api scope token (default: false)
- --mr-comment             Post/update compliance comment on this MR IID, requires api scope token (default: 0)
- --sarif-output           Write SARIF 2.1.0 report to file (in addition to primary output)
- --glsast-output          Write GitLab SAST report (gl-sast-report.json) to file (in addition to primary output)

Notifications (optional):
- --webhook-url          Webhook URL to POST findings as JSON envelopes (one POST per finding)
- --webhook-header       Additional HTTP header for webhook POST (repeatable), e.g., 'Authorization: Bearer x'
- --webhook-timeout      Timeout per webhook request (e.g., 5s)

Output and global flags:
- --json                 Output pretty JSON instead of text (default unless --format is set)
- --format               Output format: text|json|jsonl|html|sarif|glsast (default respects --json)
- --output               Write output to file (default: stdout)
- --verbose, -v          Verbose logging
- --gitlab-url           GitLab base URL (default: https://gitlab.com)
- --token                GitLab Personal Access Token (scopes: api, read_repository; write_repository for attack modules)
- --insecure-skip-tls-verify  Skip TLS certificate verification (self-hosted GitLab; for testing)
- --ca-cert              Path to PEM file with additional trusted CA certificate(s)
- --rate-rps             Max requests per second to the GitLab API (default: 8)
- --rate-burst           Burst size for rate limiter tokens (default: 16)
- --retry-max            Max retries on 429/5xx (default: 3; set to 1 to disable)
- --user-agent           Custom User-Agent header
- --http-max-idle        HTTP transport MaxIdleConns (pool size)
- --http-max-idle-per-host  HTTP transport MaxIdleConnsPerHost
- --http-idle-timeout    HTTP transport IdleConnTimeout (e.g., 90s)
- --http-tls-timeout     HTTP transport TLSHandshakeTimeout (e.g., 10s)
- --http-expect-timeout  HTTP transport ExpectContinueTimeout (e.g., 1s)
- --http-req-timeout     HTTP client overall request timeout (e.g., 30s)

## Examples

### Prepare an input file

projects.txt:
```
# Path-with-namespace or numeric IDs
mygroup/myproject
12345678
another-group/subgroup/proj
```

### Enumerate with JSON output

```bash
./gogatoz enumerate -i projects.txt -c 16 --timeout 20s --json
```

### Disable include resolution

```bash
./gogatoz enumerate -i projects.txt --follow-includes=false
```

### Increase include resolution depth

```bash
./gogatoz enumerate -i projects.txt --include-depth 3
```

### Enumerate an entire group

```bash
# Single group (recursive into subgroups)
./gogatoz enumerate --group my-org/platform --group-recursive --json

# Multiple groups
./gogatoz enumerate --groups "my-org/frontend,my-org/backend" --json
```

### Compliance scoring and CI integration

```bash
# Show compliance score (A-E letter grade)
./gogatoz enumerate -i projects.txt --score

# Post compliance comment on a merge request
./gogatoz enumerate -i projects.txt --mr-comment 42 --score

# Update compliance badge on the project
./gogatoz enumerate -i projects.txt --badge --score
```

### SARIF and GitLab SAST output

```bash
# SARIF 2.1.0 report for IDE/GitHub integration
./gogatoz enumerate -i projects.txt --format sarif -o findings.sarif

# GitLab SAST report for MR widget integration
./gogatoz enumerate -i projects.txt --format glsast -o gl-sast-report.json

# Write both SARIF and GLSAST alongside primary output
./gogatoz enumerate -i projects.txt --json --sarif-output findings.sarif --glsast-output gl-sast-report.json
```

### HTML report

```bash
./gogatoz enumerate -i projects.txt --format html -o report.html
```

### Filter false positives

```bash
./gogatoz enumerate -i projects.txt --filter-false-positives --json
```

### Log scraping for leaked secrets

```bash
# Scrape recent job logs for key=value patterns
./gogatoz enumerate -i projects.txt --log-scrape --log-max-pipelines 5 --json
```

## Understanding the Output

Text output prints one line per project with a brief CI summary or an error. JSON output returns an array of objects with the following fields:

- project_id (int)
- path_with_namespace (string)
- web_url (string)
- default_branch (string)
- scanned_ref (string) — the ref that was scanned (default branch or one provided via --ref/--refs)
- has_ci_pipeline (bool)
- ci_summary (string)
- findings (array)
- protected_branches (array) — when --protected-branches is set, the names of protected branches
- duration_ms (int)
- error (string)

Findings include a severity, rule identifier, and evidence where applicable.

## What it checks today

The analyzer currently flags common risky patterns in GitLab CI:
- Remote include risk (HIGH)
- Unpinned project include (HIGH)
- CI/CD component usage (MEDIUM)
- Tagged runner with broad triggers (HIGH)
- Merge Request triggers on tagged runners (MEDIUM)
- Plaintext secret heuristics in variables (MEDIUM)
- Risky remote script execution in job scripts (MEDIUM) — e.g., curl|bash, wget|sh, PowerShell iwr|iex
- **Variable injection (HIGH/MEDIUM)** — detects attacker-controllable CI variables (MR title/description, commit message) used directly in scripts, especially in command sinks (make, npm, pip, bash, etc.)
- **Fork MR safety (HIGH/MEDIUM)** — detects MR-triggered jobs without fork protection, especially risky for self-hosted runners and artifact-producing jobs
- **Artifact poisoning (HIGH/MEDIUM)** — detects jobs consuming artifacts from MR-triggered sources, with elevated severity for privileged downstream jobs
- Artifacts without expire_in (LOW)
- Broad workflow rules (LOW)

More advanced rules (protected branch checks, executor nuances, TOCTOU detection, environment gates) are being added progressively.

## Using a config file

You can set defaults in a config file and override with environment variables and CLI flags.
- Location: pass --config or set GOGATOZ_CONFIG; otherwise ./.gogatoz.yaml is used when present.
- Precedence: flags > environment > config file > built-in defaults.
- Keys mirror flag names (dashes allowed), e.g. gitlab-url, token, input, concurrency, timeout, follow-includes, include-depth, deep.

Example .gogatoz.yaml:

```yaml
gitlab-url: https://gitlab.com
json: true
input: projects.txt
concurrency: 16
timeout: 20s
follow-includes: true
include-depth: 3
only-findings: false
```

## Notes

- The tool fetches .gitlab-ci.yml from the project's default branch. Projects without a default branch or CI file are reported accordingly.
- Include resolution supports local, project, remote (behind guardrails: allowlist, size/time limits), official templates, and CI/CD components (fetched via GraphQL with inputs substitution). Provenance is tracked for jobs merged from includes to aid analysis and reporting.
- Parser fidelity now includes default:, before_script, and after_script in addition to stages/jobs/rules/includes/variables, plus job image/services/artifacts/cache and inheritance via extends (captured) for richer analysis.
- Respect GitLab rate limits. Use lower concurrency or add timeouts if you encounter throttling. You can also tune --rate-rps/--rate-burst and --retry-max.
