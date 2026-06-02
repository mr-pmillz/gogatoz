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

Analysis behavior:
- --concurrency, -c      Number of concurrent workers (default: 16)
- --timeout              Per-project timeout, e.g. 10s, 1m (optional)
- --follow-includes      Resolve and analyze transitive includes (default: true)
- --include-depth        Maximum include resolution depth (default: 2)
- --deep                 Shorthand to enable deep include resolution (sets --follow-includes and bumps --include-depth to >=3)
- --only-findings        Only include projects that produced one or more findings
- --only-clean           Only include projects with no findings and no errors
- --redacted             Mask plaintext secret values in findings output (default: unredacted — real values are shown). When set, evidence is shown as `KEY=<redacted>` (the variable name is still shown)
- --allow-remote-includes  Resolve remote includes (requires --remote-allowlist); disabled by default
- --remote-allowlist       Comma-separated host allowlist for remote includes (e.g., raw.githubusercontent.com,example.com)
- --remote-max-bytes       Max bytes to fetch for a remote include (0 uses default 1MiB)
- --remote-timeout         Per-remote include fetch timeout (e.g., 5s). Empty uses default 10s
- --include-cache-ttl      Enable cross-call cache for remote includes with TTL (e.g., 10m). Empty disables

Non-default refs (deep-dive):
- --ref                    A single Git reference (branch or tag) to scan in addition to the default branch
- --refs                   Comma-separated list of refs to scan per project (in addition to --ref)
- --max-refs               Maximum number of refs to scan per project (0 = all provided)

Inventory:
- --protected-branches     Fetch and include names of protected branches for each project

Notifications (optional):
- --webhook-url          Webhook URL to POST findings as JSON envelopes (one POST per finding)
- --webhook-header       Additional HTTP header for webhook POST (repeatable), e.g., 'Authorization: Bearer x'
- --webhook-timeout      Timeout per webhook request (e.g., 5s)

Output and global flags:
- --json                 Output pretty JSON instead of text (default unless --format is set)
- --format               Output format: text|json|jsonl (jsonl streams one JSON object per line)
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
