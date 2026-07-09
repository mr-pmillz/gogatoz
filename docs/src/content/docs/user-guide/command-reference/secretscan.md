---
title: Secretscan Command
description: Clone and scan repos for secrets
---

The secretscan command discovers GitLab projects, clones them locally, and scans each repository for secrets using TruffleHog, Gitleaks, and/or Titus. Use it to find hardcoded credentials, API keys, and tokens across project repositories.

## Basic Usage

```bash
gogatoz secretscan [options]
```

Authentication:

```bash
export GITLAB_TOKEN=glpat_xxx
export GITLAB_URL=https://gitlab.com   # optional, defaults to https://gitlab.com
```

You can also pass --token and --gitlab-url flags explicitly, or use `--no-token` for public projects.

## Options

Project discovery:
- `--query`                Search query filter for project discovery
- `--language`             Comma-separated language filter
- `--topic`                Comma-separated topic filter
- `--visibility`           Filter by visibility: `public`, `internal`, `private`
- `--membership`           Only projects the user is a member of
- `--owned`                Only projects owned by the user
- `--per-page`             Results per API page, max 100 (default: 50)
- `--max-pages`            Maximum pages to fetch, 0 = unlimited (default: 0)

Scanning:
- `--scanners`             Scanners to use: `auto`, `trufflehog`, `gitleaks`, `titus` (default: `auto`)
- `--clone-depth`          Git clone depth, 0 = full history (default: 1)
- `--concurrency`          Number of concurrent clone+scan workers (default: 4)
- `--scan-dir`             Scan pre-cloned repos in this directory (skips clone)
- `--discard-repos-after-scanning`  Remove repos after scanning to save disk (default: false)

Output:
- `-o, --output-dir`       Directory for cloned repos (required unless `--scan-dir`)
- `--output`               Write output to file (default: stdout)
- `--format`               Output format: `text`, `json`, `jsonl`
- `--redact`               Redact secret values in output (default: false)

Global flags (--token, --gitlab-url, --verbose, --insecure-skip-tls-verify, --ca-cert, rate/HTTP tuning) apply as usual.

## Scanner Requirements

At least one scanner must be installed:

- **TruffleHog** -- `brew install trufflehog` or `pip install trufflehog`
- **Gitleaks** -- `brew install gitleaks` or download from GitHub
- **Titus** -- download from GitHub

Use `--scanners auto` to detect all available tools and run them in parallel.

## Examples

### Auto-detect scanners, scan all accessible projects

```bash
gogatoz secretscan --query "" -o ./scan-results
```

### Scan with a specific tool

```bash
gogatoz secretscan --query "deploy" --scanners trufflehog -o ./scan-results
```

### Full git history (not just HEAD)

```bash
gogatoz secretscan --query "" --clone-depth 0 -o ./scan-results
```

### Public projects only (no token)

```bash
gogatoz secretscan --query "" --no-token --visibility public -o ./scan-results
```

### Scan pre-cloned repos (offline mode)

```bash
gogatoz secretscan --scan-dir /path/to/cloned/repos --scanners auto --redact
```

### Find hardcoded tokens across an organization

```bash
gogatoz secretscan \
  --query "" \
  --scanners trufflehog \
  --clone-depth 0 \
  --concurrency 8 \
  -o ./full-scan \
  --redact \
  --json > secrets-report.json
```

### Scan only CI-related projects

```bash
gogatoz secretscan \
  --query "ci runner deploy" \
  --membership \
  --scanners gitleaks \
  -o ./ci-scan
```

## Comparison with enumerate

| Feature | `enumerate` | `secretscan` |
|---------|------------|--------------|
| Scans | CI config (`.gitlab-ci.yml`) | Full git history |
| Finds | CI/CD misconfigurations | Hardcoded secrets in code |
| Requires clone | No (API only) | Yes (clones repos) |
| Tools | Built-in rules engine | TruffleHog, Gitleaks, Titus |
| Speed | Fast (API-based) | Slower (clones + scans) |

These commands are complementary -- use both for full coverage.

## Notes

- The `--scanners auto` mode probes your PATH for available tools and runs all that are found.
- Use `--discard-repos-after-scanning` when disk space is limited. Results are written to stdout/file before repos are removed.
- The `--clone-depth 0` flag clones full git history, which is slower but catches secrets in old commits.
- Respect GitLab rate limits when scanning many projects. Use `--concurrency` and the global rate/retry flags to tune throughput.
