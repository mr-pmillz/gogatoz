---
title: CLI Reference
description: Auto-generated command-line reference for all GoGatoZ commands
---

## gogatoz

GitLab CI/CD security scanner and attack toolkit (Go port of Gato-X)

GoGatoZ scans GitLab projects for CI/CD vulnerabilities and can enumerate and attack misconfigurations.

### Global Options

```
      --ca-cert string               Path to PEM file with additional trusted CA certificate(s)
      --config string                Path to config file (YAML/TOML/JSON). If not set, tries ./.gogatoz.yaml if present.
      --gitlab-url string            Base URL of GitLab instance (default "https://gitlab.com")
  -h, --help                         help for gogatoz
      --http-expect-timeout string   HTTP transport: ExpectContinueTimeout (e.g., 1s)
      --http-idle-timeout string     HTTP transport: IdleConnTimeout (e.g., 90s)
      --http-max-idle int            HTTP transport: MaxIdleConns (0=default)
      --http-max-idle-per-host int   HTTP transport: MaxIdleConnsPerHost (0=default)
      --http-req-timeout string      HTTP client: overall request timeout (e.g., 30s)
      --http-tls-timeout string      HTTP transport: TLSHandshakeTimeout (e.g., 10s)
      --insecure-skip-tls-verify     Skip TLS certificate verification (self-hosted GitLab; use only for testing)
      --json                         Output JSON instead of text
      --rate-burst int               Burst size for rate limiter tokens (default 16)
      --rate-rps float               Max requests per second to GitLab API (token bucket) (default 8)
      --retry-max int                Max retry attempts on 429/5xx responses (1 disables retries) (default 3)
      --token string                 GitLab Personal Access Token (or set GITLAB_TOKEN)
      --user-agent string            Custom User-Agent header (optional)
  -v, --verbose                      Verbose logging
```

---

## gogatoz search

Search GitLab projects using the API.

```
gogatoz search [flags]
```

### Options

```
      --archived-only          Only archived projects
      --code-concurrency int   Concurrency for per-project code searches (0=GOMAXPROCS)
      --code-content string    Filter projects by code content match (uses per-project code search)
      --code-max-pages int     Max pages to query per project for code search (default 1)
      --code-per-page int      Code search results per page when filtering (default 20)
      --code-ref string        Git reference (branch/tag/commit) for code search
      --format string          Output format: text|json|jsonl (default respects --json)
  -h, --help                   help for search
      --lang-concurrency int   Concurrency for per-project language API calls (0=GOMAXPROCS)
      --language string        Comma-separated list of languages to filter by
      --max-pages int          Maximum number of pages to fetch (0=all) (default 1)
      --membership             Projects the authenticated user is a member of
      --output string          Write output to file (default: stdout)
      --owned                  Only projects owned by the authenticated user
      --path-concurrency int   Concurrency for per-project path scans (0=GOMAXPROCS)
      --path-exists string     Keep only projects where this exact path exists
      --path-max-pages int     Max pages to fetch from repository tree per project (default 10)
      --path-pattern string    Glob pattern to match repository file paths
      --path-per-page int      Paths per page when scanning the repository tree (default 100)
      --path-ref string        Git reference for path scan
      --per-page int           Projects per page (default 50)
  -q, --query string           Search query (matches name/path/description)
      --topic string           Comma-separated list of project topics/tags to filter by
      --visibility string      Filter by visibility: public|internal|private
```

---

## gogatoz enumerate

Enumerate GitLab projects for CI/CD risks.

```
gogatoz enumerate [flags]
```

### Options

```
      --allow-remote-includes        Allow resolving remote includes (guarded by --remote-allowlist)
      --concurrency int              Number of concurrent workers (default 16)
      --deep                         Enable deep mode (follow includes with depth >=3)
      --follow-includes              Resolve includes transitively up to --include-depth (default true)
      --format string                Output format: text|json|jsonl (default respects --json)
  -h, --help                         help for enumerate
      --include-depth int            Depth for include resolution (default 2)
  -i, --input string                 Path to file with project identifiers, one per line. Use '-' for stdin
      --input-format string          Input format for --input: auto|text|json|jsonl (default "auto")
      --max-refs int                 Maximum number of refs to scan per project (0 = all provided)
      --only-findings                When printing text, only show projects with findings
      --output string                Write output to file (default: stdout)
      --protected-branches           Fetch and include names of protected branches
      --ref string                   Git reference to scan in addition to the default branch
      --refs string                  Comma-separated list of refs to scan per project
      --remote-allowlist string      Comma-separated host allowlist for remote includes
      --remote-cache-ttl string      Cross-call TTL cache for remote includes (e.g., 5m)
      --remote-max-bytes int         Max bytes to fetch for a remote include (default 1MiB)
      --remote-timeout string        Timeout per remote include fetch (default "10s")
      --timeout string               Per-project timeout (e.g., 20s)
      --webhook-header stringArray   Additional HTTP header for webhook POST
      --webhook-timeout string       Timeout per webhook request (e.g., 5s)
      --webhook-url string           Webhook URL to POST findings as JSON envelopes
```

---

## gogatoz attack

Run attack workflows against a target GitLab project.

```
gogatoz attack [flags]
```

### Options

```
      --artifacts-expire string      Artifacts expire_in (e.g., 1 day)
      --artifacts-path string        Artifacts path to upload
      --author-email string          Commit author email
      --author-name string           Commit author name
      --branch string                Branch to commit the CI to (default: gogatoz-attack)
      --ci-file string               Path to CI YAML file to read
      --ci-stdin                     Read CI YAML content from stdin
      --ci-yaml string               Inline CI YAML content
      --cleanup                      Enable cleanup mode to remove attack artifacts
      --cleanup-branch string        Remove specified branch from target project
      --cleanup-ci                   Remove .gitlab-ci.yml from the target branch
      --add-member                   Add a user as project member
      --cmd string                   Command for ror-shell payload (default: 'id; uname -a')
      --commit-ci                    Commit a .gitlab-ci.yml to the target repo
      --deconflict string            Branch deconflict strategy: fail|suffix|force (default "fail")
      --deploy-key                   Create a deploy key with write access on the target project
      --discover-tags                Discover runner tags for the target project and exit
      --download string              Download a file instead of running a command (ror-shell)
      --executor string              Filter discovered tags by executor hint
      --group-id string              Group ID or full path for --group-vars
      --group-vars                   Include group variables in JSON output for --secrets
  -h, --help                         help for attack
      --image string                 Docker image for the payload job
      --include-protected            Include protected variables when listing variables
      --job-name string              Payload job name
      --keepalive int                Keep job alive by emitting heartbeat every N seconds
      --key-path string              Path to save the generated private key (--deploy-key)
      --key-title string             Title for the deploy key (default: 'GoGatoZ Deploy Key')
      --manual                       Add a manual rule to the payload job
      --member-role string           Access level: guest|reporter|developer|maintainer (default: developer)
      --member-username string       Username to add as project member
      --message string               Commit message
      --os string                    Target OS: linux|windows|macos (default "linux")
      --payload string               Built-in payload type (see attack command reference for the full list)
      --payload-only                 Render the selected payload YAML to stdout and exit
      --project-vars                 Include project variables in JSON output for --secrets
      --pubkey-file string           Path to RSA public key to encrypt exfiltrated data
      --remove-member-id int         Remove member by user ID from target project
      --revoke-deploy-key int        Revoke deploy key by ID from target project
      --script-url string            Remote script URL to execute (runner-on-runner)
      --secrets                      Run secrets exfiltration attack
      --stage string                 Payload stage name (default 'attack')
      --tags string                  Comma-separated runner tags for the payload job
  -t, --target string                Target project (ID or path-with-namespace)
      --target-branch-regex string   Regex for target branch name condition (pwn-request)
      --webhook string               Webhook URL to POST env dump for secrets payload
```

---

## gogatoz api-server

Start the GoGatoZ API HTTP server.

```
gogatoz api-server [flags]
```

### Options

```
      --base-url string   Default GitLab base URL for API requests
  -h, --help              help for api-server
      --listen string     Listen address for API server (host:port) (default ":8088")
```

---

## gogatoz version

Show version.

```
gogatoz version [flags]
```

### Options

```
  -h, --help   help for version
```
