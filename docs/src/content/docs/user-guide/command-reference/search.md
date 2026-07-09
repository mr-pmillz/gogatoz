---
title: Search Command
description: Query GitLab for projects matching search criteria and optional filters
---

The search command queries GitLab for projects matching a simple search string and optional filters. If no --query is provided, it lists projects using the configured filters. Use this to discover candidate projects before running enumerate.

## Basic Usage

```bash
./gogatoz search [options]
```

Authentication:

```bash
export GITLAB_TOKEN=glpat_xxx
export GITLAB_URL=https://gitlab.com   # optional, defaults to https://gitlab.com
```

You can also pass --token and --gitlab-url flags explicitly.

## Options

Project search:
- --query, -q          Search query (matches project name/path/description)
- --per-page           Projects per page (default: 50)
- --max-pages          Maximum number of pages to fetch (default: 1)

Filters:
- --owned              Only projects owned by the authenticated user
- --membership         Only projects the authenticated user is a member of
- --visibility         Filter by visibility: public|internal|private
- --archived-only      Only archived projects
- --language           Filter by programming language (comma-separated)
- --topic              Filter by project topics/tags (comma-separated)
- --path-exists        Only projects containing a specific file (e.g., `.gitlab-ci.yml`)
- --path-pattern       Glob pattern for repo file paths (e.g., `scripts/*.sh`)

Advanced (per-project code content filter):
- --code-content       Additional content query to run against each matched project's repository (scope=blobs)
- --code-ref           Git reference (branch/tag/commit) for code search; defaults to the project's default branch
- --code-per-page      Code search results per page (default: 20)
- --code-max-pages     Max pages to fetch per project (default: 1)
- --code-concurrency   Concurrency for per-project code searches (default: GOMAXPROCS; capped at 64)

Output:
- --output             Write output to file (default: stdout)
- --format             Output format: text|json|jsonl (default respects --json)
- --json               Output JSON instead of text
- --verbose, -v        Verbose logging
- --gitlab-url         GitLab base URL (default: https://gitlab.com)
- --token              GitLab Personal Access Token (scopes: api)
- --insecure-skip-tls-verify  Skip TLS certificate verification (self-hosted GitLab; for testing)
- --ca-cert            Path to PEM file with additional trusted CA certificate(s)
- --rate-rps, --rate-burst, --retry-max, --user-agent, --http-*  Reliability and HTTP tuning (see README)

## Examples

### Simple search with JSON output

```bash
./gogatoz search -q "runner" --per-page 50 --max-pages 2 --json
```

### Projects you own

```bash
./gogatoz search -q "ci" --owned --json
```

### Member projects with internal visibility

```bash
./gogatoz search -q "pipeline" --membership --visibility internal --json
```

### Archived public projects

```bash
./gogatoz search -q "deprecated" --archived-only --visibility public --json
```

### Filter projects by code content

```bash
# Keep only projects where their repository contains the given string (searched via scope=blobs)
./gogatoz search -q "runner" --code-content "tags: self-hosted" --code-per-page 10 --json
```

### Search for hardcoded tokens in code

```bash
gogatoz search --code-content "glpat-" --json
```

### Only CI-enabled projects

```bash
gogatoz search -q "" --path-exists ".gitlab-ci.yml" --json
```

### Filter by language

```bash
gogatoz search -q "" --language python --membership --json
```

### Save results to file for pipeline into enumerate

```bash
gogatoz search --json --output targets.json
gogatoz enumerate -i targets.json --json > findings.json
```

## Output

- Text: prints one line per project: `path_with_namespace<TAB>http_url_to_repo`
- JSON: array of objects with fields like id, path_with_namespace, http_url_to_repo, web_url, visibility, default_branch, etc.

Tip: Pipe JSON output into jq to generate an input file for enumerate:

```bash
./gogatoz search -q runner --max-pages 5 --json | jq -r '.[].path_with_namespace' > projects.txt
./gogatoz enumerate -i projects.txt --json
```

## Notes

- This command uses GitLab REST API v4 ListProjects with a simple project Search. It also supports optional per-project code content filtering via the GitLab code search endpoint (scope=blobs) using --code-content. Path filtering (`--path-exists`, `--path-pattern`), language filtering (`--language`), and topic filtering (`--topic`) are available for targeted discovery.
- Respect rate limits using the global flags (--rate-rps/--rate-burst/--retry-max, HTTP pool/timeouts).
