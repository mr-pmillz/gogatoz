---
title: API Server
description: Use the GoGatoZ HTTP API to validate tokens, enumerate projects, stream findings, and search GitLab from agents and tools
---

GoGatoZ ships a lightweight HTTP API that exposes its auth, enumeration, and
search capabilities as simple JSON endpoints. It is designed for wiring GoGatoZ
into agents, pipelines, and other tooling without shelling out to the CLI.

The server is implemented in Go (no Python runtime) and talks to GitLab through
the official `client-go` SDK. It is intentionally **thin and stateless**: there
is no database and no session — every request carries (or inherits) its own
GitLab credentials and options, and the work is delegated to the same engine the
CLI uses.

:::caution[The API has no built-in authentication]
Any client that can reach the listen address can drive scans with whatever token
it supplies (or with the server's `GITLAB_TOKEN`). **Bind it to localhost** (the
default exposure should be `127.0.0.1:<port>`) or place it behind your own
authenticated reverse proxy / network controls. Never expose it directly to an
untrusted network.
:::

## Running the server

```bash
# Listen on :8088, default GitLab base URL from --gitlab-url / GITLAB_URL
./gogatoz api-server --listen :8088 --base-url https://gitlab.com
```

On startup it logs to stderr, e.g. `[api] starting server on :8088 (base=https://gitlab.com)`.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8088` | Listen address (`host:port`). Use `127.0.0.1:8088` to restrict to localhost. |
| `--base-url` | `--gitlab-url` → `GITLAB_URL` → `https://gitlab.com` | Default GitLab instance for requests that don't set `gitlab_url`. |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GOGATOZ_API_LISTEN` | Overrides `--listen`. |
| `GOGATOZ_API_BASE_URL` | Overrides `--base-url`. |
| `GITLAB_URL` | Fallback default base URL. |
| `GITLAB_TOKEN` | Fallback PAT used when a request omits `auth.token`. |

## Authentication model

Credentials are resolved **per request** with this precedence:

1. The token / URL in the request body
2. The server's `GITLAB_TOKEN` env var (token only)
3. `--base-url` → `GITLAB_URL` → `https://gitlab.com` (base URL only)

Two body shapes are used:

- `/auth/validate` takes the credentials at the **top level**: `{ "token": "...", "gitlab_url": "..." }`.
- All `/enumerate/*` and `/search/*` endpoints nest them under an **`auth`** object: `{ "auth": { "token": "...", "gitlab_url": "..." }, ... }`.

If no token can be resolved, the endpoint responds `400 { "error": "missing token" }`.

Use a GitLab Personal Access Token (PAT) with scopes `api` and `read_repository`
(enumeration and search need only read access; `write_repository` is for the
attack modules, which the API does not expose).

## Endpoints

Base path: `http://HOST:PORT`

| Method | Path | Purpose | Response |
|--------|------|---------|----------|
| `GET` | `/healthz` | Liveness check | `{ "ok": true }` |
| `POST` | `/auth/validate` | Validate a PAT via GitLab `Ping` | `{ "ok": true, "user": {…} }` |
| `POST` | `/enumerate/repo` | Scan a single project | `[Result]` |
| `POST` | `/enumerate/repos` | Scan multiple projects | `[Result]` |
| `POST` | `/enumerate/org` | Expand and scan a group | `[Result]` |
| `POST` | `/enumerate/group` | Alias for `/enumerate/org` | `[Result]` |
| `POST` | `/enumerate/stream` | Scan and stream results as NDJSON | `Result` per line |
| `POST` | `/search/projects` | Search projects with filters | `{ projects, total_found, returned }` |

Errors are returned as `{ "error": "<message>" }` with an appropriate status:
`400` (bad request / missing token / invalid input), the upstream GitLab status
for auth failures (`401`/`403`), or `502` for upstream/transport errors.

### GET /healthz

```bash
curl -s http://localhost:8088/healthz
# {"ok":true}
```

### POST /auth/validate

Validates the token by calling GitLab and returns the authenticated user.

```bash
curl -s http://localhost:8088/auth/validate \
  -H 'Content-Type: application/json' \
  -d '{"token":"glpat-xxxxxxxxxxxx","gitlab_url":"https://gitlab.com"}'
```

```json
{ "ok": true, "user": { "id": 12345, "username": "octocat", "name": "Octo Cat" } }
```

A bad token returns the upstream status (e.g. `401`) with `{ "ok": false, "error": "…" }`.

### POST /enumerate/repo

Scan one project by numeric ID or `group/project` path.

```bash
curl -s http://localhost:8088/enumerate/repo \
  -H 'Content-Type: application/json' \
  -d '{
        "auth": { "token": "glpat-xxxxxxxxxxxx" },
        "ident": "my-group/my-project",
        "options": { "concurrency": 8, "follow_includes": true, "include_depth": 2 }
      }'
```

Returns a JSON array of [Result](#result-schema) objects (one element here).

### POST /enumerate/repos

Scan many projects in one call. `idents` accepts numeric IDs and/or paths.

```bash
curl -s http://localhost:8088/enumerate/repos \
  -H 'Content-Type: application/json' \
  -d '{
        "auth": { "token": "glpat-xxxxxxxxxxxx" },
        "idents": ["my-group/proj-a", "my-group/proj-b", "12345"],
        "options": { "concurrency": 16, "fetch_runners": true, "fetch_protected": true }
      }'
```

### POST /enumerate/org  (and /enumerate/group)

Expand a group to its projects, then scan them. `group` is a numeric ID or full
path; set `include_subgroups` to recurse. `/enumerate/group` is an alias.

```bash
curl -s http://localhost:8088/enumerate/org \
  -H 'Content-Type: application/json' \
  -d '{
        "auth": { "token": "glpat-xxxxxxxxxxxx" },
        "group": "my-group/sub-group",
        "include_subgroups": true,
        "options": { "concurrency": 16, "follow_includes": true }
      }'
```

### POST /enumerate/stream

Same body as `/enumerate/repos`, but results are streamed as
**newline-delimited JSON** (`application/x-ndjson`) — one `Result` object per
line, flushed as each project finishes. Ideal for long runs and real-time
processing. If the run errors, a final `{"error":"…"}` line is emitted (the HTTP
status stays `200`).

```bash
curl -N -s http://localhost:8088/enumerate/stream \
  -H 'Content-Type: application/json' \
  -d '{
        "auth": { "token": "glpat-xxxxxxxxxxxx" },
        "idents": ["my-group/proj-a", "my-group/proj-b"],
        "options": { "concurrency": 8 }
      }' | jq -c '{project: .path_with_namespace, findings: (.findings | length)}'
```

> `curl -N` disables buffering so lines appear as they stream.

### POST /search/projects

Search GitLab projects with optional filters. Returns an envelope, not a bare
array.

```bash
curl -s http://localhost:8088/search/projects \
  -H 'Content-Type: application/json' \
  -d '{
        "auth": { "token": "glpat-xxxxxxxxxxxx" },
        "options": {
          "query": "runner",
          "visibility": "public",
          "topic": "security",
          "path_pattern": ".gitlab-ci.yml",
          "per_page": 50,
          "max_pages": 2
        }
      }'
```

```json
{
  "projects": [
    {
      "id": 4242,
      "path_with_namespace": "acme/ci-templates",
      "web_url": "https://gitlab.com/acme/ci-templates",
      "visibility": "public",
      "default_branch": "main",
      "star_count": 17
    }
  ],
  "total_found": 1,
  "returned": 1
}
```

`visibility` must be one of `public`, `internal`, `private` (or omitted).

## Enumerate options

All fields are optional and go inside `"options"`. JSON keys are `snake_case`.

| Field | Type | Description |
|-------|------|-------------|
| `concurrency` | int | Worker pool size for parallel project scans. |
| `timeout` | string | Per-request scan timeout as a Go duration (e.g. `"30s"`, `"5m"`). |
| `follow_includes` | bool | Resolve `include:` directives in `.gitlab-ci.yml`. |
| `include_depth` | int | Max recursion depth for include resolution. |
| `allow_remote_includes` | bool | Allow fetching `include: remote:` URLs. |
| `remote_allowlist` | string[] | Host allowlist for remote includes. |
| `remote_max_bytes` | int | Max size for a fetched remote include. |
| `remote_timeout` | string | Timeout (duration) for remote include fetches. |
| `remote_cache_ttl` | string | Cache TTL (duration) for remote includes. |
| `fetch_protected` | bool | Fetch protected-branch metadata. |
| `fetch_runners` | bool | Discover and enrich with runner information. |
| `runner_scope` | string | Runner discovery scope (e.g. `project`, `group`, `instance`). |
| `allow_admin` | bool | Permit admin-scoped runner queries. |
| `log_scrape` | bool | Scrape recent job logs for secrets/findings. |
| `log_max_pipelines` | int | Max pipelines to inspect when log scraping. |
| `log_max_jobs` | int | Max jobs to inspect when log scraping. |
| `refs` | string[] | Non-default refs to scan (default branch only if empty). |
| `max_refs` | int | Cap on the number of refs scanned. |

## Search options

| Field | Type | Description |
|-------|------|-------------|
| `query` | string | Project search term. |
| `per_page` | int | Results per API page. |
| `max_pages` | int | Max pages to fetch (`0` = all). |
| `owned` | bool | Restrict to projects you own. |
| `membership` | bool | Restrict to projects you are a member of. |
| `visibility` | string | `public`, `internal`, or `private`. |
| `archived` | bool | Include archived projects. |
| `path_exists` | string | Keep only projects containing this repo path. |
| `path_pattern` | string | Glob pattern matched against the repo tree (`*`, `**`, `?`). |
| `code_content` | string | Keep only projects whose code matches this content search. |
| `language` | string | Filter by language (comma-separated, any-of). |
| `topic` | string | Filter by topic/tag (comma-separated, any-of). |
| `ref` | string | Ref to use for path/code filters. |
| `path_per_page` / `path_max_pages` | int | Pagination for path-pattern filtering. |
| `code_per_page` / `code_max_pages` | int | Pagination for code-content filtering. |
| `concurrency` | int | Worker pool size for per-project filtering. |

## Result schema

`/enumerate/repo`, `/enumerate/repos`, and `/enumerate/org` return a JSON array
of these objects; `/enumerate/stream` emits one per NDJSON line. Fields tagged
`omitempty` appear only when populated.

```json
{
  "project_id": 4242,
  "path_with_namespace": "acme/api",
  "web_url": "https://gitlab.com/acme/api",
  "default_branch": "main",
  "star_count": 17,
  "scanned_ref": "main",
  "has_ci_pipeline": true,
  "ci_summary": "3 jobs across 2 stages",
  "findings": [
    { "rule": "…", "severity": "high", "title": "…", "evidence": "…" }
  ],
  "protected_branches": ["main", "release/*"],
  "runner_scope": "project",
  "runners_total": 4,
  "runners_online": 3,
  "runner_executors": { "shell": 2, "docker": 2 },
  "log_findings_count": 0,
  "duration_ms": 812,
  "error": ""
}
```

The `findings` array uses the same `analyze.Finding` shape as the CLI's JSON
output, so anything that consumes `gogatoz enumerate --json` works unchanged.
A per-project `error` string is set when that project failed (other results in
the batch are still returned).

## Example: Python client

```python
import requests

BASE = "http://localhost:8088"
AUTH = {"token": "glpat-xxxxxxxxxxxx", "gitlab_url": "https://gitlab.com"}

# 1) validate the token
requests.post(f"{BASE}/auth/validate", json=AUTH).raise_for_status()

# 2) batch enumerate
resp = requests.post(f"{BASE}/enumerate/repos", json={
    "auth": AUTH,
    "idents": ["my-group/proj-a", "my-group/proj-b"],
    "options": {"concurrency": 16, "fetch_runners": True},
})
for result in resp.json():
    print(result["path_with_namespace"], len(result.get("findings", [])))

# 3) stream enumerate (process results as they arrive)
with requests.post(f"{BASE}/enumerate/stream", json={
    "auth": AUTH,
    "idents": ["my-group/proj-a", "my-group/proj-b"],
    "options": {"concurrency": 8},
}, stream=True) as s:
    for line in s.iter_lines():
        if line:
            print(line.decode())
```

## Troubleshooting

- **`missing token`** — supply `auth.token` (or `token` for `/auth/validate`), or
  start the server with `GITLAB_TOKEN` set.
- **`502` / connection errors** — the server can't reach your GitLab instance.
  For self-hosted instances with custom CAs or self-signed certs, prefer the CLI
  (which exposes TLS flags) over the API server.
- **Streaming shows nothing until the end** — pass `curl -N` to disable client
  buffering.
- Request and startup logs are written to stderr.

## See also

- [Enumerate](/user-guide/command-reference/enumerate/) — the CLI equivalent of the `/enumerate/*` endpoints.
- [Search](/user-guide/command-reference/search/) — the CLI equivalent of `/search/projects`.

This API is evolving; the endpoint surface may change. The implementation lives
in `pkg/api/`.
</content>
