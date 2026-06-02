# pkg/api

HTTP server exposing GoGatoZ's enumeration, authentication, and project search capabilities via JSON-based REST endpoints. Uses Gin framework. Intentionally thin and stateless — configuration provided per-request, actual work delegated to `pkg/enumerate`. Supports both batch JSON responses and NDJSON streaming for real-time result delivery.

## Files

| File | Purpose |
|------|---------|
| `server.go` | Core HTTP server: route handlers, Config/Server types, request validation, auth logic, enumerator function injection |
| `search.go` | Project search implementation with concurrent per-project filtering |
| `server_test.go` | Unit tests for all endpoints (healthz, auth, enumerate, search) |
| `server_stream_test.go` | Streaming test with fake enumerator, validates NDJSON format and field presence |

## Exported API

**Types:**
- `Config` — `BaseURL` (default GitLab URL), `ListenAddr` (host:port)
- `Server` — instantiated via `NewServer()`

**Functions:**
- `NewServer(cfg Config) *Server` — creates server with all routes, Gin middleware, default enumerator pointing to `enumerate.EnumerateProjects`

## HTTP Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/validate` | Validate GitLab token via Ping |
| POST | `/enumerate/repo` | Scan single repository |
| POST | `/enumerate/repos` | Scan multiple repositories |
| POST | `/enumerate/org` | Expand and scan GitLab group |
| POST | `/enumerate/group` | Alias for `/enumerate/org` |
| POST | `/enumerate/stream` | Scan with NDJSON streaming output |
| POST | `/search/projects` | Search GitLab projects with filters |
| GET | `/healthz` | Liveness check (`{ ok: true }`) |

## Internal Patterns

- **Dependency injection**: `enumFn` and `searchFn` fields swappable for testing with fakes
- **Per-request client creation**: GitLab client created per request from auth body + config defaults
- **Three-tier URL fallback**: request body -> Config.BaseURL -> env `GITLAB_URL` -> `https://gitlab.com`
- **NDJSON streaming**: callback-based progress via `enumerate.Options.Progress`, mutex-protected writes, HTTP flushing
- **Error handling**: custom `httpError` type, `statusFromErr()` for consistent HTTP status mapping

## Testing

- `httptest.NewServer()` with fake enumerator emitting results via Progress callback
- Mock GitLab servers for auth, enumerate, and search endpoints
- Validates NDJSON format, field presence, correct streaming behavior

## Dependencies

**Imports:**
- `pkg/enumerate` — `EnumerateProjects()`, `Options`, `Result` types
- `pkg/gitlabx` — `New()` for client creation, `Ping()` for auth validation
- `pkg/pathutil` — `GlobToRegex()` for path pattern search filters

**Depended on by:**
- `cmd/api.go` — CLI command `gogatoz api-server`

## Gotchas

1. **Streaming returns 200 even on partial failure** — errors emitted as NDJSON lines in body
2. **Auth token from request body, env, or omitted** — `getenv()` strips null bytes and whitespace
3. **Option naming mismatch** — internal `enumerateOptions` uses `AllowRemote` but maps to `enumerate.Options.AllowRemoteIncludes`
4. **Streaming requires http.Flusher** — returns 500 if unsupported
5. **Group expansion uses PerPage: 100** — paginated through GitLab group API
6. **No retry/auth caching** — each request creates a fresh GitLab client

## Configuration

CLI invocation: `gogatoz api-server --listen :8088 --base-url https://gitlab.com`

| Source | Variables |
|--------|-----------|
| CLI flags | `--listen`, `--base-url` |
| Environment | `GOGATOZ_API_LISTEN`, `GOGATOZ_API_BASE_URL`, `GITLAB_URL`, `GITLAB_TOKEN` |
