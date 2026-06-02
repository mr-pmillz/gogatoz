# pkg/gitlabx

GitLab API client wrapper extending the official `gitlab.com/gitlab-org/api/client-go` library with enterprise-grade reliability. Provides token-bucket rate limiting, automatic retry with jittered exponential backoff (429/5xx), configurable TLS with custom CA support, HTTP connection pooling, code search, repository tree listing, runner discovery, GraphQL support, and CI template/component fetching. Leaf package with no internal dependencies.

## Files

| File | Purpose |
|------|---------|
| `client.go` | Core client initialization, URL normalization, round-tripper middleware (rate limit, retry, headers), GraphQL/REST utilities |
| `search.go` | Code search within projects via `/projects/:id/search?scope=blobs` with pagination |
| `runners.go` | Runner discovery across project, group, and instance level with pagination |
| `tree.go` | Repository tree listing with recursive support, blob filtering, pagination |
| `languages.go` | Project language detection via `/projects/:id/languages` |
| `components.go` | CI/CD component YAML fetching via GraphQL with heuristic field detection |

## Exported API

### Types

- `Client` — main wrapper: `GL` (*gitlab.Client), rate limiter, HTTP client, baseURL, token
- `Option` — functional option type for configuration
- `CodeSearchMatch` — Path, Filename, Startline, Data
- `RepoTreeEntry` — Path and Type ("blob"/"tree")
- `RunnerInfo` — ID, Description, Active, IsShared, Online, Status, TagList, Executor
- `GraphQLResponse` — Data (json.RawMessage) and Errors

### Constructor & Options

- `New(baseURL, token string, opts ...Option) (*Client, error)`
- `WithRateLimit(rps, burst)` — default: 8 RPS, 16 burst
- `WithRetry(maxAttempts)` — default: 3
- `WithHTTPPool(maxIdle, perHost)` — default: 256, 64
- `WithHTTPTimeouts(idleConn, tlsHandshake, expectContinue, request)` — default: 90s, 10s, 1s, 30s
- `WithInsecureTLS(skip)`, `WithRootCAs(pool)`, `WithUserAgent(ua)`

### Client Methods

- `Ping(ctx)` — verify token via /user
- `APIURL(rel)` — compose full API URLs
- `Token()`, `HTTPClient()` — accessors
- `GraphQL(ctx, query, variables)` — execute GraphQL queries
- `GetCIYMLTemplate(ctx, name)` — fetch built-in CI template
- `GetProtectedBranches(ctx, projectID, perPage, page)` — list protected branches
- `CodeSearch(ctx, projectID, query, ref, perPage, maxPages)` — search code
- `ListRepoTreePaths(ctx, projectID, ref, recursive, perPage, maxPages)` — list file paths (blobs only)
- `GetProjectLanguages(ctx, projectID)` — language percentages
- `GetComponentYAML(ctx, id, version)` — fetch CI component YAML
- `ListProjectRunners/AccumulateProjectRunners/AccumulateGroupRunners/AccumulateAllRunners` — runner APIs

## Internal Patterns

**Round-Tripper Middleware Chain**: Request flows through: rateLimitedRoundTripper -> retryingRoundTripper -> headerRoundTripper -> http.Transport. Each layer is composable and independently testable.

**Rate Limiting**: Token bucket via `golang.org/x/time/rate`. `Limiter.Wait(ctx)` blocks until token available; respects context cancellation. Per-client instance.

**Retry Logic**: Retryable codes: 429, 502, 503, 504. Backoff: 200ms base, exponential doubling, 2s max, +/-25% jitter via crypto/rand. Honors Retry-After header. Body properly closed before retry.

**URL Normalization**: `normalizeBaseURL()` handles: plain hostnames -> https://, trailing slashes removed, `/api/v4` stripped recursively, subpath preserved.

**GraphQL**: Raw HTTP to `/api/graphql` with dual headers (`PRIVATE-TOKEN` + `Authorization: Bearer`). Logical errors surfaced as Go errors.

## Testing

- `client_test.go` — fake RoundTripper for retry logic (429->OK sequences, max-attempts cutoff, context cancellation)
- `new_test.go` — URL normalization table-driven tests
- `graphql_test.go` — GraphQL request/response and error propagation
- `search_test.go`, `tree_test.go`, `languages_test.go` — httptest.Server functional tests with pagination, header verification
- `runners_integration_test.go` — credential-gated live API tests (skipped unless TEST_API_PAT or CI_JOB_TOKEN set)

## Dependencies

**Imports:** None from `pkg/` — leaf package.

**Depended on by:** `pkg/enumerate`, `pkg/pipeline`, `pkg/attack` (+ secretsdump, ror, webshell_utils), `pkg/api`

## Gotchas

1. **Rate limiter is per-client** — multiple Client instances have independent rate limits
2. **Does NOT retry on 400/401/403/404** — only 429, 502, 503, 504
3. **Jitter uses crypto/rand** — slightly slower but satisfies gosec linters
4. **Context cancellation during backoff** returns immediately (fast cancellation for workers)
5. **ListRepoTreePaths filters to blobs only** — directories excluded; use official client for trees
6. **CodeSearch keeps page=1 constant** — X-Next-Page header drives pagination (intentional, noted in code)
7. **GetComponentYAML uses heuristic field detection** — searches JSON recursively for `content`/`yaml`/`ciYml`/`text`
8. **AccumulateGroupRunners uses raw HTTP** — SDK gap; manual JSON parsing
9. **Request timeout (30s) covers entire lifecycle including retries**
10. **Client is safe for concurrent use** — rate.Limiter and http.Client are both thread-safe
11. **SDK uses int64 everywhere** — all entity IDs, all pagination fields (ListOptions.Page/PerPage, Response.NextPage) are int64 as of client-go v1.34.0
12. **Runner.Active is deprecated** — use `!Runner.Paused` instead; similarly `Project.TagList` → `Topics`
