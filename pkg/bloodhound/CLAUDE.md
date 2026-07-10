# pkg/bloodhound

## Purpose

BloodHound-CE OpenGraph integration for GoGatoZ. Maps GitLab CI/CD attack surface data (projects, groups, runners, findings, attack results, pivot chains) into a BloodHound-CE compatible graph. Supports export to ZIP, direct API upload with HMAC-SHA256 authentication, and pre-built Cypher attack path queries.

## Files

| File | Purpose |
|------|---------|
| `types.go` | Node/edge kind constants (`CICD_` namespace), struct types (`Node`, `Edge`, `SavedQuery`), `AllNodeKinds()`/`AllRelKinds()` metadata |
| `schema.json` | Embedded OpenGraph extension definition (10 node kinds, 15 relationship kinds, 1 environment) |
| `seed_data.json` | Embedded bootstrap data — one dummy edge per relationship kind for BH-CE kind registration |
| `writer.go` | `StreamingWriter` — streaming OpenGraph JSON output with edge deduplication, thread-safety, `Stats()`/`TypeStats()` |
| `builder.go` | `Builder` — converts all GoGatoZ scan data types into graph nodes/edges, extracts cross-project dependencies from finding evidence, builds transitive `CICD_DependsOn` edges (BFS), detects shared runners |
| `exporter.go` | `Export()`/`ExportToWriter()` — packages graph into BH-CE compatible ZIP (seed_data.json + cicd-data.json) |
| `auth.go` | `Authenticator` interface, `HMACAuth` (3-step HMAC-SHA256 chain), `BearerAuth` |
| `client.go` | `Client` — BH-CE API client: schema upload, file upload (start/upload/end), Cypher query execution, saved query CRUD, retry with exponential backoff |
| `queries.go` | `AttackPathQueries()` — 10 pre-built Cypher queries for CI/CD attack path analysis |

## Exported API

**Builder:**
- `NewBuilder(gitlabURL string) *Builder`
- `AddSearchResults(results []map[string]any)`
- `AddEnumerateResults(results []enumerate.Result)`
- `AddAttackResults(attacks []report.AttackView)`
- `AddPivotData(creds []store.HarvestedCredential, secrets []store.ExfiltratedSecret)`
- `AddSecretScanResults(results []store.SecretScanResult)`
- `BuildTransitiveDependencies()` — BFS walk of include graph
- `BuildSharedRunnerEdges()` — creates edges between projects sharing runner tags
- `Nodes() []*Node` / `Edges() []*Edge`

**Export:**
- `Export(b *Builder, outputPath string) error`
- `ExportToWriter(b *Builder, w io.Writer) error`

**Client:**
- `NewClient(baseURL string, auth Authenticator) *Client`
- `UploadSchema(ctx) error`
- `UploadData(ctx, zipPath) error`
- `RunCypher(ctx, query) (map[string]any, error)`
- `CreateSavedQuery(ctx, SavedQuery) error`

## Node ID Scheme

Deterministic, human-readable, no colons (BH-CE restriction):
- `cicd-instance-{sha256(url)[:12]}`
- `cicd-project-{projectID}`
- `cicd-group-{sha256(path)[:16]}`
- `cicd-config-{projectID}`
- `cicd-job-{projectID}-{sha256(jobName)[:12]}`
- `cicd-finding-{projectID}-{sha256(findingID|jobName)[:12]}`

## Dependency Extraction

The builder extracts cross-project dependencies from analyze.Finding evidence:
- `INCLUDE_PROJECT_UNPINNED`: regex `project=(\S+)` → `CICD_IncludesProject` edge
- `INCLUDE_REMOTE`: regex `remote=(\S+)` → `CICD_IncludesRemote` edge
- `INCLUDE_COMPONENT`: `component=...` → `CICD_IncludesComponent` edge
- `TRIGGER_CHAIN_RISK`: regex `project:(\S+)` → `CICD_TriggersDownstream` edge

Transitive dependencies resolved via BFS over the include graph → `CICD_DependsOn` edges.

## Testing

30 unit tests covering: writer (7), builder (9), exporter (2), auth (5), client (5), embedded data (2).
All use in-memory buffers or httptest servers — no external dependencies.
