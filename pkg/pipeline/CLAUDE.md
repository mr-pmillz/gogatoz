# pkg/pipeline

Parser and resolver for GitLab CI/CD pipeline configuration (`.gitlab-ci.yml`). Handles YAML parsing, recursive include resolution for all 5 GitLab include types (local, project, remote, template, component), job inheritance via `extends`, YAML merge key (`<<`) semantics, and provenance tracking to identify which includes contributed which jobs. Foundation for the enumerate and analyze phases.

## Files

| File | Purpose |
|------|---------|
| `parser.go` | `Parse()` entry point, `Document`/`Job`/`Include`/`Workflow`/`IncludeType` types, YAML merge key resolution, extends application, field normalization |
| `resolve.go` | `ResolveIncludes()`/`ResolveIncludesWithOptions()`, recursive include resolution for all 5 types, visited set, TTL caching, `ResolveOptions` struct |
| `merge.go` | `resolveMergesMap()` for YAML `<<`, `applyExtends()` with cycle detection, `deepMerge()` for recursive map merging |

## Exported API

### Types

- `Document` — Raw, Stages, Variables, Includes, Workflow, Default, BeforeScript, AfterScript, Jobs, Provenance (map[jobName][]Include). Method: `DebugString()`
- `Job` — Name, Stage, Script, BeforeScript, AfterScript, Rules, Only, Except, Tags, Variables, Needs, Extends, When, AllowFailure, Environment, Trigger, Image, Services, Artifacts, Cache
- `Include` — Type, Local, Project, File, Ref, Remote, Template, Component, Inputs
- `IncludeType` (string) — constants: `IncludeLocal`, `IncludeProject`, `IncludeRemote`, `IncludeTemplate`, `IncludeComponent`
- `Workflow` — Name, Rules (raw any)
- `ResolveOptions` — AllowRemote, RemoteAllowHosts, RemoteMaxBytes, RemoteTimeout, RemoteCacheTTL

### Functions

- `Parse(r io.Reader) (*Document, error)` — parse YAML into Document; applies merge key and extends automatically
- `ResolveIncludes(ctx, cl, projectID, ref, base, depth) (*Document, error)` — resolve with defaults (remote disabled)
- `ResolveIncludesWithOptions(ctx, cl, projectID, ref, base, depth, ropts) (*Document, error)` — resolve with custom options; returns merged doc + partial error

## Internal Patterns

### Include Resolution (All 5 Types)

- Depth-limited recursion with `walkInclude` closure
- Visited set prevents re-fetching (keyed by type+project+ref+path)
- Per-call cache + cross-call TTL cache (sync.Mutex protected) for remote includes
- Graceful degradation: errors collected in `partials`; returns `(mergedDoc, partialError)`
- Variables prefer base (dst wins), jobs appended, stages merged unique

### Job Inheritance (`extends`)

- Depth-first resolution with cycle detection (visiting set)
- Multiple parents: `extends: [p1, p2]` — p2 values win on conflict
- `deepMerge()` for recursive nested map merging
- Original Extends list preserved in final Job for provenance

### YAML Merge Key (`<<`)

- `resolveMergesMap()` processes children before applying `<<` at parent level
- Handles map[string]any, map[any]any, []any uniformly
- Parent list `<<: [*p1, *p2]` — later parents override earlier; child overrides all

### Provenance Tracking

- `Document.Provenance` maps job name to list of Include origins
- Multi-include support: same job from multiple includes creates multiple entries
- Root document jobs have no provenance entries

### Field Normalization

- Image: string or `{name, entrypoint}` map — extracts name only
- Services: string, array, or objects with name/image — normalized to []string
- Script: string or []string — always []string
- Tags: string or []string — always []string

## Testing

- 14 test files covering parsing, all 5 include types, extends, merge key, job fields, workflow, component inputs, provenance, remote (allowlist/size/TLS/cache), templates
- Embedded YAML constants (majority); one external fixture (`testdata_job_fields.yml`)
- Mock patterns: `httptest.NewServer/NewTLSServer` for remote includes, mock GitLab client for templates
- Helper: `findJob()` for locating jobs by name in tests

## Dependencies

### Imports

- `pkg/gitlabx` — `Client` for API calls: `GL.RepositoryFiles.GetFile()` (local/project), `GetCIYMLTemplate()` (templates), `GetComponentYAML()` (components), `HTTPClient()` (remote fetches)

### Depended on by

- `pkg/analyze` — receives parsed Document for vulnerability analysis
- `pkg/enumerate` — calls Parse/ResolveIncludes during project scanning
- `pkg/graph` — uses Document/Job for DAG construction
- `pkg/attack/payloads` — uses Parse for YAML validation in tests

## Gotchas

1. **Partial errors returned alongside merged doc** — caller must check error to know if resolution was incomplete
2. **Unpinned project includes** — when ref not specified, resolver fetches project default branch and adds partial error
3. **Empty remote allowlist rejects all remote includes** — not a safelist, but per-call check
4. **Component inputs substitution is naive** — simple `${key}` string replacement, not YAML-aware
5. **Service name normalization drops metadata** — aliases and other fields lost
6. **Rules/Only/Except stored as raw `any`** — not parsed by this package; left to analyzer
7. **Extends cycle handling** — cycles don't error; visiting job returned as-is (may contain unresolved extends)
8. **Remote includes fetched sequentially** — not parallelized; each has per-fetch timeout
9. **Global remote cache** — thread-safe (sync.Mutex) but no smart invalidation
10. **Deep recursion risk** — include depth parameter must be bounded; default or unbounded can hit limits
11. **Job-level before/after scripts**: `Job.BeforeScript` and `Job.AfterScript` are populated from job-level `before_script`/`after_script` YAML keys (nil if not set, meaning the job inherits the global `Document.BeforeScript`/`AfterScript`). The `effectiveScripts()` helper in `pkg/analyze` merges these correctly for injection/LOTP analysis.

## Configuration

### ResolveOptions fields

| Field | Default | Purpose |
|-------|---------|---------|
| `AllowRemote` | false | Enable remote include resolution |
| `RemoteAllowHosts` | empty (reject all) | Exact-match case-insensitive host filter |
| `RemoteMaxBytes` | 0 -> 1 MiB | Max bytes per remote fetch |
| `RemoteTimeout` | 0 -> 10s | Per-fetch timeout |
| `RemoteCacheTTL` | 0 (disabled) | Cross-call TTL cache duration |
