# GoGatoZ Meets BloodHound-CE: Dependency Pwnage Matrix

## Status: IMPLEMENTED (30 tests passing, lint clean)

## Overview

This feature integrates GoGatoZ with BloodHound-CE via the OpenGraph API, mapping the entire GitLab CI/CD attack surface as a navigable graph. It covers:

1. **Dependency Pwnage Matrix** -- recursive walking of cross-project CI/CD includes and trigger chains to map downstream attack surface
2. **Full Attack Surface Graph** -- all search, enumerate, attack, pivot, and secret scan data as BloodHound nodes and edges
3. **SQLite Persistence** -- graph data stored alongside existing scan data for re-export
4. **BloodHound-CE Export** -- OpenGraph-format ZIP files compatible with BH-CE ingestor
5. **API Upload** -- optional direct upload to a BH-CE instance with HMAC-SHA256 auth
6. **Custom Cypher Queries** -- 10 pre-built attack path analysis queries installed as saved queries

## Progress Tracker

### Phase 1: Core Graph Model (`pkg/bloodhound/`)
- [x] `types.go` -- 10 node kinds, 15 edge kinds, Go constants, struct types
- [x] `schema.json` -- OpenGraph extension definition (embedded)
- [x] `seed_data.json` -- Bootstrap edges for all 15 kinds (embedded)
- [x] `writer.go` -- StreamingWriter with edge dedup, thread-safety

### Phase 2: Graph Builder
- [x] `builder.go` -- Converts enumerate/search/attack/pivot/secret data to graph
- [x] `builder_test.go` -- 9 unit tests (enumerate, transitive deps, shared runners, attacks, pivots, tag extraction, node ID determinism, no-colon check)

### Phase 3: ZIP Export
- [x] `exporter.go` -- ZIP packaging with seed_data.json + cicd-data.json
- [x] `exporter_test.go` -- 2 tests (full export, empty builder)

### Phase 4: Store Integration
- [x] `GraphNode` and `GraphEdge` models added to `pkg/store/models.go`
- [x] `SaveGraphNodes/Edges`, `GetGraphNodes/Edges` in `pkg/store/store.go`
- [x] All existing store tests still pass

### Phase 5: API Client
- [x] `auth.go` -- HMAC-SHA256 (3-step chain) + Bearer auth
- [x] `client.go` -- Schema upload, file upload (start/upload/end), Cypher queries, saved queries
- [x] `auth_test.go` -- 5 tests
- [x] `client_test.go` -- 5 tests with httptest mocks (schema, upload flow, cypher, saved query, retry)

### Phase 6: Cypher Queries
- [x] `queries.go` -- 10 pre-built attack path queries

### Phase 7: CLI Integration
- [x] `cmd/bloodhound.go` -- `bloodhound` (alias: `bh`) with export/upload/queries/schema subcommands
- [x] `--bloodhound-export` flag on `enumerate` command
- [x] Environment variables: `GOGATOZ_BH_URL`, `GOGATOZ_BH_TOKEN_ID`, `GOGATOZ_BH_TOKEN_KEY`

### Phase 8: Testing & Verification
- [x] 30 unit tests passing
- [x] Lint clean (0 issues)
- [x] Full project builds
- [ ] End-to-end upload test against BH-CE instance

## Usage

```bash
# Export enumerate results directly to BloodHound-CE ZIP
gogatoz enumerate --input projects.txt --bloodhound-export attack-surface.zip

# Export from database session
gogatoz bloodhound export --session 1 --output attack-surface.zip

# Export from JSONL file
gogatoz bh export --input results.jsonl --output attack-surface.zip

# Upload schema to BloodHound-CE
gogatoz bh schema --url https://bloodhound.example.com --token-id XXX --token-key YYY

# Upload schema + data
gogatoz bh upload --session 1 --url https://bloodhound.example.com --token-id XXX --token-key YYY

# Install Cypher attack path queries
gogatoz bh queries --url https://bloodhound.example.com --token-id XXX --token-key YYY
```

## Graph Schema

### Node Types (10)
| Kind | Icon | Color | Description |
|------|------|-------|-------------|
| `CICD_GitLabInstance` | server | #FC6D26 | GitLab instance |
| `CICD_Group` | folder | #6B4FBB | Group/subgroup |
| `CICD_Project` | code-branch | #1F75CB | Repository |
| `CICD_Runner` | microchip | #E24329 | Self-hosted runner |
| `CICD_CIConfig` | file-code | #2E7D32 | .gitlab-ci.yml |
| `CICD_Job` | gear | #0288D1 | CI/CD job |
| `CICD_Finding` | bug | #D32F2F | Security finding |
| `CICD_Secret` | key | #F57C00 | CI/CD variable |
| `CICD_Pipeline` | play | #7B1FA2 | Pipeline (attacks) |
| `CICD_Credential` | id-badge | #C62828 | Harvested credential |

### Edge Types (15)
| Kind | Traversable | Description |
|------|------------|-------------|
| `CICD_Contains` | no | Group->Project, Project->Config, Config->Job |
| `CICD_MemberOf` | no | Project->Group |
| `CICD_IncludesProject` | **yes** | Cross-project CI include |
| `CICD_IncludesRemote` | **yes** | Remote URL include |
| `CICD_IncludesTemplate` | no | GitLab template include |
| `CICD_IncludesComponent` | **yes** | CI component include |
| `CICD_IncludesLocal` | no | Local file include |
| `CICD_RunsOn` | **yes** | Job->Runner |
| `CICD_HasFinding` | no | Project->Finding |
| `CICD_HasSecret` | no | Project->Secret |
| `CICD_Exploited` | **yes** | Attack->Project |
| `CICD_PivotsTo` | **yes** | Credential from Project |
| `CICD_DependsOn` | **yes** | Transitive dependency |
| `CICD_TriggersDownstream` | **yes** | Downstream trigger |
| `CICD_SharedRunner` | **yes** | Shared runner link |

## Architecture Decisions

1. **New `pkg/bloodhound/` package** -- separate from `pkg/graph/` (different data model and purpose)
2. **Direct HMAC auth** -- ported from MSSQLHound (avoids `bloodhound-go-sdk` dependency)
3. **Deterministic node IDs** -- `cicd-project-{id}` format, no colons (BH-CE restriction)
4. **Namespace: `CICD_`** -- per BH-CE OpenGraph requirements
5. **ZIP export** -- seed_data.json + cicd-data.json (official BH-CE ingest format)
6. **Streaming writer** -- handles large graphs without buffering all JSON in memory
