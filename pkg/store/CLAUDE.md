# pkg/store

## Purpose

SQLite-backed persistence for GoGatoZ scan results, attack outcomes, pivot sessions, and cryptographic keypairs using GORM. Auto-migrates on `Open()`, WAL mode enabled. Use `:memory:` for tests.

## Files

| File | Purpose |
|------|---------|
| `store.go` | `Store` struct wrapping `*gorm.DB`; `Open(dbPath)` constructor with AutoMigrate; CRUD methods for all models |
| `models.go` | 14 GORM models (see below) |
| `store_test.go` | In-memory SQLite tests: session CRUD, search/enumerate/attack persistence, keypair round-trip |

## Models

| Model | Purpose | Key Fields |
|-------|---------|------------|
| `ScanSession` | Groups results from a single invocation | GitLabURL, Status, counts |
| `SearchResult` | Project from search | GitLabProjectID, PathWithNamespace |
| `EnumerateResult` | Scan outcome per project | FindingsCount, RunnersTotal, ProtectedBranches |
| `Finding` | Single vulnerability finding | FindingID, Severity, Title, Evidence, FalsePositive |
| `AttackResult` | Attack operation outcome | Mode, Payload, Branch, PipelineURL, Status |
| `AttackExfilSecret` | Decrypted key/value from exfil artifact | Key, Value |
| `SecretScanResult` | Secret scanning outcome | Scanners, FindingsCount |
| `SecretFinding` | Single detected secret | Scanner, RuleID, File, Secret, Verified |
| `PivotSession` | Pivot operation outcome | MaxDepth, CredentialsFound, CredentialsValid |
| `HarvestedCredential` | Token metadata (no raw values) | TokenHash (SHA256), TokenType, UserID, Scopes |
| `ExfiltratedSecret` | Key/value from exfil callback | SourceProjectPath, Depth, Key, Value |
| `GraphNode` | BloodHound graph node | NodeID, Kind, Properties (JSON) |
| `GraphEdge` | BloodHound graph edge | StartID, EndID, Kind, Properties (JSON) |
| `KeyPair` | RSA keypair for `--auto-encrypt` | Label, PublicPEM, PrivatePEM, KeyBits, SessionID |

## Exported API

- `Open(dbPath) (*Store, error)` — constructor with AutoMigrate
- `Close() error`
- `CreateSession`, `UpdateSession` — session lifecycle
- `SaveSearchResults`, `SaveEnumerateResults`, `SaveAttackResult` — bulk insert
- `SaveKeyPair`, `GetKeyPair`, `GetKeyPairByLabel`, `ListKeyPairs` — keypair CRUD
- `SavePivotSession`, `SaveGraphNodes`, `SaveGraphEdges` — pivot/graph persistence

## Depended on by

- `cmd/` — persist.go, bloodhound.go, graph.go, drift.go, attack_handler_secrets.go (KeyPair)
- `pkg/mcp/` — MCP tool handlers

## Gotchas

1. **Token values never stored** — `HarvestedCredential` stores only SHA256 hashes, never raw tokens
2. **KeyPair stores private keys in plaintext** — deliberate tradeoff for offensive tool UX; rely on filesystem-level encryption for at-rest protection
3. **`:memory:` for tests** — use `openTestStore(t)` helper in tests; auto-closes via `t.Cleanup`
4. **WAL mode** — enables concurrent reads; required for API server + CLI concurrent access
5. **AutoMigrate on every Open** — safe for schema additions but won't remove dropped columns
