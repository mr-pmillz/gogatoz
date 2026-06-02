# pkg/pivot

Automated lateral movement engine for GoGatoZ. Orchestrates the cycle of enumerate → filter exploitable → attack (secrets exfil via HTTP) → receive callback → extract tokens → validate → pivot with new credentials. Uses breadth-first traversal across depth levels.

## Files

| File | Purpose |
|------|---------|
| `orchestrator.go` | Core `Orchestrator` type, BFS pivot loop `Run()`, target filtering, attack dispatch |
| `callback.go` | HTTP `CallbackServer` for receiving exfiltrated secrets, RSA/AES decryption, key generation |
| `credential.go` | Token extraction from env vars, SHA256 hashing, GitLab API validation, thread-safe `CredentialStore` |
| `options.go` | `Options` struct with defaults, `PivotEvent` type for progress reporting |
| `harvest.go` | `Harvester` HTTP callback server for passively collecting tokens from git hook callbacks |
| `harvest_test.go` | Tests for env dump parsing, harvester HTTP callback flow, method validation |

## Exported API

**Types:**
- `Orchestrator` — main pivot loop controller
- `Options` — configuration (targets, limits, callback, RSA, enumerate passthrough)
- `PivotStats` — session summary (projects enumerated/attacked, credentials found/valid, depth, duration)
- `PivotEvent` — progress event (type: depth_start/enumerate/attack/credential/error/depth_end)
- `Credential` — harvested token with metadata (hash, type, source, validation status)
- `CredentialStore` — thread-safe credential tracking with visit dedup
- `CallbackServer` — HTTP server receiving encrypted/unencrypted exfil payloads
- `ExfilPayload` — decoded callback payload with secrets map
- `ExploitableTarget` — project with exploitable finding for attack dispatch
- `Harvester` — HTTP callback server that receives base64-encoded env dumps
- `HarvestOptions` — configuration for harvester (listen addr, GitLab URL, timeout, progress callback)
- `HarvestResult` — session outcome (credentials list, callback count, duration)
- `HarvestEvent` — progress event (type: listening/callback/credential/error)

**Key Functions:**
- `NewOrchestrator(gitlabURL, token, opts)` — constructor
- `Orchestrator.Run(ctx) (*PivotStats, error)` — main pivot loop
- `Orchestrator.Credentials()` — access harvested credentials
- `ExtractTokens(envVars)` — scan env vars for GitLab token patterns
- `ValidateToken(ctx, baseURL, token)` — ping GitLab API to verify token
- `NewCallbackServer(privateKey, bufferSize)` — create callback server
- `CallbackServer.Start(ctx, addr)` / `Stop(ctx)` / `Receive(ctx, timeout)` — lifecycle
- `GenerateKeyPair(bits)` — RSA key pair generation
- `NewCredentialStore()` — constructor with `Add`, `Has`, `MarkVisited`, `IsVisited`, `All`, `Len`
- `NewHarvester(opts)` — constructor
- `Harvester.Run(ctx) (*HarvestResult, error)` — start callback server, block until timeout/cancel
- `Harvester.Stop(ctx)` — graceful shutdown
- `Harvester.Addr()` — actual listen address (for `:0` port)
- `Harvester.Credentials()` — access credential store

## Internal Patterns

- **BFS traversal**: All targets at depth N processed before depth N+1. `credQueue` drives each depth level.
- **Per-token client caching**: `clients` map stores `gitlabx.Client` per token hash, reused across depth levels.
- **OpenSSL-compatible crypto**: AES-256-CBC with PBKDF2 (SHA256, 10000 iterations, `Salted__` prefix). RSA PKCS1v15 for key wrapping. Matches `openssl enc -aes-256-cbc -pbkdf2` and `openssl rsautl -encrypt -pkcs`.
- **Token extraction dual strategy**: Name-based (GITLAB_TOKEN, *_PAT, etc.) + value-prefix (glpat-, gldt-, glcbt-, glrt-). Deduped by token value hash.
- **All attacks → secrets exfil**: Regardless of finding type, pivot always uses HTTP exfil to harvest tokens.
- **Immutable credential store**: `Add` is no-op for known hashes. Visit tracking prevents re-scanning same (token, project) pair.
- **Base64 env dump decoding**: Callbacks contain base64-encoded `printenv` output. Tries StdEncoding first, falls back to RawStdEncoding.
- **Token extraction reuse**: Uses same `ExtractTokens()` and `ValidateToken()` from credential.go

## Testing

- `credential_test.go` — 15+ table-driven extraction tests, token classification, validation mock (httptest), credential store operations
- `callback_test.go` — unencrypted roundtrip, encrypted roundtrip with real openssl, receive timeout, malformed input handling
- `orchestrator_test.go` — dry-run with mock GitLab, exploitable filtering with analyze.Finding fixtures, split tags, progress callbacks, stats accessors
- `harvest_test.go` — parseEnvDump (valid/invalid base64), full harvester HTTP roundtrip with token extraction, method-not-allowed rejection

## Dependencies

**Imports:**
- `pkg/gitlabx` — client creation and API calls
- `pkg/enumerate` — `EnumerateProjects()` for project scanning
- `pkg/enumerate/report` — `IsExploitable()`, `ResolveTags()` for target filtering
- `pkg/attack` — `NewAttacker`, `NewSecretsAttack`, `RunExfil()` for secrets exfil, `DeleteBranch` for cleanup
- `golang.org/x/crypto/pbkdf2` — OpenSSL-compatible AES key derivation

**Depended on by:**
- `cmd/pivot.go` — CLI command
- `pkg/mcp/tools_pivot.go` — MCP tool

## Gotchas

1. **Protected variables not exfiltrated** — pivot creates non-protected branches, so protected CI variables won't be injected
2. **External URL must be routable** from CI runners — use tunneling (ngrok) if runners are network-isolated
3. **5-minute receive timeout per target** — if runner is busy, callback may arrive late and be missed
4. **CI_JOB_TOKEN skipped for re-pivoting** — identified but not used for further enumeration (short-lived, limited scope)
5. **Token values never persisted** — only SHA256 hashes stored in SQLite via pkg/store
6. **RSA keys ephemeral by default** — generated per session, discarded after. Use `--rsa-key` for persistence
7. **OpenSSL 3.x default iterations** — PBKDF2 uses 10000 iterations (OpenSSL 3.x default), older versions may use different counts
8. **Single pipeline per target** — attacks one exploitable finding per project (first match), deduped by project ID
9. **Harvester blocks on Run()** — caller must use goroutine for concurrent work
10. **`:0` port for tests** — use `Harvester.Addr()` to get actual address after server starts
