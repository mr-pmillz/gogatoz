# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoGatoZ is a Go port of Gato-X, adapted for GitLab CI/CD. It's a security scanning and attack toolkit with four operational modes: **search** (discover GitLab projects), **enumerate** (scan CI/CD configs for vulnerabilities), **attack** (exploit misconfigurations), and **parse** (transform output locally without GitLab access). Module path: `github.com/mr-pmillz/gogatoz`.

## Build & Development Commands

Go version: 1.24.4 (per go.mod).

```bash
go build -o gogatoz .              # Build the CLI
make help                           # Show all available targets
make test                           # Run unit tests with coverage
make test-race                      # Run tests with race detector
make test-e2e                       # Run E2E tests against live GitLab
make lint                           # Run golangci-lint (config: .golangci-lint.yml)
make fmt                            # Format code
make vet                            # Run go vet
make ci                             # Full local CI: fmt, vet, lint, test
make cover-html                     # Generate HTML coverage report
make cover                          # Run tests with coverage and show summary
make bench                          # Run benchmarks with memory stats
make tidy                           # Ensure go.mod/go.sum are tidy
make tools                          # Install tparse and golangci-lint
make docs-cmd                       # Generate CLI command docs
go test -run TestName ./pkg/package/...  # Run a single test
```

### Continuous Integration & Release

The project uses GitHub Actions (workflows in `.github/workflows/`) and follows a **gitflow** branching model. The old `.gitlab-ci.yml` pipeline has been removed.

**Branch model:** `main` (production, tagged releases) ← `develop` (integration) ← `feature/*`, `fix/*` (daily work). Releases cut via `release/vX.Y.Z` branches; urgent fixes via `hotfix/vX.Y.Z`. Version lives in the branch name — no version constant to bump.

- **`branch-policy.yml`** — validates every PR: only `develop`, `release/*`, or `hotfix/*` may target `main`; feature/fix branches must target `develop`.
- **`ci.yml`** — runs on pushes to `main`, `develop`, `release/**`, `hotfix/**` and PRs targeting `main` or `develop`: a `build` job, a `lint` job (`golangci-lint run -c .golangci-lint.yml ./...`, golangci-lint v2 via golangci-lint-action@v9), and a `test` job (`gotestsum` race+coverage, coverage summary to the job summary, HTML/JSON coverage artifacts, `dorny/test-reporter`). Go version is read from `go.mod` via `setup-go` (`go-version-file: go.mod`).
- **`tag-release.yml`** — fires when a `release/*` or `hotfix/*` PR is merged into `main`: extracts semver from the branch name, creates an annotated `vX.Y.Z` tag, and pushes it via a GitHub App token (so the push re-triggers `release.yml`). Requires secrets `GOGATOZ_APP_ID` and `GOGATOZ_APP_PRIVATE_KEY`.
- **`release.yml`** — runs on `v*` tags: git-cliff generates `RELEASE_CHANGELOG.md`, then goreleaser publishes cross-platform binaries + a source archive + a GitHub Release and pushes multi-arch (amd64/arm64) container images to GHCR (`ghcr.io/mr-pmillz/gogatoz`) via `dockers_v2` (QEMU + buildx). `actions/attest-build-provenance` attests both `checksums.txt` and `digests.txt`. A follow-up `changelog` job regenerates `CHANGELOG.md` and commits it to `main` via the GitHub App token.
- **`docs.yml`** — builds the Astro Starlight docs (`npm ci` + `astro build`) and deploys to the repository's GitHub Pages site (root-served at the assigned `*.pages.github.io` URL; no `base` subpath).

GitHub Actions are **SHA-pinned** with `# ratchet:owner/action@vX` trailer comments. When changing an action version, re-pin with `ratchet pin .github/workflows/*.yml` (then `ratchet lint`); validate with `actionlint`.

Release builds inject version metadata via goreleaser ldflags into `github.com/mr-pmillz/gogatoz/cmd.{version,commit,date}` (defaults `dev`/`none`/`unknown` for plain `go build`; `go install ...@vX` recovers the version from module build info). The CLI `version` subcommand prints all three.

Pre-release repo settings: enable Pages (Settings → Pages → Source: GitHub Actions); after the first release, set the GHCR package public/linked for unauthenticated pulls.

Tool distribution targets GitHub only (`github.com/mr-pmillz/gogatoz`, GHCR, GitHub Releases, GitHub Pages). This is distinct from the GitLab CI/CD that GoGatoZ *scans and attacks* — all GitLab-target behavior, env vars (`GITLAB_TOKEN`/`GITLAB_URL`), and the E2E `gitlab.local` instance are unchanged.

## Architecture

### Package Layout

- **`cmd/`** — Cobra CLI commands (root, search, enumerate, attack, pivot, parse, api, report, notify). Global flags and Viper config binding in `root.go`. Shared pterm UI helpers in `ui.go`. The `parse` command overrides `PersistentPreRunE` to skip token/config init.
- **`pkg/gitlabx/`** — GitLab API client wrapper with token-bucket rate limiting, exponential backoff retry (429/5xx), configurable TLS, and HTTP connection pooling.
- **`pkg/pipeline/`** — `.gitlab-ci.yml` parser. Handles YAML parsing (`parser.go`), recursive include resolution for all 5 types — local, project, remote, template, component (`resolve.go`), and job merging with extends/anchors (`merge.go`). Tracks provenance of each job origin.
- **`pkg/analyze/`** — Vulnerability analysis engine. Multi-pass rule evaluation covering 26 finding IDs: include risks, runner exposure, MR-triggered jobs on self-hosted runners, variable injection, artifact poisoning, plaintext secrets, fork MR risks, workflow broad rules, supply chain (script injection, self-merge, cache poisoning), dispatch/TOCTOU, Pwn Request deployments, AI prompt injection, LOTP tool execution (`LOTP_TOOL_EXEC`), cache key injection (`CACHE_KEY_INJECTION`), GitLab OIDC token exposure (`OIDC_TOKEN_MR_RISK`), and downstream trigger chain abuse (`TRIGGER_CHAIN_RISK`). All script analysis uses `effectiveScripts()` to cover before_script/after_script phases. LOTP catalog in `lotp.go` covers 60+ tools from https://boostsecurityio.github.io/lotp/
- **`pkg/enumerate/`** — Concurrent project scanner using a worker pool pattern. Expands groups to projects, resolves CI configs, runs analyzer, discovers runners and protected branches. Streams results via callback.
- **`pkg/attack/`** — Exploitation modules: CI pipeline injection (`pushci.go`), secrets exfiltration with RSA encryption (`secrets.go`), persistence mechanisms (`persistence.go`), runner-on-runner targeting (`ror/`), and cleanup operations (`c2/`). Payload templates in `payloads/`.
- **`pkg/graph/`** — DAG builder for CI/CD job dependencies. Converts parsed pipeline documents into directed graphs with topological sort (Kahn's algorithm), tag indexing, and stage-based fallback edges.
- **`pkg/notify/`** — Notification system for shipping CI/CD analysis findings to external systems. Supports raw webhook POSTs (`Notifier`), Apprise API (`AppriseSender`), and direct Discord webhooks (`DiscordSender`) with rich embed formatting. Formats `enumerate.Result` slices into severity-colored Discord embeds or Apprise markdown via `FormatDiscordMessages()` and `FormatAppriseMarkdown()`.
- **`pkg/pathutil/`** — Glob-to-regex utility. Compiles simple glob patterns (`*`, `**`, `?`) into compiled regexps for path matching in search filters.
- **`pkg/pivot/`** — Automated lateral movement engine. BFS pivot loop: enumerate → filter exploitable → attack (secrets exfil via HTTP callback) → decrypt (RSA+AES) → extract tokens → validate → repeat with new credentials. Includes callback server, credential store, and per-token client caching.
- **`pkg/store/`** — SQLite-backed persistence for MCP scan results using GORM. Models: `ScanSession`, `SearchResult`, `EnumerateResult`, `Finding`, `PivotSession`, `HarvestedCredential`. Auto-migrates on open, WAL mode enabled.
- **`pkg/models/`** — Shared data models (secrets, runners, repos).
- **`pkg/api/`** — HTTP API server exposing enumeration, auth, and search via JSON REST endpoints with NDJSON streaming support.
- **`e2e/`** — End-to-end tests (`//go:build e2e`) that run against a live GitLab instance. Build tag `e2e` required. Tests cover search, enumerate, attack (commit-ci, deconflict, secrets extraction, payload generation), and piped workflows.

### Data Flow

Search → discovers projects via GitLab API with filters (language, topic, path patterns, code content).
Enumerate → takes project IDs/paths from file/stdin/JSONL → expands groups → fetches repo trees → parses `.gitlab-ci.yml` with include resolution → runs analyzer → streams findings.
Parse → transforms CLI output locally (dedup by project ID, auto-detects search vs enumerate JSONL). No GitLab token required.
Attack → targets specific projects with payloads, branch deconfliction, and cleanup.
Pivot → chains enumerate → attack → harvest in a BFS loop: exfiltrates secrets via HTTP callback, extracts GitLab tokens, validates them, and uses new credentials to discover additional scope at the next depth level.
Notify → sends enumeration results to Apprise API or Discord webhooks with formatted embeds/markdown.

### Documentation Site

Astro Starlight in `docs/`. Content in `docs/src/content/docs/`, sidebar manually configured in `docs/astro.config.mjs`. Requires Node >= 18.20.8 (pin via `docs/.nvmrc`). Build: `make docs-build`. Dev: `make docs-dev`.

### Key Patterns

- **Configuration precedence**: CLI flags > environment variables > config file (`.gogatoz.yaml`) > defaults. Managed via Viper in `cmd/root.go`.
- **Dependency injection**: GitLab client passed to analysis/attack modules. Options structs for configurable behavior. Interfaces (`attackRunner`, `secretsRunner`) for testability.
- **Attack command modes**: `cmd/attack.go` requires exactly one mode flag (`--commit-ci`, `--secrets`, `--cleanup`, `--deploy-key`, `--add-member`, `--ai-inject`, `--inject-script`, `--auto-merge`, `--harvest`, `--tamper-release`, `--tamper-package`, `--tamper-tag`) unless using `--discover-tags` or `--payload-only`. Payload types: `ror-shell`, `pwn-request`, `ror`, `secrets`, `git-hook`, `cache-poison`, `infostealer`. Anti-forensics: `--cleanup-pipeline`, `--cleanup-jobs`. New attack modes require: adding a flag var, updating mode count validation, adding a handler block, and registering the flag in `init()`.
- **Concurrency**: Worker pool in enumerator with configurable concurrency, context-based cancellation, and per-project timeouts.
- **False positive filtering**: `--filter-false-positives` flag on `enumerate` and `report` commands. Marks findings with `FalsePositive: true` + `FalsePositiveReason` (never deletes). Rules engine in `pkg/analyze/falsepositive.go`. Report `Build()` skips FP findings from severity/exploitable/infrastructure counts when `FilterFalsePositives` option is set. JSON/JSONL output includes all findings with FP metadata for client-side filtering.
- **Rate limiting**: Token bucket (`golang.org/x/time/rate`) with adaptive backoff and jitter.
- **Terminal output**: PTerm (`github.com/pterm/pterm`) for styled tables, colored severity, and prefix printers (success/error/info) in text output mode. PTerm auto-strips ANSI when stdout is not a TTY. JSON/JSONL output paths are never styled. Shared helpers in `cmd/ui.go`; enumerate report rendering in `pkg/enumerate/report/pterm.go`.
- **PTerm writing pattern**: Use `Srender()` (tables/bullet lists) or `Sprint()` (section/header/prefix printers) to get a string, then `fmt.Fprintln(w, s)` to write to Cobra's writer. `Section`/`Header` printers lack `Srender()` — use `Sprint()` only. Never use `Render()` directly (writes to stdout, bypasses Cobra's writer).

## GitLab SDK Conventions

SDK: `gitlab.com/gitlab-org/api/client-go v1.34.0`. Key type rules:
- All entity IDs are `int64` (Project.ID, Runner.ID, Group.ID, User.ID, etc.)
- All pagination fields are `int64` (ListOptions.Page/PerPage, Response.NextPage/TotalPages)
- CLI flags binding to these must use `Int64Var`, not `IntVar`
- `Runner.Active` is deprecated — use `!Runner.Paused`; `Project.TagList` is deprecated — use `Topics`
- Context passing: SDK methods take `gitlab.WithContext(ctx)`, not raw `context.Context`
- Use `any` not `interface{}` for generic ID parameters (Go 1.18+)

## Design Principles

Per CONTRIBUTING.md — these guide how to write analysis rules and findings:

1. **Operator-focused**: built for security practitioners and speed of use
2. **Bias against false negatives**: prefer catching potential issues with context to triage
3. **Provide context with findings**: include evidence and rationale
4. **Performance matters**: should scan tens of thousands of projects efficiently

## Testing

### Unit Tests

Tests use embedded YAML constants for reproducible fixtures (see `*_test.go` files with test constants). Table-driven tests are preferred for analyzer rules. Mock/fake patterns exist for command testing. Coverage is tracked with atomic mode.

GitLab API mocking pattern: `httptest.NewServer` + `gitlabx.New(srv.URL, "tok")` — used in ror, org, api, attack, and enumerate tests. SDK pagination requires headers: `X-Page`, `X-Next-Page`, `X-Per-Page`, `X-Total-Pages`, `X-Total`.

### E2E Tests

Located in `e2e/` with build tag `e2e`. Run against a live GitLab instance. 58 tests covering all operational modes: search (6), enumerate (11), analyze (17), attack (19), parse (4), pipe (1).

```bash
# Via Makefile (TEST_API_PAT takes priority over GITLAB_TOKEN):
TEST_API_PAT=glpat-xxx TEST_GITLAB_URL=https://gitlab.local TEST_RUNNER_TAG=shell_executor make test-e2e

# Directly:
TEST_API_PAT=glpat-xxx TEST_GITLAB_URL=https://gitlab.local TEST_RUNNER_TAG=shell_executor \
  go test -tags e2e -v -count=1 -timeout 300s ./e2e/...
```

**Required env vars for e2e:**
- `TEST_API_PAT` — GitLab PAT with `api` scope and access to ALL `MrPMillz/vuln-*` repos (preferred; takes priority over `GITLAB_TOKEN`). Project bot tokens only have access to their parent project and cannot see the vuln lab repos.
- `GITLAB_TOKEN` — Fallback token if `TEST_API_PAT` is not set
- `TEST_GITLAB_URL` — GitLab instance URL (default: `https://gitlab.com`)
- `TEST_RUNNER_TAG` — Runner tag for jobs that must execute (default: `shell_executor`)

**E2E test structure:**
- `e2e_test.go` — `TestMain` builds the binary, shared helpers (`requireCreds`, `runGogatoz`, `runGogatozWithTimeout`, `skipOnInsufficientScope`, `waitForPipeline`, `protectBranch`, etc.)
- `search_test.go` — 6 tests: name search, path/code content search, text/JSONL output, no-results
- `enumerate_test.go` — 11 tests: findings, injection detection, follow-includes, quick/deep modes, runners, protected branches, text/JSONL output, only-findings, piped-from-search
- `analyze_test.go` — 17 tests: per-finding tests for include risks, runner exposure, MR-triggered jobs, variable injection, artifact poisoning, plaintext secrets, fork MR risks, workflow broad rules, fork script execution, AI prompt injection
- `attack_test.go` — 26+ tests: discover-tags (text/JSON), payload-only (ror-shell, pwn-request, secrets, runner-on-runner, git-hook, cache-poison), commit-ci + cleanup, deconflict (suffix/fail), secrets project-vars, secrets extraction with artifact verification, dedicated repo exfil, dedicated push-ci, dedicated ROR, ai-inject (commit+cleanup, custom config, with MR), inject-script, tamper-release, tamper-package, auto-merge, cleanup-pipeline, missing-token/target errors
- `parse_test.go` — 4 tests: search pipe dedup, duplicate removal verification, text output, JSON output
- `pipe_test.go` — 1 test: search-to-enumerate pipe

**Target projects:** `MrPMillz/vuln` (existing tests, needs CI variable `MY_SECRET`), plus 27 `MrPMillz/vuln-*` repos (17 analyze + 6 attack + 1 shared templates + 3 AI). Created by `scripts/create-vuln-labs.sh`. `vuln-attack-secrets` needs CI variable `EXFIL_SECRET` (masked, protected).

## Linting

golangci-lint v2 config in `.golangci-lint.yml`. Key enabled linters: bodyclose, dupl, errorlint, gocognit, goconst, gocritic, goprintffuncname, gosec (excluding G306), govet, ineffassign, staticcheck (with specific exclusions: S1028, QF1002, S1034, QF1001), unconvert, unused, whitespace. Exclusion presets: comments, common-false-positives, legacy, std-error-handling.
- gocognit threshold is 30 — extract helpers when functions get complex
- gosec G107 fires on `http.Post(url, ...)` with variable URLs in tests — use `//nolint:gosec` with justification

## Lab Environment

`labs/` contains a standalone docker-compose lab for students/testing:
- `docker-compose.yml` — GitLab CE + Container Registry (port 5050) + shell/docker runners + SOCKS5 proxies + network-isolated GitLab
- `setup-lab.sh` — automated post-boot setup (root PAT, runner registration via GitLab 18.0+ API, vuln repos, internal GitLab)
- Healthcheck uses `/users/sign_in` (not `/-/readiness` which returns 404 on GitLab CE)
- Runner tags: `shell_executor,system-runner` (shell), `docker,system-runner` (docker)
- SOCKS5 proxies: `socks5-noauth` (port 1080, no auth), `socks5-auth` (port 1081, proxyuser/pr0xyP4ssW0rd)
- `serjs/go-socks5-proxy:latest` defaults `REQUIRE_AUTH=true` — the `socks5-noauth` service needs explicit `REQUIRE_AUTH: "false"` env or it crash-loops
- Network-isolated GitLab: `gitlab-internal` on `lab_isolated` network, reachable only via SOCKS5 proxy
- `scripts/create-vuln-labs.sh` NAMESPACE is env-configurable: `NAMESPACE=root ./scripts/create-vuln-labs.sh`

## Environment Variables

| Variable             | Purpose                                                                |
|----------------------|------------------------------------------------------------------------|
| `GITLAB_TOKEN`       | GitLab PAT (scopes: api, read_repository; write_repository for attack) |
| `GITLAB_URL`         | GitLab instance URL (default: https://gitlab.com)                      |
| `GOGATOZ_CONFIG`     | Config file path                                                       |
| `GOGATOZ_RATE_RPS`   | Max requests/sec (default: 8)                                          |
| `GOGATOZ_RATE_BURST` | Burst size (default: 16)                                               |
| `GOGATOZ_RETRY_MAX`  | Max retries on 429/5xx (default: 3)                                    |
| `GOGATOZ_INSECURE`   | Skip TLS verification                                                  |
| `GOGATOZ_CA_CERT`    | Additional CA certificate path                                         |
| `GOGATOZ_USER_AGENT` | Custom user-agent string                                               |
| `GOGATOZ_HTTP_MAX_IDLE` | Max idle HTTP connections                                           |
| `GOGATOZ_HTTP_MAX_IDLE_PER_HOST` | Max idle connections per host                                |
| `GOGATOZ_HTTP_IDLE_TIMEOUT` | Idle connection timeout                                           |
| `GOGATOZ_HTTP_TLS_TIMEOUT` | TLS handshake timeout                                              |
| `GOGATOZ_HTTP_EXPECT_TIMEOUT` | Response header timeout                                         |
| `GOGATOZ_HTTP_REQ_TIMEOUT` | Full request timeout                                               |
| `GOGATOZ_SOCKS5_PROXY` | SOCKS5 proxy address (host:port) for routing all connections         |
| `GOGATOZ_SOCKS5_USER` | SOCKS5 proxy username (optional)                                      |
| `GOGATOZ_SOCKS5_PASS` | SOCKS5 proxy password (optional)                                      |
| `GOGATOZ_API_LISTEN` | API server listen address                                              |
| `GOGATOZ_API_BASE_URL` | API server GitLab base URL                                           |
| `GOGATOZ_DB`         | SQLite database path for result persistence (default: `~/.local/share/gogatoz/results.db`) |
| `APPRISE_URL`        | Apprise API URL for notify command (fallback for `--apprise-url`)      |
| `DISCORD_WEBHOOK`    | Discord webhook URL for notify command (fallback for `--discord-webhook`) |
| `DATABASE_URL`       | Flagserver: PostgreSQL connection URL (default: `postgres://ctf:ctf_secret@localhost:5432/ctf?sslmode=disable`) |
| `JWT_SECRET`         | Flagserver: JWT signing key (auto-generates random if unset)           |
| `TEST_API_PAT`       | E2E: GitLab token (fallback: `GITLAB_TOKEN`, `CI_JOB_TOKEN`)          |
| `TEST_GITLAB_URL`    | E2E: GitLab instance URL (default: https://gitlab.com)                 |
| `TEST_RUNNER_TAG`    | E2E: Runner tag for executable jobs (default: shell_executor)          |

## Git Conventions

Commit messages use lowercase, no trailing period (e.g., "update changelog", "fixed golang alpine image in Dockerfile").
Branch naming: `feature/description` or `fix/description` for daily work, `release/vX.Y.Z` for releases, `hotfix/vX.Y.Z` for urgent fixes. Feature/fix branches target `develop`; release/hotfix branches target `main`. See `docs/src/content/docs/contributing/release-process.md` for the full gitflow model.

## Code Review Notes

- `make ci` runs `make fmt` first, which may auto-fix whitespace in files you didn't touch — check `git diff` before committing
- Package-level CLAUDE.md files document intentional design decisions (e.g., pagination quirks, thread-safety guarantees) — consult them before flagging "bugs" in those packages

## CTF Lab Environment (labs/setup-lab.sh)

- CTF runs on local Docker GitLab (`http://gitlab.local:8929`), separate from `gitlab.local` E2E instance
- Fixed PAT values set via `token.set_token()` in Rails runner: `CTF_CICD_BOT_PAT`, `CTF_DEPLOY_SVC_PAT`, `CTF_ADMIN_BACKUP_PAT`, `CTF_OPSEC_BOT_PAT`, `CTF_PIVOT_SVC_PAT`, `CTF_PIVOT_OPS_PAT`
- 7 public decoy repos (non-vulnerable) + 2 CTF target repos + 3 supply chain CTF repos + 3 pivot CTF repos + 1 proxy recon repo + 5 LOTP repos + 6 advanced attack repos + ci-templates
- 26 flags total (9950 pts): Main Chain (7 flags, 250 pts each = 1750 pts) + Supply Chain Track (4 flags, 500 pts each = 2000 pts) + Pivot Track (3 flags, 500 pts each = 1500 pts) + Proxy Recon Track (1 flag, 500 pts) + LOTP Track (5 flags, 300-500 pts = 1800 pts) + Advanced Attack Track (6 flags, 300-500 pts = 2400 pts)
- Supply Chain Track: ctf-script-hopping (Flag 8, script injection) → ctf-cache-poison (Flag 9, cache poisoning) → ctf-auto-merge (Flag 10, self-approve + merge) + ctf-travy (Flag 15, Trivy-style tag poisoning). Entry points: cicd-bot PAT from Flag 1 (Flags 8-10), root PAT from Flag 5 (Flag 15).
- Pivot Track: ctf-pivot-gateway (Flag 11, depth 0) → ctf-pivot-middleware (Flag 12, depth 1) → ctf-pivot-crown (Flag 13, depth 2). BFS lateral movement via `gogatoz pivot` with HTTP callback exfil. Entry point: cicd-bot PAT from Flag 1.
- Proxy Recon Track: Flag 14 (500 pts). Discover internal GitLab via infra-automation CI vars → find SOCKS5 proxy creds → enumerate gitlab-internal through authenticated proxy → extract flag from root/classified-infra. Prerequisite: root PAT from Flag 5.
- LOTP Track: vuln-gyp-inject (Flag 16, 500 pts), vuln-lotp-npm (Flag 17, 300 pts), vuln-oidc-mr-risk (Flag 18, 400 pts), vuln-trigger-chain (Flag 19, 300 pts), vuln-cache-key-injection (Flag 20, 300 pts). Living off the Pipeline attacks. Entry point: cicd-bot PAT from Flag 1.
- Advanced Attack Track: ctf-ror-exposure (Flag 21, 300 pts), vuln-memory-dump (Flag 22, 300 pts), vuln-worm (Flag 23, 500 pts), vuln-escape (Flag 24, 500 pts), vuln-var-inject (Flag 25, 400 pts), vuln-c2 (Flag 26, 400 pts). Entry point: cicd-bot PAT from Flag 1.
- 6 CTF users (main GitLab): cicd-bot (Developer), deploy-svc (Maintainer), admin-backup (Admin), opsec-bot (Developer), pivot-svc (Developer), pivot-ops (Developer)
- Internal GitLab user: internal-svc (PAT: `<see-labs/setup-lab.sh>`, Developer on root/classified-infra)
- CTF PATs must be 20+ chars of mixed-case alphanumeric after `glpat-` prefix for trufflehog entropy detection (e.g., `<example-20-char-base62>`). Human-readable tokens like `glpat-cicd-bot-readonly-token` fail trufflehog's detector.
- Runner tag workaround: GitLab 18.x `POST /api/v4/user/runners` may not apply `tag_list`; `setup-lab.sh` does a follow-up `PUT /api/v4/runners/{id}` to set tags
- Rails runner shell escaping: write Ruby scripts to a local file, `docker cp` into the container, `chmod 644` the file (mktemp creates 0600, gitlab-rails runs as `git` user), then `gitlab-rails runner /tmp/script.rb` — heredocs mangle `save!` and similar Ruby methods
- GitLab masked CI variable values only allow Base64-safe characters (A-Z, a-z, 0-9, +, /, =, @, :, ., ~). Characters like `!`, `{`, `}` are rejected. This affects both flag format (`FLAG+...+` not `FLAG{...}`) and proxy passwords.
- Companion lab docs site: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/` (Astro Starlight). When adding CTF tracks: update lab9-7.md (scoring + diagram + scoreboard), gogatoz-setup.md (architecture + repos table + users), astro.config.mjs (sidebar), and cross-links in adjacent labs.
- `--no-token` flag enables unauthenticated enumerate/search on public GitLab instances

## CTF Flag Server (labs/flagserver/)

- Separate Go module (`labs/flagserver/go.mod`) — build/test with `cd labs/flagserver && go test ./...`
- Gin HTTP framework, GORM + PostgreSQL, embedded SPA frontend (Svelte 5 + Tailwind v4)
- Authentication: per-team passwords (bcrypt cost 12) + JWT (HS256, 24h expiry). Routes: `POST /api/auth/register`, `POST /api/auth/login`
- Dockerfile uses `CGO_ENABLED=0` (PostgreSQL driver is pure Go, no CGO needed)
- Tests use in-memory SQLite via `OpenTestStore(t)` in `store_test.go` (fast, no Docker needed)
- Flags stored as SHA256 hashes — `config.go`/`handlers.go` are format-agnostic (no flag format strings)
- Flag submission endpoint: `POST /api/submit` (not `/api/flags/submit`)
- Flag values use `FLAG+contents+` format (not `FLAG{...}`) because GitLab cannot mask variables containing `{`/`}`; defined in `setup-lab.sh`, encoded as base64 JSON in `CTF_FLAGS_B64`
- Protected CI variables (`protected: true`) restrict injection to protected branches — the actual security boundary. Masked (`masked: true`) only hides from job logs, completely bypassed by artifact-based exfiltration.
- When changing flag values: update `setup-lab.sh` (plain + base64 blob), `.env.example`, `handlers_test.go`, `e2e/attack_test.go`, `scripts/create-vuln-labs.sh`
- Rate limiting: per-team (`golang.org/x/time/rate`, 10/min) + per-IP (30/min team creation, 120/min submissions) for classroom-safe abuse prevention
- Svelte curly brace gotcha: `placeholder="FLAG{...}"` breaks parser — use `placeholder={"FLAG{...}"}` instead
- Docker build: `npm ci --ignore-scripts && node node_modules/esbuild/install.js` to avoid ETXTBSY race
- Port mapping: host 31337 → container 8080 (`docker-compose.yml`); internal code always uses 8080
- Frontend hardcoded values (update when adding flags): `+page.svelte` (home: bounty count, gold total, chain count), `+layout.svelte` (footer: bounty count, pts total), `submit/+page.svelte` (default `total`), `ProgressBar.svelte` (default `total`). Backend counts are dynamic via `len(h.cfg.Flags)`.

## Legacy

The `gatox/` directory contains the original Python reference implementation being phased out. New work should be in Go only.

`.claudeignore` excludes the legacy `gatox/` dir, build artifacts, and coverage output from Claude's context.
