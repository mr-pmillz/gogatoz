---
name: ctf-qa-validation
description: QA testing and validation of GoGatoZ features against the CTF lab environment. Invoke this skill whenever testing gogatoz after code changes, validating CTF flags work, verifying lab infrastructure, running smoke tests, checking enumerate/attack/search/pivot/notify commands, or confirming a refactor didn't break anything. Even a "does it still work?" question should trigger this skill.
---

# GoGatoZ CTF QA Validation

This skill validates GoGatoZ against the local CTF lab. It works in three tiers — run the tier that matches the scope of what changed. When in doubt, start with Phase 1 and escalate if it passes.

## Credential Lookup

Never hardcode credentials. Before running any Phase 2+ commands, read the CTF lab setup script to extract the PAT values you need:

```
~/projects/gogatoz-ctf/setup-lab.sh
```

Search for these variables:
- `CTF_CICD_BOT_PAT` — cicd-bot user (api, read_repository)
- `CTF_DEPLOY_SVC_PAT` — deploy-svc user (api, read/write_repository)
- `CTF_ADMIN_BACKUP_PAT` — admin-backup user (api, read_user, read/write_repository)
- `CTF_PIVOT_SVC_PAT` — pivot-svc user (api, read/write_repository)
- `PAT_VALUE` — root admin PAT
- `CTF_INTERNAL_SVC_PAT` — internal GitLab service token
- `GITLAB_URL` — main GitLab URL (default: `http://gitlab.local:8929`)
- `INTERNAL_GITLAB_URL` — network-isolated GitLab URL
- SOCKS5 proxy credentials: search for `SOCKS5_NOAUTH_ADDR`, `proxyuser`, and proxy password

Export the values you need as shell variables (e.g., `GL`, `BOT`, `DEPLOY`, `ADMIN`) before running test commands.

## Phase 1: Build Verification (always run first)

Build the binary and run the test suite. Every QA session starts here — if this fails, nothing else matters.

```bash
cd ~/projects/gogatoz
go build -o gogatoz .
go test -race ./...
golangci-lint run -c .golangci-lint.yml ./...
```

All three must pass before proceeding. If tests fail, fix them first.

## Phase 2: Lab Smoke Test (run after any code change)

Verify the lab is running and gogatoz can talk to it. These are fast, non-destructive checks.

### 2a. Lab health

```bash
curl -sf $GL/users/sign_in > /dev/null && echo "GitLab: OK" || echo "GitLab: DOWN"
curl -sf http://localhost:31337/healthz && echo "Flagserver: OK" || echo "Flagserver: DOWN"
```

If GitLab is down: `cd ~/projects/gogatoz-ctf && docker compose up -d` then wait ~2 minutes for boot.
If flagserver is down: check `docker compose ps` for the flagserver container.

### 2b. Search smoke test

```bash
./gogatoz search --gitlab-url $GL --token $BOT --query vuln --format json 2>/dev/null | jq length
```

Expected: a non-zero number of projects returned.

### 2c. Enumerate smoke test

```bash
./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --project root/vuln --follow-includes --format json 2>/dev/null | jq '.findings | length'
```

Expected: findings count > 0.

### 2d. Parse smoke test

```bash
./gogatoz search --gitlab-url $GL --token $BOT --query vuln --format jsonl 2>/dev/null | \
  ./gogatoz parse --format json 2>/dev/null | jq '.total_projects'
```

Expected: a count of deduplicated projects.

### 2e. Output format verification

```bash
# SARIF
./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --project root/vuln --format sarif 2>/dev/null | jq '.runs[0].results | length'

# GLSAST
./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --project root/vuln --format glsast 2>/dev/null | jq '.vulnerabilities | length'
```

Expected: both produce valid JSON with non-zero results.

## Phase 3: Feature Validation (run when specific features changed)

These tests exercise attack, pivot, and advanced features against the CTF lab. Each section maps to a CTF track so you can test the exact feature that changed. Read credentials from `setup-lab.sh` and export them before running.

### 3a. Secrets Exfiltration (attack --secrets)

Tests the secrets exfil pipeline: CI generation, artifact collection, decryption. Requires a token with `write_repository` scope (e.g., `CTF_DEPLOY_SVC_PAT`).

```bash
./gogatoz attack --gitlab-url $GL --token $DEPLOY \
  --target root/vuln --secrets --method artifact \
  --branch gogatoz-qa-test
```

Verify: command produces exfiltrated variables JSON. Cleanup after:
```bash
./gogatoz attack --gitlab-url $GL --token $DEPLOY \
  --target root/vuln --cleanup --branch gogatoz-qa-test
```

### 3b. Payload Generation (attack --payload-only)

Tests payload generators without touching GitLab — safe and fast.

```bash
./gogatoz attack --payload-only --payload secrets 2>/dev/null | head -5
./gogatoz attack --payload-only --payload ror-shell 2>/dev/null | head -5
./gogatoz attack --payload-only --payload cache-poison 2>/dev/null | head -5
./gogatoz attack --payload-only --payload git-hook 2>/dev/null | head -5
```

Verify: each produces valid YAML starting with `stages:`.

### 3c. Discover Tags (attack --discover-tags)

```bash
./gogatoz attack --gitlab-url $GL --token $BOT --target root/vuln --discover-tags
```

Verify: lists runner tags (e.g., `shell_executor`).

### 3d. Pivot Dry Run (pivot command)

Tests lateral movement planning without executing attacks. Uses `CTF_CICD_BOT_PAT`.

```bash
./gogatoz pivot --gitlab-url $GL --token $BOT \
  --targets root/ctf-pivot-gateway \
  --listen :9443 --webhook http://$(hostname -I | awk '{print $1}'):9443 \
  --max-depth 1 --dry-run
```

Verify: dry-run outputs exploitable target count and planned attacks without executing.

### 3e. SOCKS5 Proxy (search/enumerate through proxy)

Read SOCKS5 proxy address and credentials from `setup-lab.sh`.

```bash
# No-auth proxy
./gogatoz search --gitlab-url $GL --token $BOT \
  --socks5-proxy localhost:1080 --query vuln --format json 2>/dev/null | jq length

# Authenticated proxy (read user/pass from setup-lab.sh)
./gogatoz search --gitlab-url $GL --token $BOT \
  --socks5-proxy localhost:1081 \
  --socks5-user $PROXY_USER --socks5-pass $PROXY_PASS \
  --query vuln --format json 2>/dev/null | jq length
```

Verify: both return the same non-zero project count.

### 3f. API Server

```bash
./gogatoz api-server --listen :18088 --api-key test-qa-key &
API_PID=$!
sleep 1

# Healthz (no auth required)
curl -sf http://localhost:18088/healthz | jq .ok

# Unauthenticated — should return 401
curl -sf -o /dev/null -w "%{http_code}" http://localhost:18088/auth/validate

# Authenticated
curl -sf -X POST http://localhost:18088/auth/validate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-qa-key" \
  -d "{\"token\":\"$BOT\",\"gitlab_url\":\"$GL\"}" | jq .ok

kill $API_PID 2>/dev/null
```

Verify: healthz=true, unauthenticated=401, authenticated=true.

### 3g. Notify (dry-run)

```bash
./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --project root/vuln --format jsonl 2>/dev/null | \
  ./gogatoz notify --dry-run --discord-webhook http://example.com/webhook 2>&1 | head -20
```

Verify: formats findings as Discord embeds without sending.

### 3h. BloodHound Export

```bash
./gogatoz bloodhound export --gitlab-url $GL --token $BOT \
  --project root/vuln --output /tmp/gogatoz-qa-bh.zip 2>/dev/null && \
  unzip -l /tmp/gogatoz-qa-bh.zip
rm -f /tmp/gogatoz-qa-bh.zip
```

Verify: ZIP contains OpenGraph JSON files.

### 3i. Explain Command

```bash
./gogatoz explain VARIABLE_INJECTION 2>/dev/null | head -10
./gogatoz explain SELF_HOSTED_EXPOSED 2>/dev/null | head -10
```

Verify: returns finding description, severity, and remediation guidance.

## Pass/Fail Criteria

| Phase | Pass Condition |
|-------|---------------|
| Phase 1 | Zero build errors, zero test failures, zero lint issues |
| Phase 2 | All smoke commands return expected output, no panics |
| Phase 3 | Each tested feature produces expected output per section |

Flag values in the CTF always use `FLAG+...+` format (never `FLAG{...}`) because GitLab cannot mask variables containing curly braces.

## Reference Paths

| Resource | Path |
|----------|------|
| GoGatoZ source | `~/projects/gogatoz` |
| CTF lab | `~/projects/gogatoz-ctf` |
| Lab setup script | `~/projects/gogatoz-ctf/setup-lab.sh` |
| Course docs | `~/projects/hackers-guide-to-cicd` |
| Lab walkthroughs | `~/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/` |
| Flag definitions | `~/projects/gogatoz-ctf/setup-lab.sh` (search for `CTF_FLAGS_B64`) |
