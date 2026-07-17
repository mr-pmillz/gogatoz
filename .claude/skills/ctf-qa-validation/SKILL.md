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

Enumerate takes project identifiers via `--input` (file or `-` for stdin), not `--project`.
Use a project that has a `.gitlab-ci.yml` — `root/vuln` may not have one, use `root/vuln-lotp-npm` or similar.

```bash
echo "root/vuln-lotp-npm" | ./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --input - --follow-includes --format json 2>/dev/null | jq '.[0].findings | length'
```

Expected: findings count > 0. The JSON output is an array of result objects.

### 2d. Parse smoke test

Parse is a subcommand (`parse dedup`), not a direct pipe target.

```bash
./gogatoz search --gitlab-url $GL --token $BOT --query vuln --format jsonl 2>/dev/null | \
  ./gogatoz parse dedup --format json 2>/dev/null | jq length
```

Expected: a count of deduplicated projects.

### 2e. Output format verification

```bash
# SARIF
echo "root/vuln-lotp-npm" | ./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --input - --format sarif 2>/dev/null | jq '.runs[0].results | length'

# GLSAST
echo "root/vuln-lotp-npm" | ./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --input - --format glsast 2>/dev/null | jq '.vulnerabilities | length'
```

Expected: both produce valid JSON with non-zero results.

## Phase 3: Feature Validation (run when specific features changed)

These tests exercise attack, pivot, and advanced features against the CTF lab. Each section maps to a CTF track so you can test the exact feature that changed. Read credentials from `setup-lab.sh` and export them before running.

### 3a. Secrets Exfiltration (attack --secrets)

Tests the secrets exfil pipeline: CI generation, artifact collection, decryption. Requires a token with `write_repository` scope (e.g., `CTF_DEPLOY_SVC_PAT`). The `--target` flag takes project path or ID.

```bash
./gogatoz attack --gitlab-url $GL --token $DEPLOY \
  --target root/vuln-lotp-npm --secrets --method artifact \
  --branch gogatoz-qa-test
```

Verify: command produces exfiltrated variables JSON. Cleanup after:
```bash
./gogatoz attack --gitlab-url $GL --token $DEPLOY \
  --target root/vuln-lotp-npm --cleanup --branch gogatoz-qa-test
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

**Expansion track payloads** (Flags 35-47) — test all 13:

```bash
for p in remote-include-cache workflow-vars spec-inputs rules-bypass interruptible \
         oidc-federation artifact-reports image-poison parallel-matrix \
         pre-get-sources cache-key-poison trigger-artifact needs-project; do
  if ./gogatoz attack --payload-only --payload "$p" 2>/dev/null | head -1 | grep -qE '(stages:|include:|workflow:)'; then
    echo "  $p: OK"
  else
    echo "  $p: FAIL"
  fi
done
```

Verify: all 13 produce valid YAML.

### 3c. Discover Tags (attack --discover-tags)

```bash
./gogatoz attack --gitlab-url $GL --token $BOT --target root/vuln --discover-tags
```

Verify: lists runner tags (e.g., `shell_executor`).

### 3d. Pivot Dry Run (pivot command)

Tests lateral movement planning without executing attacks. Uses `CTF_CICD_BOT_PAT`. The flag is `-t`/`--target` (repeatable), and `--external-url` (not `--webhook`).

```bash
./gogatoz pivot --gitlab-url $GL --token $BOT \
  -t root/ctf-pivot-gateway \
  --listen :9443 --external-url http://127.0.0.1:9443 \
  --max-depth 1 --dry-run
```

Verify: dry-run outputs exploitable target count and stats table without executing attacks.

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

BloodHound export takes a JSONL file as input (not a project flag). Generate enumerate output first, then export.

```bash
echo "root/vuln-lotp-npm" | ./gogatoz enumerate --gitlab-url $GL --token $BOT \
  --input - --format jsonl 2>/dev/null > /tmp/gogatoz-qa-enum.jsonl

./gogatoz bloodhound export --input /tmp/gogatoz-qa-enum.jsonl \
  --output /tmp/gogatoz-qa-bh.zip && \
  unzip -l /tmp/gogatoz-qa-bh.zip
rm -f /tmp/gogatoz-qa-bh.zip /tmp/gogatoz-qa-enum.jsonl
```

Verify: ZIP contains OpenGraph JSON file with nodes and edges.

### 3i. Explain Command

```bash
./gogatoz explain VARIABLE_INJECTION 2>/dev/null | head -10
./gogatoz explain SELF_HOSTED_EXPOSED 2>/dev/null | head -10
```

Verify: returns finding description, severity, and remediation guidance.

## Phase 4: Cleanup (always run after Phase 3)

Any Phase 3 test that writes to GitLab (e.g., `--secrets`, `--commit-ci`) leaves artifacts behind — branches, CI files, pipelines, and job traces. Clean these up so the lab stays pristine for the next QA run.

Cleanup requires a token with `write_repository` scope (e.g., `CTF_ADMIN_BACKUP_PAT`). Read it from `setup-lab.sh`.

### Cleanup flags

| Flag | What it removes |
|------|-----------------|
| `--cleanup` | Required mode flag — enables cleanup mode |
| `--cleanup-ci` | Deletes `.gitlab-ci.yml` from the attack branch |
| `--cleanup-jobs` | Erases job traces on recent pipelines |
| `--cleanup-jobs-ref <ref>` | Limits job trace erasure to pipelines on this branch |
| `--cleanup-jobs-max <n>` | Max pipelines to erase (default 5) |
| `--cleanup-jobs-delete` | Also delete pipelines after erasing traces |
| `--cleanup-pipeline <id>` | Delete a specific pipeline by ID |
| `--cleanup-branch <name>` | Delete a branch from the target project |

### Correct cleanup order

Run cleanup steps in this order — CI file deletion must happen before branch deletion, because the file must be on an existing branch to be removed.

```bash
# 1. Remove the CI file from the attack branch
./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target <project> --cleanup --cleanup-ci \
  --branch <attack-branch>

# 2. Erase job traces (optional, anti-forensics)
./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target <project> --cleanup --cleanup-jobs \
  --cleanup-jobs-ref <attack-branch> --cleanup-jobs-max 5

# 3. Delete specific pipeline(s) if you captured the ID
./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target <project> --cleanup --cleanup-pipeline <pipeline-id>

# 4. Delete the attack branch (last — CI file must be gone first)
./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target <project> --cleanup --cleanup-branch <attack-branch>
```

### QA cleanup example

After running the secrets exfil test (3a) with branch `gogatoz-qa-test`:

```bash
./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target root/vuln-lotp-npm --cleanup --cleanup-ci \
  --branch gogatoz-qa-test

./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target root/vuln-lotp-npm --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-qa-test

./gogatoz attack --gitlab-url $GL --token $ADMIN \
  --target root/vuln-lotp-npm --cleanup \
  --cleanup-branch gogatoz-qa-test
```

Verify: each step prints `SUCCESS`. Confirm the branch is gone:
```bash
curl -sf -H "PRIVATE-TOKEN: $ADMIN" \
  "$GL/api/v4/projects/<project-encoded>/repository/branches/gogatoz-qa-test" | jq '.name // empty'
```
Expected: empty output (branch deleted).

### Lab state check

After all cleanup, verify no gogatoz branches remain across CTF projects:

```bash
for proj in root/vuln-lotp-npm root/vuln-var-inject root/ctf-pivot-gateway; do
  encoded=$(echo "$proj" | sed 's|/|%2F|g')
  branches=$(curl -sf -H "PRIVATE-TOKEN: $ADMIN" \
    "$GL/api/v4/projects/$encoded/repository/branches" | \
    jq -r '.[].name' | grep -E "gogatoz-" || true)
  if [ -n "$branches" ]; then
    echo "LEFTOVER in $proj: $branches"
  fi
done
echo "Lab cleanup verification complete"
```

## Phase 5: Flag Submission Validation (run when flags or flagserver change)

Validates that captured flags can be submitted to the CTF platform and accepted.

### 5a. Flagserver API Reference

The flagserver runs at `http://127.0.0.1:31337` (host port 31337 → container port 8080).

**Endpoints:**
- `POST /api/auth/register` — `{"name":"<team>","password":"<8+ chars>"}` → `{"team":{...},"token":"<JWT>"}`
- `POST /api/auth/login` — same body → `{"token":"<JWT>"}`
- `POST /api/submit` — `{"flag":"FLAG+...+"}` + `Authorization: Bearer <JWT>` → `{"correct":true/false,"flag_name":"..."}`
- `GET /api/scoreboard` — `Authorization: Bearer <JWT>` → `{"teams":[...],"total_flags":N}`

**Field names:** `name` and `password` (NOT `team_name`). Flag field: `flag` (NOT `value`).

### 5b. Register/Login and Submit Flags

```bash
FLAGSERVER="http://127.0.0.1:31337"

# Register (or login if team exists)
REG=$(curl -sf -X POST "$FLAGSERVER/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"qa-team","password":"qa-password-2026!"}')
JWT=$(echo "$REG" | jq -r '.token')

if [ -z "$JWT" ] || [ "$JWT" = "null" ]; then
  JWT=$(curl -sf -X POST "$FLAGSERVER/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"name":"qa-team","password":"qa-password-2026!"}' | jq -r '.token')
fi

# Submit a flag
curl -sf -X POST "$FLAGSERVER/api/submit" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{"flag":"FLAG+value_here+"}'
```

### 5c. Rate Limiting

The flagserver enforces per-team (10/min) and per-IP (120/min submissions, 30/min team creation) rate limits. When submitting multiple flags in batch, add `sleep 2` between submissions to avoid hitting the limit. Empty responses indicate rate limiting — wait 15-30 seconds and retry.

### 5d. Flagserver .env Sync

If setup-lab.sh's `generate_flagserver_env()` has been updated but the running container still has old flags, sync manually:

```bash
cd ~/projects/gogatoz-ctf
# Extract base64 from setup-lab.sh and update .env
python3 -c "
import re
with open('setup-lab.sh') as f:
    content = f.read()
parts = re.findall(r'flags_b64\+?=\"([^\"]+)\"', content)
b64 = ''.join(parts)
with open('flagserver/.env') as f:
    lines = f.readlines()
with open('flagserver/.env', 'w') as f:
    for line in lines:
        if line.startswith('CTF_FLAGS_B64='):
            f.write(f'CTF_FLAGS_B64={b64}\n')
        else:
            f.write(line)
"

# Force-recreate (restart alone does NOT reload .env)
docker compose up -d flagserver --force-recreate
sleep 3

# Verify flag count
docker compose exec flagserver sh -c 'echo $CTF_FLAGS_B64' | \
  base64 -d 2>/dev/null | python3 -c "import json,sys; f=json.load(sys.stdin); print(f'flags: {len(f)}')"
```

### 5e. Expansion Track Payload Names

All 13 expansion payloads (Flags 35-47) for `--payload-only` and `--commit-ci --payload`:

| Payload Name | Flag | Technique |
|-------------|------|-----------|
| `remote-include-cache` | 35 | Remote include cache poisoning |
| `workflow-vars` | 36 | workflow:rules:variables injection |
| `spec-inputs` | 37 | spec:inputs interpolation injection |
| `rules-bypass` | 38 | rules:changes/exists security scan evasion |
| `interruptible` | 39 | interruptible race condition exploit |
| `oidc-federation` | 40 | OIDC id_tokens cloud credential exchange |
| `artifact-reports` | 41 | Artifact report SARIF spoofing |
| `image-poison` | 42 | Image/service container command hijack |
| `parallel-matrix` | 43 | parallel:matrix credential path sweep |
| `pre-get-sources` | 44 | pre_get_sources_script hook injection |
| `cache-key-poison` | 45 | cache:key:prefix shared cache poisoning |
| `trigger-artifact` | 46 | trigger:include:artifact child pipeline |
| `needs-project` | 47 | needs:project cross-project artifact injection |

## Pass/Fail Criteria

| Phase | Pass Condition |
|-------|---------------|
| Phase 1 | Zero build errors, zero test failures, zero lint issues |
| Phase 2 | All smoke commands return expected output, no panics |
| Phase 3 | Each tested feature produces expected output per section |
| Phase 4 | All cleanup steps return SUCCESS, no leftover gogatoz branches |
| Phase 5 | All flags accepted by flagserver, scoreboard shows correct total |

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
