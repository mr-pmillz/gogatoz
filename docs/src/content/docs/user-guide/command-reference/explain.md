---
title: Explain Command
description: Look up finding codes and remediation guidance
---

The explain command displays detailed information about a GoGatoZ finding code, including severity, description, exploitation technique, remediation guidance, and documentation link. Use it to understand findings produced by the enumerate command.

## Basic Usage

```bash
gogatoz explain [finding-code] [options]
```

No authentication is required. This command works entirely offline.

## Options

- `--list`    List all available finding codes with severities
- `--all`     Show full details for every finding code
- `--json`    Output as JSON instead of text

## Examples

### Look up a specific finding

```bash
gogatoz explain PLAINTEXT_SECRET
```

### Look up findings after enumerate

```bash
# Enumerate a project
gogatoz enumerate -i <(echo root/my-project) --json | jq '.findings[].id'

# Understand what each finding means
gogatoz explain SELF_HOSTED_EXPOSED
gogatoz explain MR_TRIGGERED_JOB
gogatoz explain LOTP_TOOL_EXEC
```

### List all finding codes

```bash
gogatoz explain --list
```

### Full reference dump

```bash
# All findings with details
gogatoz explain --all

# As JSON for tooling
gogatoz explain --all --json > finding-reference.json
```

### JSON output for a single finding

```bash
gogatoz explain SELF_HOSTED_EXPOSED --json
```

## Finding Categories

GoGatoZ detects 35 finding types across these categories:

**CI/CD Configuration:**
- PLAINTEXT_SECRET, INCLUDE_RISK, WORKFLOW_BROAD_RULES, DEBUG_TRACE_ENABLED

**Runner Security:**
- SELF_HOSTED_EXPOSED, MR_TRIGGERED_JOB, PRIVILEGED_RUNNER_RISK, DIND_DETECTED, DIND_INSECURE

**Supply Chain:**
- SCRIPT_INJECTION, CACHE_KEY_INJECTION, TRIGGER_CHAIN_RISK, LOTP_TOOL_EXEC, IMAGE_MUTABLE_TAG, IMAGE_NOT_PINNED, UNPINNED_PACKAGE_INSTALL, UNVERIFIED_SCRIPT_EXEC, RISKY_REMOTE_SCRIPT

**Secrets and Tokens:**
- VARIABLE_INJECTION, ARTIFACT_POISONING, OIDC_TOKEN_MR_RISK, FORK_MR_RISK, FORK_SCRIPT_EXEC

**Advanced:**
- SCRIPT_OBFUSCATION, SECURITY_JOB_WEAKENED, ARTIFACTS_NO_EXPIRE, JOB_HARDCODED

## Notes

- The explain command is purely informational and makes no API calls.
- Finding details include the MITRE ATT&CK technique mapping where applicable.
- Use `gogatoz explain --list` to get a quick cheat sheet of all codes and severities during an engagement.
