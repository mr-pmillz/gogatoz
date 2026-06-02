---
title: Scanning for Vulnerabilities
description: How to use GoGatoZ to find and analyze GitLab projects for CI/CD risks
---

This guide explains how to use GoGatoZ to find and analyze GitLab projects for CI/CD risks.

## Overview

GoGatoZ scanning typically involves two steps:

1. Search: discover candidate projects via GitLab APIs
2. Enumerate: analyze `.gitlab-ci.yml` and includes for misconfigurations

## Step 1: Search for candidate projects

```bash
# Simple search with JSON output
./gogatoz search -q "runner" --per-page 50 --max-pages 2 --json

# Projects containing a .gitlab-ci.yml
./gogatoz search -q "ci" --path-pattern ".gitlab-ci.yml" --json

# Filter by repository content (scope=blobs)
./gogatoz search -q "runner" --code-content "tags: self-hosted" --code-per-page 10 --json
```

You can also filter by language/topic and use `--gitlab-url` to target a self-hosted instance (see README for TLS flags).

## Step 2: Enumerate for vulnerabilities

```bash
./gogatoz enumerate -i projects.txt -c 16 --timeout 20s --json
```

- Input accepts path-with-namespace (group/project) or numeric IDs (one per line)
- Use `--follow-includes` and `--include-depth` to enable transitive include analysis

## Performance tips

- Tune API usage with `--rate-rps`, `--rate-burst`, `--retry-max`
- Increase concurrency with `--concurrency`, monitor for 429 responses
- Use JSONL for streaming pipelines: `--format jsonl`

## Next Steps

After identifying vulnerabilities:

1. Verify the findings manually to confirm they are exploitable
2. Follow responsible disclosure practices to report the issues
3. For your own repositories, implement fixes based on the findings
