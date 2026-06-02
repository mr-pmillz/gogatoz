---
title: Understanding GitLab CI/CD Vulnerabilities
description: Common vulnerability classes in GitLab CI/CD that GoGatoZ analyzes
---

This page explains common vulnerability classes in GitLab CI/CD (.gitlab-ci.yml) that GoGatoZ analyzes.

## Pwn Requests (Merge Request based)

A class of issues where a pipeline triggered by merge requests evaluates attacker-controlled input (MR title/description/labels/commits) or runs jobs on privileged runners.

### Example vulnerable pipeline

```yaml
stages:
  - test

pwn:
  stage: test
  tags: [self-hosted]
  script: |
    echo "MR title: $CI_MERGE_REQUEST_TITLE"
    bash -c "$CI_MERGE_REQUEST_DESCRIPTION"
  rules:
    # Runs for MRs targeting main or prod
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME =~ /^(main|prod)$/'
      when: on_success
```

Why it's dangerous:
- Runs on tagged self-hosted runners (often privileged) for MR pipelines
- Executes attacker-controlled MR description directly

## Variable injection in scripts

Using CI/CD variables derived from attacker input without validation can lead to command injection.

```yaml
stages:
  - test

pwn:
  stage: test
  deploy:
    script: |
      ENV=$(echo "$CI_MERGE_REQUEST_TITLE" | awk '{print $1}')
      ./deploy.sh "$ENV"
    rules:
      - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

Risk: An attacker can set the MR title to include shell metacharacters to alter script execution.

Safer pattern: sanitize, use allowlists, or map values rather than interpolating directly in shell commands.

## Insecure rules:/only: configurations

- Broad rules that run on merge_request_event for protected branches without additional gating (approval, manual job)
- Use of `when: always` or unconditional `only: [merge_requests]` on jobs that target self-hosted runners
- Missing checks for `$CI_PROJECT_VISIBILITY` or `$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` provenance when consuming artifacts

## Remote includes and components

- `include:remote` with unpinned or attacker-controlled URLs
- Project includes without ref pinning (branch instead of tag/sha)
- CI/CD components pulled with mutable refs or unvalidated inputs

## Secrets exposure

- Plaintext variables defined in `.gitlab-ci.yml`
- Echoing variables in logs or uploading as artifacts without expiry

## Script injection risk (SCRIPT_INJECTION_RISK) — HIGH

MR-triggered jobs call external repo scripts (e.g., `./scripts/deploy.sh`) that an attacker can modify through a merge request. Because the script content is not reviewed as part of the CI configuration, changes to these files bypass typical CI/CD review controls.

Why it's dangerous:
- Attackers modify a script file rather than `.gitlab-ci.yml`, making malicious changes harder to spot in code review
- The CI job executes the modified script with full runner privileges
- Commonly used for workflow hopping — pivoting from code changes to CI execution context

## Self-merge possible (SELF_MERGE_POSSIBLE) — HIGH

The project allows a user to create a merge request, approve it themselves, and merge it to the default branch. This typically occurs when approval rules require zero approvals, or when the "Prevent approval by merge request author" setting is disabled.

Why it's dangerous:
- An attacker with Developer access can push malicious CI changes and immediately merge them
- Bypasses the assumption that another human reviews changes before they reach protected branches
- Enables full supply chain compromise when combined with CI jobs that run on merge to default branch

## Cache poisoning risk (CACHE_POISONING_RISK) — MEDIUM

CI jobs use shared cache keys without branch isolation, allowing a job on one branch to poison cached artifacts consumed by jobs on other branches (including the default branch).

Why it's dangerous:
- An attacker commits a job that writes malicious content to a shared cache key
- Subsequent jobs on the default branch consume the poisoned cache without verification
- Enables persistent code execution without modifying any source files or CI configuration
