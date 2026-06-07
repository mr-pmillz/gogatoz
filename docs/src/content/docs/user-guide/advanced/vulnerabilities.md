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

---

## Living off the Pipeline (LOTP_TOOL_EXEC) — HIGH/MEDIUM

Tools such as `npm`, `make`, `pip`, `gradle`, `eslint`, `terraform`, and 60+ others read configuration from files in the repository (e.g., `package.json`, `Makefile`, `requirements.txt`, `.eslintrc`). When these tools run in MR-triggered jobs, a fork author can submit an MR that **weaponizes the config file** to execute arbitrary code when the pipeline runs — without touching `.gitlab-ci.yml` at all.

Source: [Living off the Pipeline (LOTP)](https://boostsecurityio.github.io/lotp/)

```yaml
# Example: vulnerable — npm runs in MR-triggered job
lint:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - npm install    # reads package.json — attacker-controlled in fork
    - npm run lint   # reads .eslintrc — attacker can add malicious ESLint plugin
```

Severity: **HIGH** when self-hosted runners are targeted (persistent infra at risk); **MEDIUM** on shared/ephemeral runners.

Mitigation: Restrict LOTP-tool jobs to protected branches only, add fork protection rules (`CI_MERGE_REQUEST_SOURCE_PROJECT_PATH == CI_MERGE_REQUEST_TARGET_PROJECT_PATH`), or move tool config outside the repository.

## Cache key injection (CACHE_KEY_INJECTION) — HIGH/MEDIUM

Cache keys derived from attacker-controllable variables (such as `$CI_MERGE_REQUEST_TITLE`, `$CI_COMMIT_AUTHOR`, or `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`) let an attacker craft an MR to target or overwrite a specific cache entry.

```yaml
# Example: vulnerable — cache key derived from MR title
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: "build-$CI_MERGE_REQUEST_TITLE"   # attacker controls the cache slot
    paths: [.cache/]
  script:
    - make build
```

Mitigation: Use static cache keys or keys derived from content hashes of pinned files (e.g., `cache: key: files: [package-lock.json]`).

## GitLab OIDC token in MR jobs (OIDC_TOKEN_MR_RISK) — HIGH

GitLab can issue short-lived OIDC tokens via the `id_tokens:` job key, which are accepted by AWS, GCP, and Azure for passwordless authentication. If a job that defines `id_tokens:` is triggered by a merge request, **a fork author can trigger that job and capture the token** to authenticate against cloud providers.

```yaml
# Example: vulnerable — OIDC token issued for MR pipeline
validate_mr:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts get-caller-identity   # token is now accessible to the job log
```

Mitigation: Only issue OIDC tokens in jobs restricted to protected branches. Never use `id_tokens:` in MR-triggered jobs.

## Downstream trigger chain abuse (TRIGGER_CHAIN_RISK) — HIGH/MEDIUM

Jobs that use `trigger:` to launch downstream (child) pipelines in an MR-triggered context allow fork authors to initiate cross-project pipeline runs. With `strategy: depend`, the parent job waits for the child, creating timing-based attack windows.

```yaml
# Example: vulnerable — downstream trigger from MR-triggered job
trigger_child:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  trigger:
    project: org/child-project
    strategy: depend    # HIGH severity: parent waits, attacker observes timing
```

Mitigation: Never trigger downstream pipelines from MR-triggered jobs unless the downstream project independently restricts who can run pipelines. Prefer `strategy: mirror` for status forwarding only.
