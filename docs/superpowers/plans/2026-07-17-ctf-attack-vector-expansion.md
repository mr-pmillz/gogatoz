# CTF Attack Vector Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 13 new CTF challenges (Flags 35-47) across 3 new tracks to the GoGatoZ lab, validate them, and create walkthrough documentation.

**Architecture:** New challenges are added to `setup-lab.sh` as a new function `create_expansion_repos()` called from `create_ctf_chain()`. Each repo follows the existing pattern: `create_ctf_project` + `ctf_add_variable` + `add_project_member`. Three new lab pages are added to the hackers-guide-to-cicd Astro Starlight docs site, and existing scoring/reference tables are updated.

**Tech Stack:** Bash (setup-lab.sh), Markdown/MDX (Astro Starlight docs), GoGatoZ CLI

## Global Constraints

- Flag format: `FLAG+<leetspeak>+` (no curly braces — GitLab masking constraint)
- Flag IDs: 35-47 (contiguous, following existing max ID 34)
- All CI variables: masked=true, protected=false (standard for extractable secrets)
- All repos: `add_project_member` cicd-bot at level 30 (Developer)
- All CI jobs: `tags: [shell_executor]` (shell runner available in lab)
- Flag values must be 20+ chars after `FLAG+` prefix for trufflehog entropy detection
- Base64 JSON array for flagserver must be valid JSON — test with `echo $B64 | base64 -d | jq .`
- Docs pages use Astro Starlight frontmatter (`title:` only) and standard section structure

---

### Task 1: Add `create_expansion_repos()` function to setup-lab.sh (Track 1: Flags 35-39)

**Files:**
- Modify: `/home/phil/projects/gogatoz-ctf/setup-lab.sh`

**Interfaces:**
- Consumes: helper functions `create_ctf_project`, `ctf_add_variable`, `add_project_member`, `ctf_update_file` (all existing in setup-lab.sh)
- Produces: 5 GitLab repos (shared-ci-templates, monorepo-platform, component-library, secure-pipeline, deploy-orchestrator) with CI configs and flag variables

- [ ] **Step 1: Add the `create_expansion_repos()` function skeleton and Track 1 repos**

Insert before the `create_ctf_chain()` function (line 3372). Add all 5 Track 1 repos:

```bash
# ── Attack Vector Expansion Track ──────────────────────────────────────────
# 13 new challenges (Flags 35-47) across 3 tracks:
#   Track 1: Include & Workflow Abuse (Flags 35-39, 1800 pts)
#   Track 2: Cloud & Container Federation (Flags 40-43, 1500 pts)
#   Track 3: Advanced Supply Chain II (Flags 44-47, 1800 pts)

create_expansion_repos() {
  log "Creating expansion track repos (Flags 35-47)..."

  # ── Track 1: Include & Workflow Abuse ────────────────────────────────────

  # ── shared-ci-templates (PUBLIC) ─────────────────────────────────────────
  # Challenge: Remote include with cache:true — poisoned template persists
  create_ctf_project "shared-ci-templates" "public" \
'include:
  - remote: '"'"'https://gitlab.local:8929/root/ci-templates/-/raw/main/build-template.yml'"'"'
    cache: "1h"

stages:
  - build
  - test

build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "Building with cached template config"
    - echo "Template version: $TEMPLATE_VERSION"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

test:
  stage: test
  tags: [shell_executor]
  script:
    - echo "Running tests"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# shared-ci-templates

Centralized CI/CD templates for the organization. Build and test
configurations are cached from remote includes for performance.
"

  ctf_add_variable "shared-ci-templates" "TEMPLATE_SECRET" "FLAG+r3m0t3_1nclud3_c4ch3_p01s0n3d_4ll_p1p3l1n3s_pwn3d+" "true" "false"
  add_project_member "shared-ci-templates" "cicd-bot" 30

  # ── monorepo-platform (PUBLIC) ───────────────────────────────────────────
  # Challenge: workflow:rules:variables overrides NPM_CONFIG_REGISTRY
  create_ctf_project "monorepo-platform" "public" \
'workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        BUILD_ENV: "staging"
        NPM_CONFIG_REGISTRY: "https://registry.npmjs.org"
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        BUILD_ENV: "production"
    - when: always

stages:
  - install
  - build

install:
  stage: install
  tags: [shell_executor]
  script:
    - echo "Installing from $NPM_CONFIG_REGISTRY"
    - echo "Environment: $BUILD_ENV"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "Building monorepo platform"
    - echo "Registry: $NPM_CONFIG_REGISTRY"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# monorepo-platform

Monorepo build system with per-environment configuration.
Workflow-level variables control the build behavior.
"

  ctf_add_variable "monorepo-platform" "PLATFORM_SECRET" "FLAG+w0rkfl0w_v4rs_h1j4ck3d_4ll_j0bs_0wn3d_r3g1stry_sw4p+" "true" "false"
  add_project_member "monorepo-platform" "cicd-bot" 30

  # ── component-library (PUBLIC) ───────────────────────────────────────────
  # Challenge: spec:inputs interpolation injection
  create_ctf_project "component-library" "public" \
'include:
  - component: gitlab.local:8929/root/ci-components/deploy@main
    inputs:
      environment: "staging"
      deploy_target: "https://app.internal"

stages:
  - deploy

deploy:
  stage: deploy
  tags: [shell_executor]
  script:
    - echo "Deploying to $DEPLOY_TARGET"
    - echo "Environment: $DEPLOY_ENV"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# component-library

Reusable CI/CD component library. Uses spec:inputs for
parameterized pipeline configuration.
"

  ctf_add_variable "component-library" "COMPONENT_SECRET" "FLAG+sp3c_1nputs_1nt3rp0l4t10n_br34k0ut_y4ml_1nj3ct3d+" "true" "false"
  add_project_member "component-library" "cicd-bot" 30

  # ── secure-pipeline (PUBLIC) ─────────────────────────────────────────────
  # Challenge: rules:changes/exists suppress security scanning
  create_ctf_project "secure-pipeline" "public" \
'stages:
  - test
  - security
  - deploy

unit-tests:
  stage: test
  tags: [shell_executor]
  script:
    - echo "Running unit tests"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

sast:
  stage: security
  tags: [shell_executor]
  script:
    - echo "Running SAST scan"
    - echo "Checking for vulnerabilities..."
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "**/*.py"
        - "**/*.js"
        - "**/*.go"
    - if: $CI_COMMIT_BRANCH == "main"

secret_detection:
  stage: security
  tags: [shell_executor]
  script:
    - echo "Running secret detection"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "**/*.py"
        - "**/*.js"
    - if: $CI_COMMIT_BRANCH == "main"

deploy:
  stage: deploy
  tags: [shell_executor]
  script:
    - echo "Deploying application"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# secure-pipeline

Production deployment pipeline with integrated security scanning.
SAST and secret detection run on merge requests.
"

  ctf_add_variable "secure-pipeline" "SCAN_SECRET" "FLAG+rul3s_byp4ss_s4st_d4st_d1s4bl3d_d3f3ns3_3v4s10n+" "true" "false"
  add_project_member "secure-pipeline" "cicd-bot" 30

  # ── deploy-orchestrator (PUBLIC) ─────────────────────────────────────────
  # Challenge: interruptible:true race condition on setup job
  create_ctf_project "deploy-orchestrator" "public" \
'stages:
  - setup
  - verify
  - deploy

credential-setup:
  stage: setup
  tags: [shell_executor]
  interruptible: true
  script:
    - echo "Fetching deployment credentials..."
    - sleep 15
    - echo "Credentials configured"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

verify-setup:
  stage: verify
  tags: [shell_executor]
  script:
    - echo "Verifying credential setup"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

deploy:
  stage: deploy
  tags: [shell_executor]
  script:
    - echo "Deploying with configured credentials"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# deploy-orchestrator

Multi-stage deployment orchestrator with credential setup,
verification, and deployment stages.
"

  ctf_add_variable "deploy-orchestrator" "DEPLOY_RACE_SECRET" "FLAG+1nt3rrupt1bl3_r4c3_c0nd1t10n_s3tup_f41l_3xpl01t3d+" "true" "false"
  add_project_member "deploy-orchestrator" "cicd-bot" 30
```

- [ ] **Step 2: Verify the bash syntax is valid**

Run: `bash -n /home/phil/projects/gogatoz-ctf/setup-lab.sh`
Expected: no output (clean parse)

- [ ] **Step 3: Commit**

```bash
git add setup-lab.sh
git commit -m "feat: add Track 1 expansion repos (Flags 35-39) — include & workflow abuse"
```

---

### Task 2: Add Track 2 repos (Flags 40-43) to `create_expansion_repos()`

**Files:**
- Modify: `/home/phil/projects/gogatoz-ctf/setup-lab.sh`

**Interfaces:**
- Consumes: same helpers as Task 1
- Produces: 4 GitLab repos (cloud-deployer, compliance-scanner, microservice-build, load-test-runner)

- [ ] **Step 1: Append Track 2 repos to `create_expansion_repos()`**

Insert after the deploy-orchestrator block, before the closing `}` of `create_expansion_repos`:

```bash
  # ── Track 2: Cloud & Container Federation ────────────────────────────────

  # ── cloud-deployer (PUBLIC) ──────────────────────────────────────────────
  # Challenge: OIDC id_tokens exfiltration + cloud credential exchange
  create_ctf_project "cloud-deployer" "public" \
'stages:
  - authenticate
  - deploy

cloud-auth:
  stage: authenticate
  tags: [shell_executor]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://iam.googleapis.com
  script:
    - echo "Authenticating to cloud provider via OIDC"
    - echo "Token audience: https://iam.googleapis.com"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

deploy-cloud:
  stage: deploy
  tags: [shell_executor]
  script:
    - echo "Deploying to cloud infrastructure"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# cloud-deployer

Cloud infrastructure deployment pipeline using OIDC federation
for keyless authentication to cloud providers.
"

  ctf_add_variable "cloud-deployer" "CLOUD_SECRET" "FLAG+01dc_f3d3r4t10n_cl0ud_cr3ds_3xch4ng3d_4ws_gcp_4zur3+" "true" "false"
  add_project_member "cloud-deployer" "cicd-bot" 30

  # ── compliance-scanner (PUBLIC) ──────────────────────────────────────────
  # Challenge: Inject clean SARIF to suppress real security findings
  create_ctf_project "compliance-scanner" "public" \
'stages:
  - scan
  - report

security-scan:
  stage: scan
  tags: [shell_executor]
  script:
    - echo "Running compliance checks..."
    - echo '"'"'{"version":"2.1.0","runs":[]}'"'"' > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

compliance-report:
  stage: report
  tags: [shell_executor]
  script:
    - echo "Generating compliance report"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# compliance-scanner

Security compliance pipeline that produces SARIF reports
for the GitLab security dashboard.
"

  ctf_add_variable "compliance-scanner" "COMPLIANCE_SECRET" "FLAG+4rt1f4ct_r3p0rt_sp00f3d_s4r1f_cl34n_r34l_bugs_h1dd3n+" "true" "false"
  add_project_member "compliance-scanner" "cicd-bot" 30

  # ── microservice-build (PUBLIC) ──────────────────────────────────────────
  # Challenge: image:name override + services:command injection
  create_ctf_project "microservice-build" "public" \
'stages:
  - build
  - test

build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "Building microservice"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

integration-test:
  stage: test
  tags: [shell_executor]
  services:
    - name: postgres:14
    - name: redis:7
  script:
    - echo "Running integration tests with services"
    - echo "DB host: $POSTGRES_PORT_5432_TCP_ADDR"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# microservice-build

Microservice build and integration test pipeline.
Uses PostgreSQL and Redis service containers.
"

  ctf_add_variable "microservice-build" "BUILD_SECRET" "FLAG+1m4g3_p01s0n_s3rv1c3_c0mm4nd_c0nt41n3r_h1j4ck3d+" "true" "false"
  add_project_member "microservice-build" "cicd-bot" 30

  # ── load-test-runner (PUBLIC) ────────────────────────────────────────────
  # Challenge: parallel:matrix combinatorial credential sweep
  create_ctf_project "load-test-runner" "public" \
'stages:
  - test

load-test:
  stage: test
  tags: [shell_executor]
  parallel:
    matrix:
      - REGION: ["us-east-1", "eu-west-1"]
        CONCURRENCY: ["10", "50", "100"]
  script:
    - echo "Load testing region=$REGION concurrency=$CONCURRENCY"
    - echo "Test ID: $CI_NODE_INDEX of $CI_NODE_TOTAL"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# load-test-runner

Parallel load testing suite. Uses matrix variables to test
across multiple regions and concurrency levels.
"

  ctf_add_variable "load-test-runner" "LOAD_SECRET" "FLAG+p4r4ll3l_m4tr1x_cr3d_sw33p_c0mb1n4t0r14l_3xpl0d3+" "true" "false"
  add_project_member "load-test-runner" "cicd-bot" 30
```

- [ ] **Step 2: Verify bash syntax**

Run: `bash -n /home/phil/projects/gogatoz-ctf/setup-lab.sh`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add setup-lab.sh
git commit -m "feat: add Track 2 expansion repos (Flags 40-43) — cloud & container federation"
```

---

### Task 3: Add Track 3 repos (Flags 44-47) and wire into `create_ctf_chain()`

**Files:**
- Modify: `/home/phil/projects/gogatoz-ctf/setup-lab.sh`

**Interfaces:**
- Consumes: same helpers as Task 1
- Produces: 4 GitLab repos (bootstrap-runner, build-cache-manager, release-orchestrator, shared-artifacts). Function wired into `create_ctf_chain()`.

- [ ] **Step 1: Append Track 3 repos and close the function**

Insert after the load-test-runner block:

```bash
  # ── Track 3: Advanced Supply Chain II ────────────────────────────────────

  # ── bootstrap-runner (PUBLIC) ────────────────────────────────────────────
  # Challenge: hooks:pre_get_sources_script injection
  create_ctf_project "bootstrap-runner" "public" \
'stages:
  - init
  - build

init:
  stage: init
  tags: [shell_executor]
  hooks:
    pre_get_sources_script:
      - echo "Pre-source initialization"
      - echo "Setting up runner environment"
  script:
    - echo "Runner initialized"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "Building with initialized runner"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# bootstrap-runner

Runner initialization pipeline with pre-source hooks
for environment setup before repository checkout.
"

  ctf_add_variable "bootstrap-runner" "BOOTSTRAP_SECRET" "FLAG+pr3_g3t_s0urc3s_h00k_b3f0r3_g1t_f3tch_pwn3d+" "true" "false"
  add_project_member "bootstrap-runner" "cicd-bot" 30

  # ── build-cache-manager (PUBLIC) ─────────────────────────────────────────
  # Challenge: cache:key:prefix + cache:key:files poisoning
  create_ctf_project "build-cache-manager" "public" \
'stages:
  - install
  - build

install:
  stage: install
  tags: [shell_executor]
  script:
    - echo "Installing dependencies"
    - mkdir -p node_modules
    - echo "lodash@4.17.21" > node_modules/.package-lock.json
  cache:
    key:
      prefix: "deps"
      files:
        - package-lock.json
    paths:
      - node_modules/
    policy: pull-push
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

build:
  stage: build
  tags: [shell_executor]
  script:
    - echo "Building with cached deps"
    - ls node_modules/ || echo "No cache hit"
  cache:
    key:
      prefix: "deps"
      files:
        - package-lock.json
    paths:
      - node_modules/
    policy: pull
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# build-cache-manager

Build cache optimization pipeline using structured cache keys
with prefix and file-based key generation.
"

  ctf_add_variable "build-cache-manager" "CACHE_MGR_SECRET" "FLAG+c4ch3_k3y_pr3f1x_p01s0n_sh4r3d_c4ch3_1nj3ct3d+" "true" "false"
  add_project_member "build-cache-manager" "cicd-bot" 30

  # ── release-orchestrator (PUBLIC) ────────────────────────────────────────
  # Challenge: trigger:include:artifact child pipeline injection
  create_ctf_project "release-orchestrator" "public" \
'stages:
  - generate
  - release

generate-config:
  stage: generate
  tags: [shell_executor]
  script:
    - echo "Generating release pipeline config"
    - |
      cat > release-pipeline.yml << '"'"'EOF'"'"'
      stages: [publish]
      publish:
        stage: publish
        tags: [shell_executor]
        script:
          - echo "Publishing release"
      EOF
  artifacts:
    paths:
      - release-pipeline.yml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

trigger-release:
  stage: release
  trigger:
    include:
      - artifact: release-pipeline.yml
        job: generate-config
    strategy: depend
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# release-orchestrator

Release pipeline using dynamic child pipeline configuration
generated as a build artifact.
"

  ctf_add_variable "release-orchestrator" "RELEASE_ORCH_SECRET" "FLAG+tr1gg3r_4rt1f4ct_ch1ld_p1p3l1n3_dyn4m1c_1nj3ct3d+" "true" "false"
  add_project_member "release-orchestrator" "cicd-bot" 30

  # ── shared-artifacts (PUBLIC) ────────────────────────────────────────────
  # Challenge: needs:project cross-project artifact supply chain
  create_ctf_project "shared-artifacts" "public" \
'stages:
  - build

build:
  stage: build
  tags: [shell_executor]
  needs:
    - project: root/component-library
      job: deploy
      ref: main
      artifacts: true
  script:
    - echo "Building with shared artifacts"
    - ls -la || echo "No artifacts pulled"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
' \
"# shared-artifacts

Cross-project artifact dependency chain. Pulls build
artifacts from the component-library project.
"

  ctf_add_variable "shared-artifacts" "SHARED_ART_SECRET" "FLAG+n33ds_pr0j3ct_cr0ss_4rt1f4ct_supply_ch41n_pwn3d+" "true" "false"
  add_project_member "shared-artifacts" "cicd-bot" 30

  ok "Expansion track repos created (13 repos, Flags 35-47)"
}
```

- [ ] **Step 2: Wire `create_expansion_repos()` into `create_ctf_chain()`**

Add the call after `update_vuln_repos_for_ctf`:

```bash
create_ctf_chain() {
  log ""
  log "=== Step 6: Lab Projects & Accounts ==="
  create_ctf_users
  create_ctf_repos
  create_pivot_repos
  create_sample_repos
  create_worm_track
  update_vuln_repos_for_ctf
  create_expansion_repos
}
```

- [ ] **Step 3: Verify bash syntax**

Run: `bash -n /home/phil/projects/gogatoz-ctf/setup-lab.sh`
Expected: no output

- [ ] **Step 4: Commit**

```bash
git add setup-lab.sh
git commit -m "feat: add Track 3 expansion repos (Flags 44-47) — advanced supply chain II"
```

---

### Task 4: Update `generate_flagserver_env()` with Flags 35-47

**Files:**
- Modify: `/home/phil/projects/gogatoz-ctf/setup-lab.sh`

**Interfaces:**
- Consumes: existing `generate_flagserver_env()` function, flag values from Tasks 1-3
- Produces: updated `CTF_FLAGS_B64` containing 47 flags (34 existing + 13 new)

- [ ] **Step 1: Generate the base64-encoded JSON for flags 35-47**

The new flag JSON objects to append (before the closing `]`):

```json
,{"id": 35,"value": "FLAG+r3m0t3_1nclud3_c4ch3_p01s0n3d_4ll_p1p3l1n3s_pwn3d+","points": 400,"name": "Remote Include Cache Poison","hint": "Remote includes with cache:true persist poisoned config across pipelines"},{"id": 36,"value": "FLAG+w0rkfl0w_v4rs_h1j4ck3d_4ll_j0bs_0wn3d_r3g1stry_sw4p+","points": 400,"name": "Workflow Variable Hijack","hint": "workflow:rules:variables override package registries for all jobs"},{"id": 37,"value": "FLAG+sp3c_1nputs_1nt3rp0l4t10n_br34k0ut_y4ml_1nj3ct3d+","points": 300,"name": "Component Input Injection","hint": "spec:inputs interpolation breaks out with YAML metacharacters"},{"id": 38,"value": "FLAG+rul3s_byp4ss_s4st_d4st_d1s4bl3d_d3f3ns3_3v4s10n+","points": 400,"name": "Security Scan Evasion","hint": "Modify rules:changes to suppress SAST and secret detection jobs"},{"id": 39,"value": "FLAG+1nt3rrupt1bl3_r4c3_c0nd1t10n_s3tup_f41l_3xpl01t3d+","points": 300,"name": "Interruptible Race Condition","hint": "Cancel an interruptible setup job and exploit the on_failure fallback"},{"id": 40,"value": "FLAG+01dc_f3d3r4t10n_cl0ud_cr3ds_3xch4ng3d_4ws_gcp_4zur3+","points": 500,"name": "OIDC Cloud Federation","hint": "Exfiltrate OIDC tokens from id_tokens: and exchange for cloud credentials"},{"id": 41,"value": "FLAG+4rt1f4ct_r3p0rt_sp00f3d_s4r1f_cl34n_r34l_bugs_h1dd3n+","points": 400,"name": "Artifact Report Spoofing","hint": "Inject a clean SARIF report to suppress real security findings"},{"id": 42,"value": "FLAG+1m4g3_p01s0n_s3rv1c3_c0mm4nd_c0nt41n3r_h1j4ck3d+","points": 300,"name": "Container Service Hijack","hint": "Override services:command to execute code in service containers"},{"id": 43,"value": "FLAG+p4r4ll3l_m4tr1x_cr3d_sw33p_c0mb1n4t0r14l_3xpl0d3+","points": 300,"name": "Matrix Credential Sweep","hint": "Use parallel:matrix to sweep credential paths across parallel instances"},{"id": 44,"value": "FLAG+pr3_g3t_s0urc3s_h00k_b3f0r3_g1t_f3tch_pwn3d+","points": 400,"name": "Pre-Source Hook Injection","hint": "hooks:pre_get_sources_script runs before git fetches the repo"},{"id": 45,"value": "FLAG+c4ch3_k3y_pr3f1x_p01s0n_sh4r3d_c4ch3_1nj3ct3d+","points": 400,"name": "Cache Key Prefix Poison","hint": "Manipulate cache:key:prefix to poison shared build caches"},{"id": 46,"value": "FLAG+tr1gg3r_4rt1f4ct_ch1ld_p1p3l1n3_dyn4m1c_1nj3ct3d+","points": 500,"name": "Child Pipeline Injection","hint": "Write malicious YAML as artifact and trigger it as a child pipeline"},{"id": 47,"value": "FLAG+n33ds_pr0j3ct_cr0ss_4rt1f4ct_supply_ch41n_pwn3d+","points": 500,"name": "Cross-Project Artifact Injection","hint": "needs:project pulls attacker-controlled artifacts from a compromised project"}]
```

Generate the base64 for the full 47-flag array by: (a) decoding existing `flags_b64`, (b) removing the trailing `]`, (c) appending the 13 new entries with the trailing `]`, (d) re-encoding, (e) splitting into 76-char lines for the bash variable.

Run a script to produce the new `flags_b64` lines:

```bash
# Decode existing, append new flags, re-encode
cd /home/phil/projects/gogatoz-ctf
# Extract the current base64 value from setup-lab.sh
existing_b64=$(sed -n '/^local flags_b64="/,/^$/p' setup-lab.sh | \
  grep 'flags_b64' | sed 's/.*flags_b64[+=]*"//' | sed 's/"//' | tr -d '\n')
# Decode, strip trailing ], append new flags + ]
existing_json=$(echo "$existing_b64" | base64 -d)
new_json="${existing_json%]},NEW_FLAGS_HERE]"
# Re-encode and split
echo "$new_json" | base64 -w 76
```

Replace the `flags_b64` assignment block in `generate_flagserver_env()` (lines 3663-3769) with the new base64 lines.

- [ ] **Step 2: Verify the base64 decodes to valid JSON with 47 flags**

Run: `echo "$NEW_B64" | base64 -d | python3 -c "import json,sys; f=json.load(sys.stdin); print(f'Flags: {len(f)}, Max ID: {max(x[\"id\"] for x in f)}, Total pts: {sum(x[\"points\"] for x in f)}')" `
Expected: `Flags: 47, Max ID: 47, Total pts: 18650`

- [ ] **Step 3: Commit**

```bash
git add setup-lab.sh
git commit -m "feat: register Flags 35-47 in flagserver base64 JSON"
```

---

### Task 5: Update `print_summary()` and totals

**Files:**
- Modify: `/home/phil/projects/gogatoz-ctf/setup-lab.sh`

**Interfaces:**
- Consumes: print_summary function at line 3786
- Produces: updated summary output reflecting 47 flags, 18650 pts, 12 tracks

- [ ] **Step 1: Update the summary text**

Change line 3816 from:
```
  echo "  32 flags across 9 chains (12850 pts total)"
```
to:
```
  echo "  47 flags across 12 chains (18650 pts total)"
```

Add three new track descriptions after the existing Nested Runner C2 track block:

```bash
  echo
  echo "  Include & Workflow Abuse Track (5 flags, 300-400 pts = 1800 pts)"
  echo "    Config manipulation: remote include cache, workflow vars, spec:inputs, rules bypass, interruptible"
  echo "    Entry: cicd-bot token (from Flag 1)"
  echo
  echo "  Cloud & Container Federation Track (4 flags, 300-500 pts = 1500 pts)"
  echo "    Cloud abuse: OIDC federation, artifact reports, image/service poison, parallel matrix"
  echo "    Entry: cicd-bot token (from Flag 1)"
  echo
  echo "  Advanced Supply Chain II Track (4 flags, 400-500 pts = 1800 pts)"
  echo "    Supply chain: pre-source hooks, cache key prefix, child pipeline trigger, cross-project artifacts"
  echo "    Entry: cicd-bot token (from Flag 1)"
```

- [ ] **Step 2: Verify bash syntax**

Run: `bash -n /home/phil/projects/gogatoz-ctf/setup-lab.sh`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add setup-lab.sh
git commit -m "feat: update print_summary with 3 new expansion tracks (47 flags, 18650 pts)"
```

---

### Task 6: Create lab9-14.md — Include & Workflow Abuse

**Files:**
- Create: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/lab9-14.md`

**Interfaces:**
- Consumes: flag values/repo names from Tasks 1-3
- Produces: complete CTF track walkthrough page with scoring table, 5 stages, hints/spoilers, key takeaways

- [ ] **Step 1: Write the lab page**

Follow the existing CTF track template from lab9-12.md / lab9-13.md. The page must include:

1. Frontmatter with title
2. Introductory paragraph
3. Scoring table (5 flags)
4. Mermaid diagram showing the 5 attack techniques
5. Prerequisites section
6. 5 stages — each with Objective, Concept (annotated YAML), Target, and `<details><summary>Hint N</summary>` blocks
7. Scoreboard tracking table
8. Solutions (Instructor Reference) in `<details>` blocks with full `gogatoz` commands
9. Key Takeaways
10. Next Steps linking to lab9-15

Each stage solution must show:
- `gogatoz enumerate` command to detect the vulnerability
- `gogatoz attack --payload-only --payload <name>` to preview the payload
- `gogatoz attack --commit-ci --payload <name> --target root/<repo>` to execute
- Expected flag value

- [ ] **Step 2: Verify the docs build**

Run: `cd /home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd && npm run build 2>&1 | tail -5`
Expected: build succeeds

- [ ] **Step 3: Commit**

```bash
cd /home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd
git add src/content/docs/labs/gitlab-exploitation/lab9-14.md
git commit -m "docs: add Lab 9.14 — Include & Workflow Abuse CTF track (Flags 35-39)"
```

---

### Task 7: Create lab9-15.md — Cloud & Container Federation

**Files:**
- Create: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/lab9-15.md`

**Interfaces:**
- Same template as Task 6 but for Track 2 (4 stages, Flags 40-43)

- [ ] **Step 1: Write the lab page**

Same structure as Task 6 but for the 4 Cloud & Container Federation challenges. Link back to lab9-14 and forward to lab9-16.

- [ ] **Step 2: Verify docs build**

Run: `cd /home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd && npm run build 2>&1 | tail -5`

- [ ] **Step 3: Commit**

```bash
git add src/content/docs/labs/gitlab-exploitation/lab9-15.md
git commit -m "docs: add Lab 9.15 — Cloud & Container Federation CTF track (Flags 40-43)"
```

---

### Task 8: Create lab9-16.md — Advanced Supply Chain II

**Files:**
- Create: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/lab9-16.md`

**Interfaces:**
- Same template as Task 6 but for Track 3 (4 stages, Flags 44-47)

- [ ] **Step 1: Write the lab page**

Same structure as Task 6 but for the 4 Advanced Supply Chain II challenges. Link back to lab9-15.

- [ ] **Step 2: Verify docs build**

Run: `cd /home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd && npm run build 2>&1 | tail -5`

- [ ] **Step 3: Commit**

```bash
git add src/content/docs/labs/gitlab-exploitation/lab9-16.md
git commit -m "docs: add Lab 9.16 — Advanced Supply Chain II CTF track (Flags 44-47)"
```

---

### Task 9: Update existing docs pages and sidebar

**Files:**
- Modify: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/astro.config.mjs` (line 108)
- Modify: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/lab9-7.md`
- Modify: `/home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/gogatoz-setup.md`

**Interfaces:**
- Consumes: repo names, flag IDs, point values from the design spec
- Produces: updated sidebar, scoring tables, repo reference tables

- [ ] **Step 1: Add sidebar entries in astro.config.mjs**

After line 108 (`lab9-13` entry), add:

```javascript
                { label: 'Lab 9.14: Include & Workflow Abuse', slug: 'labs/gitlab-exploitation/lab9-14' },
                { label: 'Lab 9.15: Cloud & Container Federation', slug: 'labs/gitlab-exploitation/lab9-15' },
                { label: 'Lab 9.16: Advanced Supply Chain II', slug: 'labs/gitlab-exploitation/lab9-16' },
```

- [ ] **Step 2: Update lab9-7.md scoring table**

Add Flags 35-47 to the scoring table (before the `**Total**` row). Update the total from `12350` to `17450` (the lab9-7 table may not include all flags — check against what's listed). Add 3 new track references in the `:::note[Advanced Tracks]` block:

```markdown
Flags 35-39: Include & workflow abuse (remote include cache, workflow vars, spec:inputs, rules bypass, interruptible). See [Lab 9.14](./lab9-14/).
Flags 40-43: Cloud & container federation (OIDC federation, artifact reports, image poison, parallel matrix). See [Lab 9.15](./lab9-15/).
Flags 44-47: Advanced supply chain II (pre-source hooks, cache key prefix, child pipeline trigger, cross-project artifacts). See [Lab 9.16](./lab9-16/).
```

- [ ] **Step 3: Update gogatoz-setup.md CTF Repos table**

Add 13 new rows to the "CTF Repos" table (line 454), maintaining the existing format:

```markdown
| `shared-ci-templates` | Public | Include & Workflow | FLAG 35 (400 pts) | Remote include cache poisoning |
| `monorepo-platform` | Public | Include & Workflow | FLAG 36 (400 pts) | Workflow:rules:variables hijack |
| `component-library` | Public | Include & Workflow | FLAG 37 (300 pts) | spec:inputs interpolation injection |
| `secure-pipeline` | Public | Include & Workflow | FLAG 38 (400 pts) | rules:changes/exists scan evasion |
| `deploy-orchestrator` | Public | Include & Workflow | FLAG 39 (300 pts) | Interruptible race condition exploit |
| `cloud-deployer` | Public | Cloud & Container | FLAG 40 (500 pts) | OIDC id_tokens cloud federation |
| `compliance-scanner` | Public | Cloud & Container | FLAG 41 (400 pts) | Artifact report SARIF spoofing |
| `microservice-build` | Public | Cloud & Container | FLAG 42 (300 pts) | Image/service container hijack |
| `load-test-runner` | Public | Cloud & Container | FLAG 43 (300 pts) | parallel:matrix credential sweep |
| `bootstrap-runner` | Public | Supply Chain II | FLAG 44 (400 pts) | pre_get_sources_script injection |
| `build-cache-manager` | Public | Supply Chain II | FLAG 45 (400 pts) | cache:key:prefix poisoning |
| `release-orchestrator` | Public | Supply Chain II | FLAG 46 (500 pts) | trigger:include:artifact child pipeline |
| `shared-artifacts` | Public | Supply Chain II | FLAG 47 (500 pts) | needs:project cross-project artifacts |
```

- [ ] **Step 4: Verify docs build**

Run: `cd /home/phil/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd && npm run build 2>&1 | tail -5`
Expected: build succeeds

- [ ] **Step 5: Commit**

```bash
git add astro.config.mjs \
  src/content/docs/labs/gitlab-exploitation/lab9-7.md \
  src/content/docs/labs/gitlab-exploitation/gogatoz-setup.md
git commit -m "docs: update sidebar, scoring tables, and repo reference for Flags 35-47"
```

---

### Task 10: Validate with ctf-qa-validation skill

**Files:**
- No new files — uses existing GoGatoZ CLI and lab environment

**Interfaces:**
- Consumes: running lab environment (docker compose up + setup-lab.sh), GoGatoZ binary
- Produces: validation report confirming all 13 flags are solvable

- [ ] **Step 1: Invoke the ctf-qa-validation skill**

Use `Skill(skill: "ctf-qa-validation")` to validate that:
1. All 13 repos are created correctly
2. `gogatoz enumerate` detects the corresponding vulnerability in each repo
3. `gogatoz attack --payload-only --payload <name>` generates valid YAML for all 13 payloads
4. Flag values match between setup-lab.sh CI variables and flagserver JSON
5. Documentation builds without errors

- [ ] **Step 2: Fix any issues found by validation**

Address any failures from the QA validation — mismatched flag values, broken CI configs, missing variables, etc.

- [ ] **Step 3: Final commit**

```bash
# In gogatoz-ctf repo:
git add setup-lab.sh
git commit -m "fix: address QA validation findings for expansion tracks"

# In hackers-guide-to-cicd repo:
git add -A
git commit -m "fix: address QA validation findings for expansion lab pages"
```
