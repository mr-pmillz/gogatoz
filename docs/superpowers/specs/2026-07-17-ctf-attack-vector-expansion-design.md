# Design: CTF Attack Vector Expansion (13 New Challenges)

## Context

GoGatoZ gained 13 new attack payload generators and 8 analyzer detection rules (Sprints 1-4 on `feat/research`). These need corresponding CTF challenges in the lab environment so students can practice the techniques, plus walkthrough documentation in the hackers-guide-to-cicd site.

## Scope

- **13 new flags** (IDs 35-47) across **3 new tracks**
- **13 new repos** in `setup-lab.sh`
- **3 new lab pages** (lab9-14.md, lab9-15.md, lab9-16.md)
- **Updates** to scoring tables, repo reference, sidebar config, and summary in existing pages

## Flag Registry

Existing: 34 flags, 13550 pts, max ID 34.
New: 13 flags, 5100 pts, IDs 35-47.
Combined: **47 flags, 18650 pts**.

### Track 1: Include & Workflow Abuse (lab9-14.md)

Entry point: cicd-bot PAT (from Flag 1). 5 flags, 1800 pts.

| ID | Pts | Repo | CI Variable | Flag Value | Technique |
|----|-----|------|-------------|------------|-----------|
| 35 | 400 | shared-ci-templates | TEMPLATE_SECRET | `FLAG+r3m0t3_1nclud3_c4ch3_p01s0n3d_4ll_p1p3l1n3s_pwn3d+` | Remote include cache poisoning (`include:remote` + `cache: true`) |
| 36 | 400 | monorepo-platform | PLATFORM_SECRET | `FLAG+w0rkfl0w_v4rs_h1j4ck3d_4ll_j0bs_0wn3d_r3g1stry_sw4p+` | workflow:rules:variables injection (NPM_CONFIG_REGISTRY override) |
| 37 | 300 | component-library | COMPONENT_SECRET | `FLAG+sp3c_1nputs_1nt3rp0l4t10n_br34k0ut_y4ml_1nj3ct3d+` | spec:inputs interpolation injection via crafted component input |
| 38 | 400 | secure-pipeline | SCAN_SECRET | `FLAG+rul3s_byp4ss_s4st_d4st_d1s4bl3d_d3f3ns3_3v4s10n+` | rules:changes/exists suppress security scanning |
| 39 | 300 | deploy-orchestrator | DEPLOY_RACE_SECRET | `FLAG+1nt3rrupt1bl3_r4c3_c0nd1t10n_s3tup_f41l_3xpl01t3d+` | interruptible:true + on_failure fallback exploitation |

### Track 2: Cloud & Container Federation (lab9-15.md)

Entry point: cicd-bot PAT. 4 flags, 1500 pts.

| ID | Pts | Repo | CI Variable | Flag Value | Technique |
|----|-----|------|-------------|------------|-----------|
| 40 | 500 | cloud-deployer | CLOUD_SECRET | `FLAG+01dc_f3d3r4t10n_cl0ud_cr3ds_3xch4ng3d_4ws_gcp_4zur3+` | OIDC id_tokens exfiltration + cloud credential exchange |
| 41 | 400 | compliance-scanner | COMPLIANCE_SECRET | `FLAG+4rt1f4ct_r3p0rt_sp00f3d_s4r1f_cl34n_r34l_bugs_h1dd3n+` | Inject clean SARIF to suppress real findings |
| 42 | 300 | microservice-build | BUILD_SECRET | `FLAG+1m4g3_p01s0n_s3rv1c3_c0mm4nd_c0nt41n3r_h1j4ck3d+` | image:name override + services:command injection |
| 43 | 300 | load-test-runner | LOAD_SECRET | `FLAG+p4r4ll3l_m4tr1x_cr3d_sw33p_c0mb1n4t0r14l_3xpl0d3+` | parallel:matrix combinatorial credential path sweep |

### Track 3: Advanced Supply Chain (lab9-16.md)

Entry point: cicd-bot PAT. 4 flags, 1800 pts.

| ID | Pts | Repo | CI Variable | Flag Value | Technique |
|----|-----|------|-------------|------------|-----------|
| 44 | 400 | bootstrap-runner | BOOTSTRAP_SECRET | `FLAG+pr3_g3t_s0urc3s_h00k_b3f0r3_g1t_f3tch_pwn3d+` | hooks:pre_get_sources_script injection (runs before git fetch) |
| 45 | 400 | build-cache-manager | CACHE_MGR_SECRET | `FLAG+c4ch3_k3y_pr3f1x_p01s0n_sh4r3d_c4ch3_1nj3ct3d+` | cache:key:prefix + cache:key:files manipulation |
| 46 | 500 | release-orchestrator | RELEASE_ORCH_SECRET | `FLAG+tr1gg3r_4rt1f4ct_ch1ld_p1p3l1n3_dyn4m1c_1nj3ct3d+` | trigger:include:artifact child pipeline injection |
| 47 | 500 | shared-artifacts | SHARED_ART_SECRET | `FLAG+n33ds_pr0j3ct_cr0ss_4rt1f4ct_supply_ch41n_pwn3d+` | needs:project cross-project artifact dependency injection |

## Repo Specifications

Each repo follows the standard pattern: `create_ctf_project` with `.gitlab-ci.yml` + README, `ctf_add_variable` for secrets, `add_project_member` for cicd-bot access.

### Flag 35: shared-ci-templates

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `TEMPLATE_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Includes a remote URL with `cache: "1h"`. A build job references the cached template. The flag is a masked CI variable extractable by poisoning the cached remote include to exfiltrate env vars.

```yaml
include:
  - remote: https://gitlab.local:8929/root/ci-templates/-/raw/main/build-template.yml
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
```

**Solution**: Use `gogatoz attack --payload-only --payload remote-include-cache` to generate a poisoned include config. Commit a `.gitlab-ci.yml` that caches the attacker-controlled remote URL. The cached template persists across pipelines, allowing env dump of `TEMPLATE_SECRET`.

### Flag 36: monorepo-platform

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `PLATFORM_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `workflow:rules:variables` to set build configuration. MR-triggered pipelines inherit workflow-level variables that can be overridden.

```yaml
workflow:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload workflow-vars` to generate a config that overrides `NPM_CONFIG_REGISTRY` at the workflow level. Commit CI that sets workflow:rules:variables to redirect the registry to an attacker-controlled endpoint, exfiltrating `PLATFORM_SECRET` via the hijacked install step.

### Flag 37: component-library

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `COMPONENT_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `include:` with `inputs:` for a CI component. The input values are interpolated before pipeline merge.

```yaml
include:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload spec-inputs` to craft input values containing YAML metacharacters that break out of interpolation. The injected payload exfiltrates `COMPONENT_SECRET`.

### Flag 38: secure-pipeline

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `SCAN_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Has SAST and secret detection jobs with `rules:changes` and `rules:exists` conditions. An attacker can modify the rules to suppress scanning.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload rules-bypass` to generate rules that suppress the security jobs while adding an attacker job. Commit CI that replaces the `sast` and `secret_detection` rules with nonexistent paths, then add a job that exfiltrates `SCAN_SECRET`.

### Flag 39: deploy-orchestrator

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `DEPLOY_RACE_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Multi-stage pipeline where a critical setup job is marked `interruptible: true`. An attacker can trigger a new pipeline to cancel the setup, then exploit the on_failure fallback.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload interruptible` to generate a pipeline that marks setup as interruptible and adds an on_failure fallback. Commit CI where the fallback job captures partial credentials from the interrupted setup, exposing `DEPLOY_RACE_SECRET`.

### Flag 40: cloud-deployer

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `CLOUD_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `id_tokens:` for OIDC federation with a cloud provider. MR-triggered jobs expose the OIDC token.

```yaml
stages:
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
    - echo "Deploying to cloud"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

**Solution**: Use `gogatoz attack --payload-only --payload oidc-federation --oidc-provider gcp` to generate a payload that captures the OIDC token and exchanges it for cloud credentials. The MR-triggered `cloud-auth` job exposes `GITLAB_OIDC_TOKEN`, which can be used to exfiltrate `CLOUD_SECRET`.

### Flag 41: compliance-scanner

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `COMPLIANCE_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Produces security report artifacts that feed GitLab's security dashboard. No real scanner is invoked.

```yaml
stages:
  - scan
  - report

security-scan:
  stage: scan
  tags: [shell_executor]
  script:
    - echo "Running compliance checks..."
    - echo '{"version":"2.1.0","runs":[]}' > gl-sast-report.json
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
```

**Solution**: Use `gogatoz attack --payload-only --payload artifact-reports` to generate a malicious SARIF report that suppresses all findings. Commit CI that replaces the security-scan job with one that produces a clean report while exfiltrating `COMPLIANCE_SECRET`.

### Flag 42: microservice-build

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `BUILD_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `services:` with container images. The service configuration is modifiable via MR.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload image-poison` to generate a config that overrides the service container commands. Commit CI with `services:command` pointing to an attacker script that exfiltrates `BUILD_SECRET`.

### Flag 43: load-test-runner

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `LOAD_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `parallel:matrix` for combinatorial test execution across environments.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload parallel-matrix` to generate a matrix sweep that targets credential paths. Commit CI with `parallel:matrix` variables pointing to sensitive file paths, sweeping credentials across parallel instances. One instance captures `LOAD_SECRET`.

### Flag 44: bootstrap-runner

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `BOOTSTRAP_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `hooks:pre_get_sources_script` to run initialization before Git fetches sources.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload pre-get-sources` to inject code into the pre_get_sources_script hook. This runs before any Git operations, allowing credential capture and exfiltration of `BOOTSTRAP_SECRET`.

### Flag 45: build-cache-manager

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `CACHE_MGR_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses structured `cache:key:prefix` + `cache:key:files` for dynamic cache key generation.

```yaml
stages:
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
```

**Solution**: Use `gogatoz attack --payload-only --payload cache-key-poison` to inject a job that manipulates the cache key prefix and poisons the shared cache. The poisoned cache contains a script that exfiltrates `CACHE_MGR_SECRET` on the next build.

### Flag 46: release-orchestrator

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `RELEASE_ORCH_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `trigger:include:artifact` to generate dynamic child pipeline configs.

```yaml
stages:
  - generate
  - release

generate-config:
  stage: generate
  tags: [shell_executor]
  script:
    - echo "Generating release pipeline config"
    - |
      cat > release-pipeline.yml << 'EOF'
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
```

**Solution**: Use `gogatoz attack --payload-only --payload trigger-artifact` to inject a job that writes a malicious child pipeline YAML as an artifact. The trigger job executes the attacker-controlled pipeline, which exfiltrates `RELEASE_ORCH_SECRET`.

### Flag 47: shared-artifacts

**Visibility**: public
**Members**: cicd-bot (Developer, 30)
**CI Variables**: `SHARED_ART_SECRET` (masked, unprotected)

**`.gitlab-ci.yml`**: Uses `needs:project` to pull artifacts from a cross-project dependency.

```yaml
stages:
  - build

build:
  stage: build
  tags: [shell_executor]
  needs:
    - project: root/component-library
      job: build
      ref: main
      artifacts: true
  script:
    - echo "Building with shared artifacts"
    - ls -la || echo "No artifacts pulled"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

**Solution**: Use `gogatoz attack --payload-only --payload needs-project` to generate a config that pulls artifacts from an attacker-controlled project. Commit CI that references a compromised source project, injecting malicious build scripts that exfiltrate `SHARED_ART_SECRET`.

## Documentation Updates

### New Lab Pages

| File | Title | Sidebar Label |
|------|-------|---------------|
| `lab9-14.md` | Lab 9.14: Include & Workflow Abuse | Include & Workflow Abuse |
| `lab9-15.md` | Lab 9.15: Cloud & Container Federation | Cloud & Container Federation |
| `lab9-16.md` | Lab 9.16: Advanced Supply Chain II | Advanced Supply Chain II |

Each page follows the existing CTF track template: scoring table, mermaid diagram, stages with objectives/hints/spoilers, scoreboard, key takeaways.

### Existing Pages to Update

1. **gogatoz-setup.md**: Add 13 repos to "Complete Repo Reference" table and "CTF Repos" table. Add 3 tracks to "CTF Tracks" summary table.
2. **lab9-7.md**: Add Flags 35-47 to master scoring table. Add 3 new tracks to scoreboard. Update total flag count (47) and point total (18650).
3. **lab9-1.md**: Add new finding IDs to vulnerability classification diagram and "Build an Attack Plan" table.
4. **astro.config.mjs**: Add 3 new sidebar entries under "GitLab CI/CD Exploitation (GoGatoZ)".

## Verification

Each new challenge is validated by:

1. Lab boots successfully with `docker compose up`
2. `setup-lab.sh` completes without errors
3. Each repo is created with correct CI config and variables
4. `gogatoz enumerate` detects the corresponding finding ID
5. `gogatoz attack --payload-only --payload <name>` generates valid YAML
6. The attack payload, when committed, successfully exfiltrates the flag
7. Flag submission to flagserver succeeds
8. Documentation builds without errors (`npm run build` in docs site)
