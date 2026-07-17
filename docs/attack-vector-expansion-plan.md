# Plan: New GoGatoZ Attack Vectors Based on GitLab CI/CD YAML Research

## Context

This plan identifies gaps between GoGatoZ's current attack capabilities and the GitLab CI/CD YAML attack surface. Research was based on the complete GitLab Docs CI/CD YAML syntax reference (v19.3), covering 160+ sections across ~600KB of documentation.

## Current Attack Module Inventory (28+ modules)

| Module | File(s) | Mechanism |
|--------|---------|-----------|
| ROR Shell | `payloads.go` | Webshell command execution |
| Pwn Request | `payloads.go` | MR description code execution |
| Runner-on-Runner | `payloads.go` | Remote script fetch+exec |
| Secrets Exfil | `secrets.go` + `infostealer.go` | RSA-encrypted credential harvesting |
| Infostealer | `infostealer.go` | Comprehensive file sweep (100+ paths) |
| LOTP Config Files | `lotp.go` | npm-gyp/npm/make/pytest/goreleaser/gradle/terraform |
| Container Escape | `container_escape.go` | Docker socket/cgroup/kernel escape |
| C2 Covert Channels | `c2_channels.go` | DNS tunnel, WAV/PNG steg, ICMP |
| Supply Chain Worm | `supplychain_worm.go` | Cross-repo self-propagation |
| Script Injection | `scriptinject/` | External script prepend/append |
| Release Tamper | `release.go` + `release_pipeline.go` | Release artifact/metadata modification |
| Package Tamper | `package.go` | Generic Packages API upload |
| Tag Poisoning | `tag.go` | Trivy-style tag repointing |
| Variable Injection | `variable_injection.go` | Group/project/template variable injection |
| Dead Man's Switch | `deadmanswitch.go` | Token revocation monitoring (systemd/LaunchAgent) |
| Sigstore Forgery | `sigstore.go` | SLSA attestation forging via Fulcio+Rekor |
| K8s Secrets Sweep | `k8s_secrets.go` | Kubernetes API secret enumeration |
| Vault Enum | `vault_enum.go` | HashiCorp KV mount enumeration |
| NPM Tamper | `npm_tamper.go` | npm preinstall hook injection |
| Workflow Exfil | `workflow_exfil.go` | Stealth variable exfiltration |
| Commit Prefix | `commit_prefix.go` | Release-triggering commit messages |
| Branch Mutator | `branchmutator.go` | Cross-branch file mutation |
| Runner Var Dump | `runner_var_dump.go` | /proc/environ variable dumping |
| Persistence | `persistence.go` | Deploy keys, members, MR pipelines, auto-merge |
| WebShell | `webshell.go` | Manual job-triggered shell |
| C2 Controller | `c2/controller.go` | Session orchestration |
| Memory Dump | `memorydump.go` | /proc/<pid>/mem extraction |
| Git Hook | `payloads.go` | git hooks installation |
| Tamper Release/Pkg/Tag | `tamper/` | API-based release/package/tag tampering |

## Priority Attack Vectors (by impact / effort ratio)

---

### V1: Remote Include Cache Poisoning (P0)

**Why:** GitLab 19.0 added `include:cache` for remote includes (1hr default TTL). An attacker who can control the remote content or the include URL can poison the cache, affecting all pipelines that use it. Currently GoGatoZ has NO module targeting this.

**Attack Flow:**
1. Inject a remote include with `cache: true` or `cache: '1h'` into target CI config
2. The attacker controls the remote endpoint (or uses SSRF if target hits attacker-controlled URL)
3. Remote content caches for TTL — all subsequent pipelines use poisoned config
4. Include the attacker's malicious payload in the cached remote content

**Implementation:**
- New file: `pkg/attack/payloads/remote_include_cache.go`
- `GenerateRemoteIncludeCacheYAML(opts RemoteIncludeCacheOptions) string`
- Options: `RemoteURL`, `CachedPayload` (the YAML content to cache), `CacheTTL`, `InjectAt` (inject before/after specific stage)
- The payload itself is a remote include with a malicious payload embedded in the cached content
- Integration into existing attack pipeline (similar to how supplychain_worm.go integrates)

---

### V2: OIDC ID Token Exfiltration via Cloud Federation (P0)

**Why:** GitLab supports `id_tokens` keyword with OIDC tokens for cloud provider federation (AWS, GCP, Azure). The docs show the token can be requested via the CI/CD job JWT. GoGatoZ's sigstore module handles Sigstore but has NO module for cloud provider OIDC token abuse. This is a major gap — OIDC tokens can be exchanged for cloud credentials.

**Attack Flow:**
1. Target CI job uses `id_tokens:` with an OIDC token configuration
2. Exfiltrate the OIDC token (it's available in the CI environment)
3. Exchange the OIDC token for cloud provider credentials (AWS STS, GCP workload identity, Azure Federated Identity)
4. Use obtained cloud credentials for further access

**Implementation:**
- New file: `pkg/attack/payloads/oidc_federation.go`
- `GenerateOIDCFederationYAML(opts OIDCFederationOptions) string`
- Options: `Provider` ("aws", "gcp", "azure"), `Audience`, `RoleARN`, `CallbackURL`
- The payload requests the OIDC token, then exchanges it via cloud provider APIs
- For AWS: exchange via STS WebIdentityAssumeRole
- For GCP: exchange via Google workload identity JWT token endpoint
- For Azure: exchange via Azure AD federated identity
- Return exfiltrated cloud credentials

---

### V3: pre_get_sources_script Injection (P1)

**Why:** GitLab supports `hooks:pre_get_sources_script` — a hook that runs BEFORE Git fetches sources. This is a critical pre-repository-extraction hook where an attacker can inject malicious scripts that execute before any legitimate code is available on the runner. GoGatoZ has no coverage of this attack surface.

**Attack Flow:**
1. Inject `hooks:` with a `pre_get_sources_script` into the CI config
2. This hook runs before Git fetches the repository, potentially before any legitimate CI logic
3. Can install backdoors, modify the Git fetch behavior, or extract credentials before the legitimate pipeline starts

**Implementation:**
- New file: `pkg/attack/payloads/pre_get_sources.go`
- `GeneratePreGetSourcesYAML(opts PreGetSourcesOptions) string`
- Options: `HookScript` (custom hook content), `InjectAfterGit` (whether to hook after initial fetch)
- The payload injects a pre_get_sources_script that runs arbitrary commands before source retrieval
- Stealth: can modify the git fetch URL to pull attacker-controlled code instead

---

### V4: workflow:rules:variables Injection (P1)

**Why:** GitLab supports `workflow:rules:variables` which allows conditional variable definition at the workflow level, executed BEFORE any job runs. This is more powerful than job-level variables because it affects ALL jobs. GoGatoZ has variable injection but NO workflow-level rules-based variable injection.

**Attack Flow:**
1. Inject `workflow:rules:variables` with conditions that trigger on pipeline source types (merge requests, pushes, schedules)
2. Conditionally set high-precedence workflow variables (e.g., override CI/CD variables used by all jobs)
3. All subsequent jobs inherit these malicious variables

**Implementation:**
- New file: `pkg/attack/payloads/workflow_rules_vars.go`
- `GenerateWorkflowRulesVarsYAML(opts WorkflowRulesVarsOptions) string`
- Options: `Rules` (conditional rules), `Variables` (key-value pairs to inject), `WorkflowName`
- The payload uses `workflow:` with `rules:` and `variables:` to inject variables conditionally
- Can target specific pipeline sources (merge_request_event, push, schedule, API)
- Can inject into workflow-level variables that override all job variables

---

### V5: Cache Key Prefix Injection (P1)

**Why:** GitLab supports `cache:key:prefix` and `cache:key:files` / `cache:key:files_commits` for dynamic cache key generation. An attacker who controls the cache key can poison the shared cache, affecting sibling projects or future builds. Currently GoGatoZ has cache poisoning via `cache:paths` but not cache key manipulation.

**Attack Flow:**
1. Inject a job with a custom `cache:key` using `cache:key:prefix` with attacker-controlled values
2. Sibling projects using the same cache key prefix share the poisoned cache
3. Future builds pull malicious artifacts/files from the poisoned cache
4. Can use `cache:key:files` or `cache:key:files_commits` to make the cache key depend on attacker-controlled content

**Implementation:**
- New file: `pkg/attack/payloads/cache_key_poison.go`
- `GenerateCacheKeyPoisonYAML(opts CacheKeyPoisonOptions) string`
- Options: `KeyPrefix`, `CachePaths`, `PoisonPaths`, `Scope` ("project", "group", "all")
- The payload sets a cache:key with attacker-controlled prefix + paths
- Can poison the cache with malicious files that get picked up by other builds
- Can use `cache:policy` to control upload/download behavior for maximum impact

---

### V6: spec:inputs Interpolation Injection (P1)

**Why:** GitLab's `spec:inputs` system uses `$[[ inputs.input-id ]]` interpolation format evaluated BEFORE the pipeline configuration is merged. If an attacker can control input values (via `include:inputs`), they can inject arbitrary YAML. GoGatoZ has `include:inputs` documentation but NO attack module targeting spec:inputs injection.

**Attack Flow:**
1. Compromise a project that uses `spec:inputs` in included configurations
2. Inject malicious values via `include:inputs` that, when interpolated, alter the pipeline structure
3. Use YAML injection (e.g., `value: "malicious: [value]"` or block scalars) to inject arbitrary CI keys
4. Inject code execution, variable override, or include manipulation

**Implementation:**
- New file: `pkg/attack/payloads/spec_inputs_injection.go`
- `GenerateSpecInputsInjectionYAML(opts SpecInputsOptions) string`
- Options: `InputKey`, `MaliciousValue`, `InterpolationTarget` (spec:inputs field)
- Payloads: YAML injection via block scalar, key injection via interpolated string, value injection via multiline
- The payload demonstrates how to craft `include:inputs` values that break out of the interpolation context
- Can inject `script:`, `image:`, `include:`, or other CI keywords through interpolation

---

### V7: Trigger Include Artifact/Dynamic Child Pipeline Poisoning (P1)

**Why:** GitLab supports `trigger:include:artifact` for triggering dynamic child pipelines (fetch from artifacts instead of repository). This is distinct from `trigger:include:local` and `trigger:include:project`. GoGatoZ has basic `trigger` support but NO module targeting artifact-based child pipelines.

**Attack Flow:**
1. Inject a job that builds a malicious `.gitlab-ci.yml` and stores it as an artifact
2. A downstream `trigger:include:artifact` job pulls this malicious CI config from the artifact
3. Executes the attacker-controlled pipeline in the child project
4. Chain this across multiple projects via artifact passing

**Implementation:**
- New file: `pkg/attack/payloads/trigger_artifact.go`
- `GenerateTriggerArtifactYAML(opts TriggerArtifactOptions) string`
- Options: `MaliciousCIPath`, `ArtifactName`, `TriggerProject`, `TriggerBranch`
- Stage 1: Job that writes malicious YAML and uploads as artifact
- Stage 2: Trigger job using `trigger:include:artifact` to pull and execute
- Can chain with variable injection to control the child pipeline behavior

---

### V8: Parallel Matrix Combinatorial Attack (P1)

**Why:** GitLab supports `parallel:matrix` for combinatorial job execution (e.g., N x M = N*M jobs). An attacker can abuse this to create hundreds/thousands of jobs from a single injection point, causing resource exhaustion and increasing the surface for credential extraction across multiple parallel executions.

**Attack Flow:**
1. Inject a `parallel:matrix` job that spawns many parallel credential-extraction instances
2. Each parallel instance independently sweeps different credential paths
3. Massive parallel exfiltration overwhelms the ability to detect individual exfil events
4. Can also use for brute-force attacks (token validation, rate-limited API calls)

**Implementation:**
- New file: `pkg/attack/payloads/parallel_matrix.go`
- `GenerateParallelMatrixYAML(opts ParallelMatrixOptions) string`
- Options: `MatrixKeys` (key-value pairs for combinatorial expansion), `Script` (per-iteration command)
- The payload creates a parallel:matrix job with combinatorial execution
- Can target different credential paths per parallel instance
- Can be used for brute-force (matrix of API keys, tokens, etc.)

---

### V9: Artifact Reports Injection (P1)

**Why:** GitLab supports `artifacts:reports` with multiple report types: `dependency_scanning`, `sarif`, `secret_scanning`, `sast`, `dast`, `license_management`, `container_scanning`, `coverage_fuzzing`. These reports can influence GitLab's security dashboard and merge request UI. GoGatoZ has NO coverage of artifact report manipulation.

**Attack Flow:**
1. Inject a job that produces a malicious SARIF/dependency scanning report
2. The report creates false positives that hide real vulnerabilities or suppress security alerts
3. Can also use reports to create false sense of security (hiding malicious dependencies)
4. SARIF reports are especially dangerous as they can suppress real findings

**Implementation:**
- New file: `pkg/attack/payloads/artifact_reports.go`
- `GenerateArtifactReportsYAML(opts ArtifactReportsOptions) string`
- Options: `ReportType` (sarif, dependency_scanning, secret_scanning), `Payload` (report content)
- Generates valid SARIF/dependency scanning JSON that suppresses real findings
- Can inject false-positive reports to hide GoGatoZ's own activities
- Can also use to create noise that drowns out genuine security alerts

---

### V10: image:name / services:command Container Image Poisoning (P2)

**Why:** GitLab supports `image:name` with variable expansion and `services:command` for injecting custom commands into service containers. An attacker can override the image or service commands to redirect builds to malicious registries or inject code into service containers.

**Attack Flow:**
1. Inject `image:name` pointing to a malicious image (or use variable expansion to redirect)
2. Inject `services:command` to run malicious commands in service containers
3. Can also inject `services:variables` to poison service environment

**Implementation:**
- New file: `pkg/attack/payloads/image_poison.go`
- `GenerateImagePoisonYAML(opts ImagePoisonOptions) string`
- Options: `MaliciousImage`, `ServiceCommand`, `ServiceVariables`
- Can override `image:name` to pull from attacker-controlled registry
- Can inject `services:command` to run arbitrary commands in service containers
- Can use variable expansion (`$CI_VARIABLE_NAME`) to make the attack conditional

---

### V11: rules:changes / rules:exists Git Operations (P2)

**Why:** `rules:changes` and `rules:exists` can control whether jobs run based on file existence or changes. An attacker can inject rules that prevent legitimate security jobs from running (e.g., security scanning, DAST) while allowing attacker-controlled jobs to run.

**Attack Flow:**
1. Inject `rules:exists` with paths that only match attacker-controlled files
2. This effectively blocks legitimate security scanning jobs (they don't match the rules)
3. Meanwhile, attacker's malicious jobs have `rules:changes` that match their injected files
4. Creates a blind spot where security jobs are silently skipped

**Implementation:**
- New file: `pkg/attack/payloads/rules_bypass.go`
- `GenerateRulesBypassYAML(opts RulesBypassOptions) string`
- Options: `BypassedJobs` (list of job names to suppress), `MatchPaths` (paths for attacker jobs)
- Injects rules that selectively bypass security scanning jobs
- Can use `rules:exists` to only run on attacker-controlled file paths
- Can suppress DAST, SAST, dependency scanning, and secret scanning jobs

---

### V12: Interruptible Job State Loss (P2)

**Why:** GitLab supports `interruptible: true` which cancels the previous instance of a job when a new pipeline runs. An attacker can inject `interruptible` to cause state loss — e.g., interrupt a key setup job before it completes, causing the pipeline to run with incomplete initialization.

**Attack Flow:**
1. Inject `interruptible: true` on critical setup jobs
2. When attacker triggers a new pipeline, the previous job is interrupted
3. If the setup job was installing dependencies or initializing credentials, interruption causes failure
4. Can be combined with a fallback job that runs attacker-controlled code when setup fails

**Implementation:**
- New file: `pkg/attack/payloads/interruptible_attack.go`
- `GenerateInterruptibleAttackYAML(opts InterruptibleOptions) string`
- Options: `TargetJobs` (jobs to make interruptible), `FallbackScript` (run when interrupted)
- Injects `interruptible: true` on critical jobs
- Combines with a fallback that runs when the interrupted job fails

---

### V13: Dependency Pwnage via needs:project / needs:pipeline (P2)

**Why:** GitLab supports `needs:project` for cross-project artifact dependency and `needs:pipeline` for pipeline-level dependency. An attacker can inject a `needs:project` that pulls artifacts from a compromised project, injecting malicious files into the build without any CI config change in the target project.

**Attack Flow:**
1. Inject `needs:project` referencing a compromised project's artifacts
2. The target project pulls attacker-controlled files as build artifacts
3. This bypasses all CI config analysis since the attacker didn't modify the target's `.gitlab-ci.yml`
4. Can also use `needs:pipeline` for cross-pipeline artifact injection

**Implementation:**
- New file: `pkg/attack/payloads/needs_project.go`
- `GenerateNeedsProjectYAML(opts NeedsProjectOptions) string`
- Options: `SourceProject`, `SourcePipeline`, `ArtifactPaths` (what to pull), `DestinationStage`
- Injects a `needs:project` job that pulls from a compromised project
- The pulled artifacts contain attacker-controlled files (binaries, configs, scripts)
- Can also inject into `needs:artifacts` to control which artifacts are passed

---

## Summary of Planned Attacks

| # | Module | Priority | Impact | Effort | New File |
|---|--------|----------|--------|--------|----------|
| 1 | Remote Include Cache Poisoning | P0 | High | Low | `remote_include_cache.go` |
| 2 | OIDC ID Token Exfiltration | P0 | Critical | Medium | `oidc_federation.go` |
| 3 | pre_get_sources_script Injection | P1 | High | Low | `pre_get_sources.go` |
| 4 | workflow:rules:variables | P1 | High | Medium | `workflow_rules_vars.go` |
| 5 | Cache Key Prefix Poisoning | P1 | High | Low | `cache_key_poison.go` |
| 6 | spec:inputs Injection | P1 | Medium | Medium | `spec_inputs_injection.go` |
| 7 | Trigger Artifact Poisoning | P1 | High | Medium | `trigger_artifact.go` |
| 8 | Parallel Matrix Attack | P1 | Medium | Low | `parallel_matrix.go` |
| 9 | Artifact Reports Injection | P1 | Medium | Low | `artifact_reports.go` |
| 10 | Image/Service Poisoning | P2 | Medium | Low | `image_poison.go` |
| 11 | Rules Bypass | P2 | High | Low | `rules_bypass.go` |
| 12 | Interruptible State Loss | P2 | Medium | Low | `interruptible_attack.go` |
| 13 | needs:project Artifact Injection | P2 | High | Medium | `needs_project.go` |

## Recommended Implementation Order

1. **V2 OIDC Federation** (P0, critical impact, existing GoGatoZ patterns to follow)
2. **V3 pre_get_sources_script** (P1, straightforward YAML injection, high impact)
3. **V5 Cache Key Poisoning** (P1, small module, high impact on build integrity)
4. **V1 Remote Include Cache** (P0, leverages GitLab 19.0 feature)
5. **V9 Artifact Reports** (P1, small SARIF generator module)
6. **V4 workflow:rules:variables** (P1, workflow-level control)
7. **V11 Rules Bypass** (P2, stealth defense evasion)
8. **V6 spec:inputs Injection** (P1, YAML injection techniques)
9. **V7 Trigger Artifact** (P1, child pipeline attack)
10. **V12 Interruptible Attack** (P2, denial-of-service + state manipulation)
11. **V13 needs:project** (P2, cross-project artifact supply chain)
12. **V10 Image Poisoning** (P2, container image supply chain)
13. **V8 Parallel Matrix** (P1, resource exhaustion + brute force)
