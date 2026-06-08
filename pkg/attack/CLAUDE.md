# pkg/attack

Exploitation and persistence modules for GoGatoZ. Provides CI pipeline injection, secrets exfiltration with RSA encryption, persistence mechanisms (deploy keys, project members, MR pipelines), runner-on-runner targeting, and C2 session orchestration. Designed for security practitioners to exploit GitLab CI/CD misconfigurations discovered during enumeration.

## Files

**Root package (`pkg/attack/`):**

| File | Purpose |
|------|---------|
| `attacker.go` | Core `Attacker` struct wrapping GitLab client; branch management, file ops, pipeline commits |
| `constants.go` | `GogatozAttacks = "gogatoz-attack"` default branch name |
| `pushci.go` | `PushCI` wrapper for push-triggered pipeline generation |
| `secrets.go` | `SecretsAttack` wrapper for secrets enumeration and exfiltration with optional RSA encryption |
| `persistence.go` | `Persistence` wrapper for deploy keys (RSA 2048), project members, MR-triggered pipelines |
| `webshell.go` | `WebShell` wrapper for manual job-triggered web shells |
| `webshell_utils.go` | Utilities: `ISOTimeNow()`, `PollWithTimeout()`, `WaitForPipelineForRef()`, `WaitForJobCompletion()` |
| `lotp.go` | `LOTPAttack` wrapper; `InjectLOTPPayload()` reads+commits weaponized config files to a branch |

**Subdirectories:**

| Directory | Files | Purpose |
|-----------|-------|---------|
| `payloads/` | `payloads.go`, `payloads_test.go`, `infostealer.go`, `infostealer_test.go`, `lotp.go`, `lotp_test.go` | YAML payload generators: RoR Shell, Pwn Request, Runner-on-Runner, Secrets Exfil, Git Hook, Cache Poison; LOTP config-file payload generators: Phantom Gyp (binding.gyp+index.js), npm, Make, pytest, goreleaser, gradle, terraform; Infostealer shell script |
| `c2/` | `controller.go`, `controller_test.go` | C2 session orchestration with branch deconflict strategies (fail/force/suffix) |
| `ror/` | `ror.go` | Runner discovery and tag filtering by executor heuristics |
| `secretsdump/` | `secretsdump.go`, `artifacts.go`, `logs.go`, `consts.go`, `logs_test.go` | Variable enumeration, ZIP artifact scraping, job log scraping for secrets |
| `scriptinject/` | `extract.go`, `extract_test.go`, `inject.go`, `inject_test.go` | Script injection: extract external script refs from CI YAML, prepend/append payloads to repo scripts (workflow hopping) |
| `tamper/` | `release.go`, `release_test.go`, `package.go`, `package_test.go`, `tag.go`, `tag_test.go` | Release/package/tag tampering: modify release metadata/links, upload malicious packages via Generic Packages API, Trivy-style tag poisoning (swap file in tagged commit, clone metadata, re-point tag) |

## Exported API (Key Items)

**Types:** `Attacker`, `PushCI`, `SecretsAttack`, `Persistence`, `WebShell`, `LOTPAttack`, `LOTPResult` (root); `CommonOptions`, `RORShellOptions`, `PwnRequestOptions`, `RunnerOnRunnerOptions`, `SecretsExfilOptions`, `InfostealerOptions` (payloads); `Controller`, `StartOptions` (c2); `RunnerSummary` (ror); `Variable`, `ArtifactFinding`, `Finding` (secretsdump); `GitHookOptions`, `CachePoisonOptions` (payloads); `ScriptRef` (scriptinject); `TamperReleaseOptions`, `ReleaseInfo`, `LinkInfo`, `PackageResult`, `TamperTagOptions`, `TamperTagResult`, `TagCommitInfo` (tamper); `AutoMergeResult`, `ApprovalStatus` (persistence); `SharedRunnerInfo` (ror)

**Key Functions:**

- `NewAttacker(gl, baseURL, authorName, authorEmail, timeout)` -- constructor
- `NewLOTPAttack(att)` -- wraps Attacker for LOTP config-file injection
- `LOTPAttack.InjectLOTPPayload(ctx, projectID, branch, tool, cmd)` -- generates and commits weaponized config files to branch; returns LOTPResult
- `payloads.GenerateLOTPPayload(tool, cmd)` -- returns LOTPPayload (tool, files, description, reference); tools: npm-gyp/gyp, npm, make, pytest, goreleaser, gradle, terraform
- `payloads.KnownLOTPTools` -- []string of all supported LOTP tool identifiers
- `Attacker.CommitCIPipeline(ctx, projectID, branch, yaml, message)` -- commit CI pipeline
- `Attacker.EnsureBranch/UpsertFile/DeleteBranch/SetupUser` -- repo operations
- `Attacker.EraseJob(ctx, projectID, jobID)` -- erase job trace (anti-forensics)
- `Attacker.DeletePipeline(ctx, projectID, pipelineID)` -- delete pipeline (anti-forensics)
- `Attacker.EraseRecentPipelines(ctx, projectID, ref, max, delete)` -- bulk erase recent pipeline job traces
- `Attacker.TriggerPipeline(ctx, projectID, ref)` -- trigger pipeline on ref
- `Attacker.GetFileContent(ctx, projectID, ref, path)` -- fetch file content from repo
- `PushCI.GeneratePushCI(branch, jobName, payload, tags)` -- generate push-triggered YAML
- `SecretsAttack.RunExfil(ctx, projectID, branch, pubkey, tags)` -- run secrets exfil pipeline
- `Persistence.CreateDeployKey/AddProjectMemberByUsername/RunMRPwn` -- persistence methods
  - CLI flags: `--deploy-key` + `--key-path`/`--key-title` → `CreateDeployKey`; `--add-member` + `--member-username`/`--member-role` → `AddProjectMemberByUsername`; `--commit-ci --payload pwn-request` → `RunMRPwn` (via `GenerateMRPwnCI`)
- `Persistence.RunAutoMerge(ctx, projectID, branch, file, content, msg, title, desc, target)` -- create MR, self-approve, merge
- `WebShell.GenerateWebShellCI(jobName, tags, shell, downloadPath)` -- manual job shell
- `c2.NewController(att).StartSession(ctx, opts)/StopSession(ctx, projectID, branch, removeCI)` -- C2 lifecycle
- `ror.DiscoverProjectRunnerTags(ctx, client, projectID)` -- runner tag discovery
- `ror.DiscoverGroupRunnerSharing(ctx, client, groupID)` -- find runners shared across group projects
- `secretsdump.ScrapeArtifacts/ScrapeJobLogs` -- secrets extraction from artifacts and logs
- `payloads.GenerateGitHookYAML(opts)` -- git hook installation payload
- `payloads.GenerateCachePoisonYAML(opts)` -- cache poisoning payload
- `scriptinject.ExtractScriptRefs(doc)` -- find external script references in CI YAML
- `scriptinject.PrependPayload/AppendPayload(original, payload)` -- inject payload into script
- `tamper.TamperRelease(ctx, client, projectID, tag, opts)` -- modify release metadata and links
- `tamper.PublishPackage(ctx, client, projectID, name, ver, fileName, reader)` -- upload package
- `tamper.TamperTag(ctx, client, projectID, opts)` -- Trivy-style tag poisoning: swap file in tagged commit, clone metadata, re-point tag
- `tamper.GetTagCommit(ctx, client, projectID, tagName)` -- fetch tag's commit metadata (author, email, message, SHA)
- `payloads.GenerateInfostealerScript(opts)` -- generate infostealer shell script (env dump, credential sweep, network enum, compression, encryption, exfil)

## Internal Patterns

- **Wrapper pattern**: PushCI, SecretsAttack, Persistence, WebShell embed `*Attacker` via anonymous field
- **Interface for testability**: c2 Controller uses `repo` interface (4 methods) satisfied by Attacker and test fakes
- **Deconflict strategies**: C2 branch naming -- "fail" (error if exists), "force" (delete+recreate), "suffix" (append -1, -2, etc. up to 99)
- **Best-effort scraping**: ScrapeArtifacts/ScrapeJobLogs tolerate per-item failures, cap at 500 findings
- **Payload generators**: Pure functions using options structs; tested by parsing output with `pipeline.Parse()`

## Testing

- `attacker_test.go` -- constructor validation
- `webshell_utils_test.go` -- utility functions with mock HTTP servers
- `c2/controller_test.go` -- fake repo mock + full lifecycle tests
- `payloads/payloads_test.go` -- table-driven YAML parse validation per generator
- `secretsdump/logs_test.go` -- HTTP mock server testing log scraping
- `scriptinject/extract_test.go` -- table-driven tests for script reference extraction
- `scriptinject/inject_test.go` -- prepend/append payload injection tests
- `tamper/release_test.go` -- httptest mock for release tampering
- `tamper/package_test.go` -- httptest mock for package publishing

## Dependencies

**Imports:**

- `pkg/gitlabx` -- GitLab API client (used by Attacker, ror, secretsdump, webshell_utils)
- `pkg/pipeline` -- YAML validation in payload tests only

**Depended on by:**

- `pkg/enumerate` -- imports `attack/secretsdump` for log scraping

## Gotchas

1. **EnsureBranch defaults to "main"** if project has no DefaultBranch
2. **UpsertFile is try-update-then-create** -- only falls back to create on 404
3. **DeployKey always sets CanPush: true** (write access for persistence)
4. **Access level defaults to Developer** for unknown/empty strings
5. **C2 forces Manual: true** regardless of caller input
6. **Pipeline URL built before pipeline exists** -- callers should poll with `WaitForPipelineForRef()`
7. **Findings capped at 500** in ScrapeArtifacts/ScrapeJobLogs (global, not per-pipeline)
8. **Runner tag filtering is heuristic** -- matches executor name in tag string (case-insensitive)
9. **GenerateExfilCI YAML must use double-quoted strings** -- backtick strings with `\n` produce literal backslash-n characters which GitLab stores as-is, producing unparseable YAML. Always use `fmt.Sprintf("...\n...")` not backtick strings for CI YAML generation.
10. **Heredocs (`<<'PY'`) break GitLab CI YAML parser** -- GitLab silently rejects the YAML (pipeline created with 0 jobs, no yaml_errors). Use `python3 -c` one-liners instead.
11. **Tags indentation is 2-space (job-level)** -- `tags:` must align with `stage:`, `script:`, `artifacts:`. Using 4-space indent nests it under the previous key's value, producing invalid YAML.
12. **Protected variables require protected branches** -- `MY_SECRET` (or any protected CI variable) is only injected into pipelines running on protected branches. To exfiltrate protected secrets, the target branch must be protected before the pipeline runs.
13. **`--deconflict force` creates two pipelines** -- branch deletion + recreation triggers one pipeline with stale YAML, then the file commit triggers a second with the new YAML. Always check the LATEST pipeline on the branch, not the first one seen.
14. **GenerateExfilCI uses python3 → python2 → shell fallback** -- shell runners (Alpine, minimal images) may lack Python. The fallback chain in `secrets.go` uses `command -v python3`, then `python`, then pure shell (`printenv` + `sed` + `printf`).
15. **Auto-merge may fail silently** -- GitLab requires different users for MR author and approver. Self-approve only works if approval rules permit it (0-1 required approvers, no code owner requirement).
16. **EraseJob vs DeletePipeline** -- EraseJob removes the job trace/log only; DeletePipeline removes the entire pipeline. Use EraseRecentPipelines for bulk cleanup.
