---
title: Validate Command
description: Map GitLab token capabilities with read-only evidence
---

The `validate` command identifies a GitLab token and maps what it can safely be
shown to do. Every network probe is an HTTP GET. The command never pushes code,
creates a runner, starts a pipeline, changes a variable, rotates a token, or
otherwise modifies GitLab state.

## Usage

```bash
export GITLAB_TOKEN=glpat_xxx

# Instance-wide summary
gogatoz validate

# Machine-readable output
gogatoz validate --json

# Project-specific role and branch inference
gogatoz validate --target group/project --json
```

`--target`, or `-t`, accepts a numeric project ID or path with namespace.

## Status model

| Status | Meaning |
|---|---|
| `confirmed` | A read-only endpoint returned a successful response. |
| `inferred` | Declared scopes and observed roles or protection rules support the capability, but no mutation was attempted. |
| `denied` | GitLab returned 401/403, a required declared scope is absent, or the observed role is insufficient. |
| `unknown` | The endpoint or PAT self-introspection is unavailable, rate-limited, unsupported, or ambiguous. |

Each capability includes a confidence level and evidence. Keep the distinction
between `confirmed` and `inferred` when importing the JSON into another tool.

## Project-specific inference

With `--target`, GoGatoZ reads:

- project metadata and the token owner's effective project or group role;
- one repository-tree page to confirm repository visibility;
- one jobs page to confirm historical job visibility; and
- default-branch protection metadata.

It then infers repository push, protected-default-branch push, project
administration, and runner creation/management capabilities. Group-specific
protected-branch grants that cannot be resolved safely remain `unknown` rather
than being reported as available.

## Safety boundary

The command does not provide an active write-probe mode. If a security test
requires proof of a write operation, perform that separately against an
explicitly authorized disposable project and restore the changed state.
