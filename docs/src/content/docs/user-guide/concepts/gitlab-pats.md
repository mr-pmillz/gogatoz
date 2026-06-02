---
title: GitLab Personal Access Tokens (PATs)
description: How GoGatoZ uses GitLab PATs for authentication and required scopes
---

GoGatoZ uses the GitLab API to search projects, read pipeline files, and (optionally) perform attack/persistence operations in attack mode. Authentication is provided via a GitLab Personal Access Token (PAT).

## Required scopes

- api — required for most API interactions (projects, repository files, variables)
- read_repository — allows reading repositories (clone, read content)
- write_repository — only required for attack modules that push changes or create branches/merge requests

For enumeration/search only, api and read_repository are sufficient. Attack modules may need write_repository depending on the action.

## Creating a PAT

1. Sign in to your GitLab instance (e.g., https://gitlab.com).
2. Open your user menu -> Edit profile -> Access tokens (or navigate to: https://gitlab.com/-/user_settings/personal_access_tokens).
3. Name the token (e.g., gogatoz), select expiration, and select scopes:
   - api
   - read_repository
   - write_repository (only if you plan to use attack modules)
4. Create the token and copy it somewhere secure.

## Using the token with GoGatoZ

Environment variables (recommended):

```bash
export GITLAB_URL=https://gitlab.com
export GITLAB_TOKEN=glpat_xxx
```

CLI flags (override env and config file):

```bash
./gogatoz --gitlab-url https://gitlab.com --token glpat_xxx enumerate -i projects.txt --json
```

Config file (.gogatoz.yaml):

```yaml
gitlab-url: https://gitlab.com
token: glpat_xxx
```

Precedence: flags > environment > config file > defaults.

## Safety tips

- Use a separate PAT for scanning with the minimum required scopes.
- Prefer short-lived tokens and rotate them regularly.
- For remote include resolution, use the allowlist and size/timeout guardrails to avoid fetching from unexpected hosts.
- Respect API rate limits; tune --rate-rps/--rate-burst and --retry-max as needed.
