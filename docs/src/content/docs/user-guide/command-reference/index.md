---
title: Command Reference
description: Detailed usage information for each GoGatoZ command
---

GoGatoZ provides three main commands, each with its own set of options:

1. [Search Command](/user-guide/command-reference/search/) - Discover GitLab projects of interest
2. [Enumerate Command](/user-guide/command-reference/enumerate/) - Analyze GitLab projects for exploitable CI/CD issues
3. [Attack Command](/user-guide/command-reference/attack/) - Stage payloads or commit CI for ethical testing

## Common Global Flags

These options are available across all commands (flags override env which override config file):

- `--gitlab-url` string: Base URL of GitLab instance (default: https://gitlab.com)
- `--token` string: GitLab Personal Access Token (or env GITLAB_TOKEN)
- `--json`: Output JSON instead of text (where supported)
- `--verbose`, `-v`: Verbose logging
- Reliability and HTTP tuning:
  - `--rate-rps`, `--rate-burst`, `--retry-max`, `--user-agent`
  - `--http-max-idle`, `--http-max-idle-per-host`, `--http-idle-timeout`, `--http-tls-timeout`, `--http-expect-timeout`, `--http-req-timeout`
- TLS for self-hosted instances:
  - `--insecure-skip-tls-verify`, `--ca-cert`
- Config file: `--config` path (default: reads ./.gogatoz.yaml if present)

See each command page for command-specific flags.

## Basic Usage

The general syntax for GoGatoZ commands is:

```bash
gogatoz [command] [options]
```

Where `[command]` is one of:
- `search` - Search for GitLab projects
- `enumerate` - Enumerate projects for CI/CD risks
- `attack` - Execute payloads or commit CI YAML

## Getting Help

To see the available options for any command, use the `-h` or `--help` flag:

```bash
gogatoz --help
gogatoz search --help
gogatoz enumerate --help
gogatoz attack --help
```

For detailed information about each command, refer to the specific command pages linked above.
