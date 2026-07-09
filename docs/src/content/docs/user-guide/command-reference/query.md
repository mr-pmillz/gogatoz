---
title: Query Command
description: Query the local results database
---

The query command lets you review stored scan results, findings, attack data, and harvested credentials from the local SQLite database without re-running scans.

Every `search`, `enumerate`, `attack`, and `pivot` command automatically persists results. The query command provides read-only access to this data.

## Basic Usage

```bash
gogatoz query <subcommand> [options]
```

No GitLab authentication is required. This command works entirely against the local database.

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `sessions` | List all scan sessions with timestamps and project counts |
| `projects` | List all projects discovered across all sessions |
| `findings` | Show scan findings (optionally filtered by session) |
| `attacks` | Show attack results (commit-ci, secrets, etc.) |
| `secrets` | Show exfiltrated secrets from `--secrets` attacks |
| `credentials` | Show harvested credentials from `pivot` operations |
| `exfil` | Show exfiltrated data from `--ror-listen` callbacks |

## Options

- `--db`          SQLite database path (default: `~/.local/share/gogatoz/results.db`)
- `--format`      Output format: `text` or `json` (default: `text`)
- `--session`     Filter by session ID (default: all sessions)
- `--limit`       Max results to return (default: unlimited)
- `--redacted`    Mask secret values in output (default: false)

## Examples

### List all scan sessions

```bash
gogatoz query sessions
```

### Show findings for a specific session

```bash
gogatoz query findings --session 1
```

### Show all attack results

```bash
gogatoz query attacks
```

### Show exfiltrated secrets (redacted)

```bash
gogatoz query secrets --redacted
```

### Show pivoted credentials

```bash
gogatoz query credentials
```

### Show ROR listener callback data

```bash
gogatoz query exfil
```

### Review an engagement

```bash
# What sessions have I run?
gogatoz query sessions

# What did session 3 find?
gogatoz query findings --session 3 --format json | \
  jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'

# What credentials did the pivot harvest?
gogatoz query credentials --format json
```

### Export for reporting

```bash
# All findings as JSON for post-processing
gogatoz query findings --format json > all-findings.json

# Re-generate report from stored data
gogatoz report --db ~/.local/share/gogatoz/results.db --session 1 --output report.html
```

## Notes

- The database is created automatically on first use by any command that persists results.
- WAL mode is enabled on the SQLite database for concurrent read access.
- The `--redacted` flag masks secret values but preserves variable names for context.
- Use `GOGATOZ_DB` environment variable to override the default database path globally.
