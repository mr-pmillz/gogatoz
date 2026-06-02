---
title: Generating Reports
description: Generate HTML reports and send notifications from GoGatoZ scan results
---

This guide covers generating reports from enumeration results and sending findings to external systems like Discord.

## Overview

After scanning projects with `enumerate`, GoGatoZ provides two commands for working with results:

- **`report`** — Generate self-contained HTML, text, or JSON reports
- **`notify`** — Send formatted findings to Discord via Apprise API or direct webhook

Both commands accept input from JSONL files, SQLite databases, or stdin pipes.

## Generating HTML Reports

### From JSONL output

First, run an enumeration scan and save results as JSONL:

```bash
gogatoz enumerate -i targets.txt --json -o results.jsonl
```

Then generate an HTML report:

```bash
gogatoz report --input results.jsonl --output report.html
```

The HTML report is self-contained (no external dependencies) and includes charts and searchable tables.

### From SQLite database

If the MCP server or a previous scan stored results in SQLite:

```bash
gogatoz report --db results.sqlite3 --session 1 --output report.html
```

### Other formats

```bash
# Plain text summary
gogatoz report --input results.jsonl --format text

# JSON (structured, parseable)
gogatoz report --input results.jsonl --format json

# JSONL (one record per line, streamable)
gogatoz report --input results.jsonl --format jsonl

# Only include projects with findings
gogatoz report --input results.jsonl --only-findings --output findings-only.html
```

## Sending Notifications

### Discord via Apprise

[Apprise](https://github.com/caronc/apprise-api) is a notification aggregator. If you have an Apprise API endpoint:

```bash
gogatoz notify --input results.jsonl \
  --apprise-url https://apprise.example/notify/apprise
```

### Discord direct webhook

Send findings directly to a Discord channel webhook:

```bash
gogatoz notify --input results.jsonl \
  --discord-webhook https://discord.com/api/webhooks/CHANNEL_ID/TOKEN
```

Findings are formatted as severity-colored Discord embeds with project details, rule names, and evidence.

### Piped from enumerate

Stream results directly without intermediate files:

```bash
gogatoz enumerate -i targets.txt --json | \
  gogatoz notify --discord-webhook https://discord.com/api/webhooks/...
```

### Dry run

Preview what would be sent without actually posting:

```bash
gogatoz notify --input results.jsonl --apprise-url x --dry-run
```

## Lab Exercise

Using the CTF lab environment (`http://gitlab.local:8929`):

### 1. Enumerate the lab projects

```bash
export GITLAB_TOKEN=glpat-lab-admin-token-12345
export GITLAB_URL=http://gitlab.local:8929

gogatoz search -q "" --no-token --json | \
  jq -r '.[].path_with_namespace' > lab-projects.txt

gogatoz enumerate -i lab-projects.txt \
  --follow-includes --json -o lab-results.jsonl
```

### 2. Generate an HTML report

```bash
gogatoz report --input lab-results.jsonl \
  --only-findings --output lab-report.html
```

Open `lab-report.html` in your browser to review the findings with charts and tables.

### 3. Generate a text summary

```bash
gogatoz report --input lab-results.jsonl --only-findings --format text
```

## Next Steps

- [MCP Capstone Lab](/user-guide/use-cases/mcp-lab/) — Use GoGatoZ as an MCP server with Claude Code to automate the full workflow
