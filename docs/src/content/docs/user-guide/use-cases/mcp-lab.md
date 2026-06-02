---
title: MCP Capstone Lab
description: Use GoGatoZ as an MCP server with Claude Code for AI-assisted GitLab CI/CD security scanning
---

This capstone lab brings together everything from previous labs — search, enumerate, attack, and reporting — by using GoGatoZ as a Model Context Protocol (MCP) server with Claude Code.

> **Prerequisites**: Complete the previous labs (Scanning, Runner Takeover, Post-Compromise, Reporting) before starting this capstone.

## Overview

GoGatoZ includes a built-in MCP server that exposes its security scanning tools to AI assistants like Claude Code. This enables conversational, AI-assisted security assessments where you can ask Claude to discover projects, analyze CI/CD configurations, and identify vulnerabilities.

### What the MCP Server Exposes

| Tool | Description |
|------|-------------|
| `search_projects` | Discover GitLab projects with filters (language, topic, visibility, file paths) |
| `enumerate_projects` | Scan CI/CD configs for vulnerabilities with include resolution |
| `attack_project` | Execute attack workflows (commit-ci, secrets extraction, tag discovery) |

Results are optionally persisted to a SQLite database for later reporting.

## Setting Up the MCP Server

### 1. Build GoGatoZ

```bash
cd /path/to/gogatoz
go build -o gogatoz .
```

### 2. Configure Claude Code

Add GoGatoZ as an MCP server in your Claude Code settings. Create or edit `.claude/settings.json` in your project:

```json
{
  "mcpServers": {
    "gogatoz": {
      "command": "/path/to/gogatoz",
      "args": [
        "mcp",
        "--gitlab-url", "http://gitlab.local:8929",
        "--db", "/tmp/gogatoz-mcp.sqlite3",
        "--insecure-skip-tls-verify"
      ],
      "env": {
        "GITLAB_TOKEN": "glpat-lab-admin-token-12345"
      }
    }
  }
}
```

Key flags:
- `--gitlab-url` — Your GitLab instance (use `http://gitlab.local:8929` for the lab)
- `--db` — SQLite path for persisting results across sessions
- `--insecure-skip-tls-verify` — Required for lab environments without valid TLS
- `--no-token` — Use this instead of a token for unauthenticated scanning of public instances

### 3. Verify the connection

Start a new Claude Code session and ask:

```
Search for all GitLab projects on the lab instance
```

Claude should invoke the `search_projects` tool and return a list of projects.

## Lab Walkthrough

### Phase 1: Discovery

Ask Claude Code to discover what's on the lab GitLab instance:

```
Search for all projects on the lab GitLab instance. Show me which ones have
CI/CD pipelines configured.
```

Claude will use `search_projects` with `path_exists: ".gitlab-ci.yml"` to find projects with CI configurations.

### Phase 2: Enumeration

Ask Claude to scan the discovered projects for vulnerabilities:

```
Enumerate all the projects you found for CI/CD security vulnerabilities.
Follow includes and check for runners.
```

Claude will use `enumerate_projects` with `follow_includes: true` and `fetch_runners: true`. The results will show findings categorized by severity (HIGH, MEDIUM, LOW) with evidence and remediation recommendations.

### Phase 3: Analysis

Ask Claude to analyze the findings:

```
Which projects have HIGH severity findings? What attack paths do you see?
```

Claude can reason about the findings and suggest exploitation chains based on the evidence.

### Phase 4: Targeted Attack

With Claude's analysis, execute a targeted attack:

```
Use discover_tags on the vulnerable project to find available runner tags,
then extract secrets from the project with the self-hosted runner.
```

Claude will use `attack_project` with `mode: "discover_tags"` first, then `mode: "secrets"` to extract CI/CD variables.

### Phase 5: Reporting

Generate a report from the MCP session's results:

```bash
gogatoz report --db /tmp/gogatoz-mcp.sqlite3 --session 1 \
  --only-findings --output capstone-report.html
```

## SQLite Result Persistence

When `--db` is provided, the MCP server stores all results in SQLite:

| Table | Contents |
|-------|----------|
| `scan_sessions` | Timestamped scan sessions |
| `search_results` | Project discovery results |
| `enumerate_results` | Per-project enumeration data |
| `findings` | Individual vulnerability findings |

Query results directly:

```bash
sqlite3 /tmp/gogatoz-mcp.sqlite3 \
  "SELECT severity, rule, COUNT(*) FROM findings GROUP BY severity, rule ORDER BY severity"
```

## Tips

- **Iterative workflow**: Start broad (search all), narrow down (enumerate high-value targets), then go deep (attack specific projects)
- **Session persistence**: The SQLite database preserves results across Claude Code sessions — you can resume where you left off
- **Combine with CLI**: Use MCP for interactive exploration and the CLI for batch operations and reporting
- **Unauthenticated scanning**: Use `--no-token` for scanning public GitLab instances without credentials

## Summary

This capstone lab demonstrates the full GoGatoZ workflow powered by AI:

1. **Search** — Discover projects on the target GitLab instance
2. **Enumerate** — Analyze CI/CD configurations for vulnerabilities
3. **Attack** — Exploit misconfigurations to extract secrets
4. **Report** — Generate findings reports from persisted results

By combining GoGatoZ's MCP server with Claude Code, you can conduct conversational security assessments that leverage AI reasoning to identify and chain attack paths.
