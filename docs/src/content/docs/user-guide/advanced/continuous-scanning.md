---
title: Continuous Scanning
description: Production-grade continuous scanning of large GitLab instances
---

GoGatoZ supports production-grade continuous scanning of large GitLab instances.

- High concurrency with rate limiting and retries
- Transitive include analysis for `.gitlab-ci.yml` (with depth limits and optional remote include fetching)
- Optional webhook notifications for fresh findings
- Config file + env + flags precedence for reproducible runs

## Notifications (webhooks)

Use CLI flags when running enumerate:

```bash
# Send each finding as a JSON envelope to a webhook
./gogatoz enumerate -i projects.txt \
  --webhook-url https://hooks.example/webhook \
  --webhook-header 'Authorization: Bearer x' \
  --webhook-timeout 5s --json
```

Each finding is POSTed as a small JSON object including project metadata, the rule, severity, and occurred_at timestamp. See pkg/notify for the envelope schema.

## Repository discovery

Use the built-in search first, then filter by repo contents when needed:

```bash
# Find projects matching a query
./gogatoz search -q "runner" --per-page 100 --max-pages 0 --json > projects.json

# Filter to projects that contain a .gitlab-ci.yml
./gogatoz search -q "ci" --path-pattern ".gitlab-ci.yml" --json > candidates.json

# Keep only projects whose repo content contains strings of interest
./gogatoz search -q "runner" --code-content "tags: self-hosted" --code-per-page 10 --json
```

You can also filter by language and topic, and you can run against self-hosted instances via `--gitlab-url` and TLS flags.

## Daily pipeline

A practical daily workflow for continuous scanning:

```bash
# 1) Discover candidates (JSONL makes piping easy)
./gogatoz search -q "ci" --path-pattern ".gitlab-ci.yml" --format jsonl > candidates.jsonl

# 2) Extract identifiers
jq -r '.path_with_namespace // .id' candidates.jsonl > projects.txt

# 3) Enumerate with concurrency and webhooks
./gogatoz enumerate -i projects.txt -c 32 --timeout 20s \
  --webhook-url https://hooks.example/webhook \
  --format jsonl --output findings.jsonl
```

## Performance tuning

- API rate limiting: `--rate-rps`, `--rate-burst`, `--retry-max`
- HTTP pooling/timeouts: `--http-max-idle*`, `--http-*-timeout`, `--http-req-timeout`
- Include resolution: `--follow-includes`, `--include-depth`, `--allow-remote-includes`, `--remote-*`
- Concurrency: `--concurrency` controls parallel analysis

Tip: Start with lower concurrency on self-hosted GitLab and gradually increase while monitoring 429s.

## Include caching

- In-process caching avoids re-fetching the same remote include within a run
- Optional TTL cache for remote includes via `--include-cache-ttl 10m`
