---
title: Watch Command
description: Monitor GitLab release refs and publishing workflow drift
---

The `watch` command polls one GitLab project and keeps an in-memory baseline of
its CI configuration, branches, tags, and recent pipeline refs.

```bash
gogatoz watch --target group/project --branches main,next --interval 60s
gogatoz watch --target group/project --format json --notify https://alerts.example.test/gogatoz
```

The first observation establishes the baseline. Later observations report:

- normal branch SHA movement and non-fast-forward rewrites;
- tag target changes, deletion, and recreation;
- branches with recent pipeline activity that disappear within the configured
  short-lived window;
- unusual bursts of newly created branches and tags; and
- changes to jobs that publish packages or create GitLab releases.

For ancestry checks, GoGatoZ uses GitLab's merge-base API. It reads repository
and pipeline metadata only and does not run a pipeline or modify a ref.

## Options

- `--target`: project ID or path with namespace (required)
- `--branches`: comma-separated CI configuration refs (default `main`)
- `--interval`: polling interval (default `60s`)
- `--short-lived-window`: branch lifetime threshold (default `15m`)
- `--burst-threshold`: new ref count per interval (default `5`)
- `--format`: `text|json`
- `--notify`: optional webhook that receives the same alert object

Tag recreation can only be identified when at least one polling observation
sees the tag absent. Choose an interval appropriate for the release process and
retain GitLab audit events as the authoritative actor record.
