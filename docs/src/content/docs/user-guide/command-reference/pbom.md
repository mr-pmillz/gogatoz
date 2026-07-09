---
title: PBOM Command
description: Generate Pipeline Bill of Materials
---

The pbom command generates a Pipeline Bill of Materials (PBOM) that inventories all container images and CI include references used in a GitLab project's CI/CD pipeline. Use it to audit supply chain dependencies in your pipelines.

## Basic Usage

```bash
gogatoz pbom --project <path-or-id> [options]
```

Authentication:

```bash
export GITLAB_TOKEN=glpat_xxx
export GITLAB_URL=https://gitlab.com   # optional, defaults to https://gitlab.com
```

You can also pass --token and --gitlab-url flags explicitly.

## Options

Project selection:
- `--project`              Project ID or path-with-namespace (required)
- `--ref`                  Git ref to scan (default: project default branch)

Output:
- `-f, --format`           Output format: `json` or `cyclonedx` (default: `json`)
- `-o, --output`           Output file path (default: stdout)

Include resolution:
- `--follow-includes`      Resolve includes transitively (default: true)
- `--include-depth`        Depth for include resolution (default: 2)
- `--allow-remote-includes`  Allow resolving remote includes (default: false)
- `--remote-allowlist`     Comma-separated host allowlist for remote includes
- `--remote-max-bytes`     Max bytes per remote include (default: 1048576 / 1 MiB)
- `--remote-timeout`       Timeout per remote include fetch (default: 10s)

Global flags (--token, --gitlab-url, --verbose, --insecure-skip-tls-verify, --ca-cert, rate/HTTP tuning) apply as usual.

## Examples

### Generate PBOM in native JSON format

```bash
gogatoz pbom --project root/my-project
```

### CycloneDX 1.5 SBOM format

```bash
gogatoz pbom --project root/my-project --format cyclonedx
```

### Save to file

```bash
gogatoz pbom --project root/my-project --format cyclonedx -o pipeline-sbom.json
```

### Scan a specific branch

```bash
gogatoz pbom --project root/my-project --ref develop
```

### Integrate with vulnerability scanners

```bash
# Generate CycloneDX SBOM and scan with Grype
gogatoz pbom --project root/my-project --format cyclonedx -o sbom.json
grype sbom:sbom.json
```

## What's in a PBOM

The PBOM inventories:

- **Container images** -- every `image:` reference in the pipeline, with registry, tag, and digest information. Flags mutable tags (`:latest`, `:stable`) and unpinned images.
- **CI includes** -- all `include:` references: local files, project refs, remote URLs, templates, and components. Shows the full include tree with transitive resolution.
- **External scripts** -- remote script references executed via `curl | bash` or similar patterns.

## CycloneDX Integration

The `--format cyclonedx` output produces a valid CycloneDX 1.5 SBOM that integrates with:

- Dependency-Track for vulnerability monitoring
- Grype/Trivy for image vulnerability scanning
- OWASP toolchain for supply chain security

## Notes

- The PBOM command only reads pipeline configuration; it does not trigger any pipelines or modify projects.
- Include resolution uses the same engine as enumerate, with the same guardrails (allowlist, size/time limits).
- The CycloneDX output follows the 1.5 specification and can be validated with the CycloneDX CLI tool.
