---
title: Deps Command
description: Audit lockfiles and SBOMs with native ProjectDiscovery depx intelligence
---

The `deps audit` command checks dependency metadata against
[ProjectDiscovery depx](https://github.com/projectdiscovery/depx) malicious and
quarantined package intelligence. The integration uses depx's native Go
implementation in-process.

## Safety boundary

`deps audit` reads metadata only. It does not invoke npm, pip, Go, Cargo,
Bundler, Maven, or another package manager. It does not install packages,
execute package contents, or run lifecycle scripts.

## Basic usage

```bash
# Recursively discover supported lockfiles in the current directory
gogatoz deps audit .

# Audit explicit dependency metadata files
gogatoz deps audit package-lock.json bom.cdx.json

# Fail a CI job when malicious or quarantined metadata is found
gogatoz deps audit . --fail-on-findings
```

depx supports npm, Python, Go, Cargo, Ruby, and Maven/Gradle lockfile formats,
plus CycloneDX and SPDX SBOMs. Pass an SBOM explicitly when using the standalone
command; GitLab enumeration discovers supported SBOM names inside the bounded
repository archive automatically.

## Output formats

```bash
gogatoz deps audit . --format json
gogatoz deps audit . --format sarif --output dependency-findings.sarif
gogatoz deps audit . --format glsast --output gl-sast-report.json
```

Supported formats are `text`, `json`, `sarif`, and `glsast`. SARIF and GitLab
SAST findings include the dependency metadata file plus CWE, OWASP CI/CD, and
MITRE ATT&CK identifiers.

## Options

- `--cache-dir`: depx inventory cache directory
- `--timeout`: depx inventory and registry request timeout (default `30s`)
- `--format`, `-f`: `text|json|sarif|glsast`
- `--output`, `-o`: write the report to a file
- `--fail-on-findings`: return a non-zero status when a malicious or quarantined dependency is found

## Findings

- `MALICIOUS_DEPENDENCY` — a version matched depx malicious-package intelligence
- `QUARANTINED_DEPENDENCY` — npm identifies the name as a security holding package

Treat a finding as an incident-response signal. Remove or replace the affected
dependency without installing it, determine whether any build consumed it, and
rotate credentials available to affected CI jobs.

## Scan GitLab projects

Use `enumerate --dependencies` to combine dependency intelligence with the
normal GitLab CI/CD analyzer:

```bash
gogatoz enumerate --target group/project --dependencies --format json
```

The report includes a `dependency_scan` object and merges dependency findings
into the project's standard `findings` array.
