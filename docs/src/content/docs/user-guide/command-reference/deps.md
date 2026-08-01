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
gogatoz deps audit . --format gldep --output gl-dependency-scanning-report.json
gogatoz deps audit . --format cyclonedx --output bom.cdx.json
gogatoz deps audit . --format spdx --output bom.spdx.json
```

Supported formats are `text`, `json`, `sarif`, `glsast`, `gldep`, `cyclonedx`,
and `spdx`. CycloneDX and SPDX are emitted by depx's native exporters. SARIF
and GitLab security reports include dependency coordinates plus CWE, OWASP
CI/CD, and MITRE ATT&CK identifiers.

## Release cooldown intelligence

Release intelligence is opt-in. GoGatoZ asks depx for a native CycloneDX
component inventory, then reads version timestamps from npm, PyPI, and
RubyGems metadata endpoints. It does not fetch a package archive.

```bash
gogatoz deps audit . \
  --cooldown 72h \
  --dormancy-threshold 8760h \
  --release-burst-window 2h \
  --release-burst-threshold 3 \
  --format json
```

`--cooldown 0` is the default and performs no release-metadata registry
queries. Cooldown enrichment cannot be combined with CycloneDX or SPDX output;
choose text, JSON, SARIF, GitLab SAST, or GitLab Dependency Scanning instead.

## Options

- `--cache-dir`: depx inventory cache directory
- `--timeout`: depx inventory and registry request timeout (default `30s`)
- `--cooldown`: minimum selected-package age; `0` disables registry queries
- `--dormancy-threshold`: release gap treated as resurrection (default `8760h`)
- `--release-burst-window`: maximum coordinated-release window (default `1h`)
- `--release-burst-threshold`: minimum releases in a burst (default `3`)
- `--format`, `-f`: `text|json|sarif|glsast|gldep|cyclonedx|spdx`
- `--output`, `-o`: write the report to a file
- `--fail-on-findings`: return a non-zero status when a malicious or quarantined dependency is found

## Findings

- `MALICIOUS_DEPENDENCY` — a version matched depx malicious-package intelligence
- `QUARANTINED_DEPENDENCY` — npm identifies the name as a security holding package
- `DEPENDENCY_COOLDOWN` — the exact selected version is newer than the configured minimum age
- `DORMANT_PACKAGE_RESURRECTION` — a recent selected version follows a long release gap
- `DEPENDENCY_RELEASE_BURST` — several selected versions were released in a narrow window

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
