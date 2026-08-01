---
title: Deps Command
description: Audit lockfiles and SBOMs with native ProjectDiscovery depx intelligence
---

The `deps audit` command checks dependency metadata against
[ProjectDiscovery depx](https://github.com/projectdiscovery/depx) malicious and
quarantined package intelligence. The integration uses depx's native Go
implementation in-process.

The `deps verify` command statically inspects a package archive and can compare
it with reviewed source and SLSA/in-toto provenance. Use it before installing a
new package version or promoting a release artifact.

## Safety boundary

`deps audit` reads metadata only. It does not invoke npm, pip, Go, Cargo,
Bundler, Maven, or another package manager. It does not install packages,
execute package contents, or run lifecycle scripts.

`deps verify` applies the same no-execution rule. It parses bounded archive
members in memory and never extracts them onto the filesystem. HTTP(S) inputs
use same-origin redirects and strict download, member, file-count, and expanded
size limits. GoGatoZ does not resolve package names through a registry: provide
the exact archive URL or a local archive that you trust GoGatoZ to read.

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

## Verify a package artifact

Inspect an npm tarball, Python wheel, Ruby gem, ZIP, or tar archive without
installing it:

```bash
gogatoz deps verify --artifact /path/to/package.tgz

gogatoz deps verify \
  --artifact /path/to/package.tgz \
  --source /path/to/reviewed-source \
  --provenance /path/to/provenance.json \
  --expected-repository https://gitlab.example.test/team/package \
  --expected-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-ref refs/tags/v1.2.3 \
  --expected-pipeline 987 \
  --format sarif \
  --output artifact-verification.sarif \
  --fail-on-findings
```

Supported verifier formats are `text`, `json`, `sarif`, and `glsast`. SARIF
and GitLab SAST output include CWE, OWASP CI/CD, and MITRE ATT&CK metadata.

The verifier reports:

- `PACKAGE_EXECUTION_TRIGGER` — lifecycle, native build, Python path, or import-time execution behavior
- `PACKAGE_PERSISTENCE_INDICATOR` — developer-tool, detached-process, cron, or systemd persistence behavior
- `PACKAGE_EXECUTABLE_PAYLOAD` — executable content or a file extension that disagrees with its magic bytes
- `PACKAGE_OBFUSCATION` — numeric byte arrays reconstructed through `String.fromCharCode`
- `ARTIFACT_SOURCE_DIVERGENCE` — published content is absent from or changed relative to reviewed source
- `ARTIFACT_PARTIAL_BUILD` — the artifact contains substantially fewer files or bytes than reviewed source
- `PROVENANCE_MISMATCH` — provenance does not match the expected repository, commit, ref, or pipeline
- `RELEASE_TAG_MISMATCH` — the package version does not match an expected release tag

Source divergence can be legitimate when a release adds generated or compiled
outputs. Treat it as a review queue: explain and reproduce each difference from
the expected commit before consuming the artifact.

Verifier resource limits default to a 64 MiB download, 256 MiB expanded
content, 8 MiB per member, and 10,000 regular files. They can be reduced with
`--max-download-bytes`, `--max-expanded-bytes`, `--max-file-bytes`, and
`--max-files`.

## Scan GitLab projects

Use `enumerate --dependencies` to combine dependency intelligence with the
normal GitLab CI/CD analyzer:

```bash
gogatoz enumerate --target group/project --dependencies --format json
```

The report includes a `dependency_scan` object and merges dependency findings
into the project's standard `findings` array.
