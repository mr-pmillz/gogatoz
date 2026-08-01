# Package artifact verifier P1 validation

## Scope

P1 adds static inspection for npm tarballs, Python wheels, Ruby gems, ZIP, and
tar archives through `gogatoz deps verify`. It can compare an artifact with a
reviewed source archive or directory and validate SLSA/in-toto provenance
against an expected repository, commit, ref, and pipeline identity.

## Safety invariants

- No package manager is invoked.
- No package is installed, imported, extracted, or executed.
- Archive members are inspected in memory and traversal, links, devices, and
  non-regular members are rejected.
- Downloads use same-origin redirects and bounded byte limits.
- Expanded bytes, individual member bytes, and file counts are bounded.
- Local source directories are traversed through a rooted filesystem handle;
  links and special files are rejected.
- Tests use locally generated, inert archives. No third-party malicious package
  name, URL, payload, or registry download is used.

## TDD evidence

The RED commits define the expected behavior before implementation:

- `b410c60` — bounded static archive inspection
- `abde8dd` — source and provenance verification
- `ba36f72` — CLI and taxonomy output
- `f636c0f` — branch refs must not be mistaken for release tags

The corresponding GREEN and hardening commits are:

- `3d6e390` — archive parsing and security-signal detection
- `1207d27` — source comparison and provenance validation
- `b7a3097` — CLI, SARIF, GitLab SAST, and taxonomy integration
- `062b375` — archive, HTTP, redirect, resource, and report hardening
- `a65bc56` — release-tag normalization
- `5fe69cc` — end-to-end CLI verification with an inert synthetic archive

## Verification commands

```bash
go build ./...
go test -race -count=1 ./...
golangci-lint run -c .golangci-lint.yml ./...
go test -cover ./pkg/artifactverify
```

`pkg/artifactverify` has at least 80% statement coverage. The full test suite
also verifies that all eight verifier findings include CWE, OWASP CI/CD, and
MITRE ATT&CK classifications in both SARIF and GitLab SAST output.

## CTF decision

No live CTF lab is created for package-artifact execution behavior. Unit and
CLI tests generate inert archives locally and assert that lifecycle strings and
other static indicators are detected without running them. This avoids adding
an installable package, a malicious third-party reference, or an accidental
execution path to the CTF environment.
