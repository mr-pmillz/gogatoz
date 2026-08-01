# Multi-ecosystem package tamper P2 validation

## Scope

P2 replaces the legacy automatic npm tamper path with a manual,
preview-first workflow for npm, PyPI, and RubyGems. npm supports `preinstall`,
`postinstall`, and `import`; PyPI and RubyGems support explicit import entry
files.

## Safety invariants

- Preview mode is the default and contains no install, build, or publish command.
- The job copies the checkout into a temporary directory and mutates only that copy.
- Preview entry files and npm manifests cannot be symbolic links.
- Injected code is base64 transported, written into the copy, and never executed.
- No registry has a default; no writable-package discovery or token harvesting remains.
- Every preview and live job is manual.
- Live publishing requires an explicit package, registry, exact
  `publish:<ecosystem>:<package>` acknowledgement, and public-registry opt-in
  when applicable.
- The running job requires the matching protected, masked
  `GOGATOZ_PACKAGE_TAMPER_APPROVED` value and validates the static package name
  before any publish command.

## TDD evidence

- `9938b32` — RED multi-ecosystem behavior and authorization boundaries
- `ecf7598` — GREEN preview-first npm/PyPI/RubyGems implementation
- `cd26224` — RED checkout isolation, symlink, and package-identity tests
- `40f40d6` — GREEN isolation and identity hardening
- `d4d56e1` — RED shell-expansion entry-path regression
- `a159622` — GREEN canonical entry-path character enforcement

## Verification

```bash
go build ./...
go test -race -count=1 ./...
golangci-lint run -c .golangci-lint.yml ./...
go test -coverprofile=/tmp/package-tamper.cover ./pkg/attack/payloads
```

The modified `npm_tamper.go` implementation has 95.0% statement coverage.
The tests execute a locally generated preview shell in a temporary directory,
verify the synthetic injected code did not run, confirm the checkout was not
modified, inspect the resulting archive in memory, and prove a symlink target
cannot be changed.

Built-CLI QA renders all three ecosystems with stderr suppressed and verifies
that preview YAML contains no install/build/publish command. It also verifies
that a missing acknowledgement and a missing public-registry opt-in both fail
without emitting payload output.

## CTF decision

No package-tamper pipeline is committed to or run in GoGatoZ CTF. No package is
installed, built, imported, or published there, and no third-party malicious
package is named or downloaded. The feature is validated only with local,
synthetic test fixtures.
