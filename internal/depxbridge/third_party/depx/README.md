# depx source snapshot

This directory contains the depx v0.1.1 packages needed by GoGatoZ's native
dependency scanner, under the upstream MIT license in `LICENSE`.
`UPSTREAM.json` records the module checksums and included packages.

depx exposes its audit service only through Go `internal` packages. Keeping the
required source inside GoGatoZ lets `go install github.com/mr-pmillz/gogatoz@latest`
work without a local `replace` directive or an external depx executable.

To update the snapshot, change `VERSION` in `scripts/sync_depx.py`, then run
`python3 scripts/sync_depx.py` from the repository root. The script copies only
the transitive package closure of audit, config, intel, and registry. It rewrites
internal import paths and adds a generated-file header; upstream logic is
unchanged. External module versions remain managed by the root `go.mod`.

Do not edit the generated Go files directly. After syncing, run `go mod tidy`,
the bridge and depscan tests, and the project build, tests, and lint checks.
