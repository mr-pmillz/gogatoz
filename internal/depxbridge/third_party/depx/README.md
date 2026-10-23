# depx source snapshot

This directory contains the depx v0.1.1 packages needed by GoGatoZ's native
dependency scanner, under the upstream MIT license in `LICENSE`.
`UPSTREAM.json` records the module checksums, included packages, and local patch
checksums.

depx exposes its audit service only through Go `internal` packages. Keeping the
required source inside GoGatoZ lets `go install github.com/mr-pmillz/gogatoz@latest`
work without a local `replace` directive or an external depx executable.

To update the snapshot, change `VERSION` in `scripts/sync_depx.py`, then run
`python3 scripts/sync_depx.py` from the repository root. The script copies only
the transitive package closure of audit, config, intel, and registry. It rewrites
internal import paths, adds a generated-file header, and applies the reviewed
patches in `scripts/depx_patches/` before updating the snapshot. If a patch no
longer applies, syncing fails before changing the snapshot. External module
versions remain managed by the root `go.mod`.

The local patches fix directory discovery of mixed-case lockfiles, SBOMs, and
paths containing newlines; reject incomplete SCALIBR extractions; and export
valid empty SBOMs. SBOM filename aliases use a temporary copy so they work
without Windows symlink privileges. Regression tests live in the parent bridge
package.

Run `python3 scripts/sync_depx.py --check` to verify the generated files, license,
and provenance without modifying them. CI runs this check to prevent accidental
edits or lost patches.

Do not edit the generated Go files directly. After syncing, run `go mod tidy`,
the bridge and depscan tests, and the project build, tests, and lint checks.
