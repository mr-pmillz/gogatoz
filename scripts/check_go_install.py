#!/usr/bin/env python3
"""Test versioned go install against this checkout through a temporary proxy."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/mr-pmillz/gogatoz"


def main():
    # A unique version prevents a prior successful check from hiding changes.
    version = f"v0.0.0-installcheck.{time.time_ns()}"
    names = subprocess.check_output([
        "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
    ], cwd=ROOT).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="gogatoz-install-") as directory:
        scratch = Path(directory)
        proxy = scratch / "proxy"
        versions = proxy / MODULE / "@v"
        versions.mkdir(parents=True)
        (versions / f"{version}.mod").write_bytes((ROOT / "go.mod").read_bytes())
        (versions / f"{version}.info").write_text(json.dumps({
            "Version": version,
            "Time": datetime.now(timezone.utc).isoformat(),
        }))
        (versions / "list").write_text(version + "\n")
        with zipfile.ZipFile(versions / f"{version}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(set(names)):
                path = ROOT / name
                if name and path.is_file() and not path.is_symlink():
                    archive.write(path, f"{MODULE}@{version}/{name}")

        env = os.environ.copy()
        upstream = subprocess.check_output(["go", "env", "GOPROXY"], text=True).strip()
        excluded = subprocess.check_output(["go", "env", "GONOSUMDB"], text=True).strip()
        env.update({
            "GOBIN": str(scratch / "bin"),
            "GOWORK": "off",
            "GOPROXY": proxy.as_uri() + "," + upstream,
            "GONOPROXY": "none",
            "GONOSUMDB": ",".join(filter(None, [excluded, MODULE])),
        })
        # The working directory has no go.mod or local bridge. Unlike go build,
        # a versioned install also rejects replace/exclude directives.
        subprocess.run(["go", "install", f"{MODULE}@{version}"],
                       cwd=scratch, env=env, check=True)
        binary = scratch / "bin" / ("gogatoz.exe" if os.name == "nt" else "gogatoz")
        subprocess.run([str(binary), "version"], cwd=scratch, env=env, check=True)
        print("Versioned go install passed.")


if __name__ == "__main__":
    main()
