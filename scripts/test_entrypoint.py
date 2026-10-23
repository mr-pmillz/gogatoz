"""Exercise the release entrypoint without requiring Docker or a Go build."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("bash"), "entrypoint requires bash")
class EntrypointTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="gogatoz-entrypoint-test-")
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        binary = self.directory / "gogatoz"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "print(json.dumps(sys.argv[1:]))\n"
            "sys.exit(7)\n"
        )
        binary.chmod(0o700)
        self.env = os.environ.copy()
        self.env.pop("CI", None)
        self.env["PATH"] = str(self.directory) + os.pathsep + self.env["PATH"]

    def run_entrypoint(self, args, *, ci=False, stdin=""):
        env = self.env | ({"CI": "true"} if ci else {})
        return subprocess.run(
            ["bash", str(Path(__file__).resolve().parents[1] / "entrypoint.sh"), *args],
            env=env, input=stdin, text=True, capture_output=True, timeout=10,
        )

    def test_cli_arguments_and_exit_status(self):
        for args, want in (
            ([], ["--help"]),
            (["--help"], ["--help"]),
            (["--output", "path with spaces"], ["--output", "path with spaces"]),
            (["gogatoz", "version"], ["version"]),
        ):
            with self.subTest(args=args):
                result = self.run_entrypoint(args)
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertEqual(json.loads(result.stdout), want)

    def test_ci_preserves_explicit_command(self):
        result = self.run_entrypoint(["gogatoz", "version"], ci=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["version"])

    def test_ci_shell_without_arguments(self):
        result = self.run_entrypoint([], ci=True, stdin="printf 'ci-shell\\n'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ci-shell\n")

    def test_explicit_shell(self):
        result = self.run_entrypoint(["bash", "-c", "printf 'explicit-shell\\n'"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "explicit-shell\n")


if __name__ == "__main__":
    unittest.main()
