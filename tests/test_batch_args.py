"""BatBadBut: cmd.exe metacharacter injection through an allow-listed .cmd/.bat.

Windows has no way to launch a batch file without cmd.exe -- CreateProcess
silently re-invokes `cmd.exe /c`, and cmd re-parses the command line it is
handed. Python's argv quoting (subprocess.list2cmdline) only quotes an argument
containing whitespace or a quote; it never escapes cmd's metacharacters. So a
list argv with shell=False is NOT sufficient: an allow-listed `npm.cmd` handed
the single argument `--version&whoami` runs whoami.

Reproduced against this repo's own venv before the fix (the marker file was
written), which is why the guard rejects rather than escapes.
"""

import os
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from core import (  # noqa: E402
    BATCH_METACHARACTERS,
    ensure_safe_batch_args,
    is_batch_executable,
)


class BatchExecutableDetectionTests(unittest.TestCase):
    def test_batch_suffixes_detected_case_insensitively(self):
        for name in (r"C:\tools\npm.cmd", r"C:\tools\NPM.CMD", "run.bat", "run.BaT"):
            self.assertTrue(is_batch_executable(name), name)

    def test_native_executables_are_not_batch(self):
        for name in (r"C:\Python\python.exe", "/usr/bin/git", "node", "git.com"):
            self.assertFalse(is_batch_executable(name), name)


class EnsureSafeBatchArgsTests(unittest.TestCase):
    BATCH = r"C:\Program Files\nodejs\npm.cmd"

    def test_metacharacter_rejected(self):
        # The exact payload that executed whoami before the fix.
        with self.assertRaises(ValueError) as ctx:
            ensure_safe_batch_args(self.BATCH, ["--version&whoami>marker.txt"])
        self.assertIn("cmd.exe", str(ctx.exception))

    def test_every_metacharacter_is_rejected(self):
        for char in BATCH_METACHARACTERS:
            with self.assertRaises(ValueError, msg=repr(char)):
                ensure_safe_batch_args(self.BATCH, ["install" + char + "calc"])

    def test_ordinary_args_allowed(self):
        ensure_safe_batch_args(self.BATCH, ["install", "--save-dev", "typescript@5.4"])
        ensure_safe_batch_args(self.BATCH, ["run", "build:prod"])
        # Spaces are safe: list2cmdline quotes them, and cmd honours the quotes.
        ensure_safe_batch_args(self.BATCH, ["--prefix", "C:\\my project"])

    def test_native_executable_is_not_restricted(self):
        # git.exe is not re-parsed by cmd.exe, so '&' is just data there and
        # must keep working (e.g. a commit message or a branch name).
        ensure_safe_batch_args(r"C:\Git\git.exe", ["commit", "-m", "fix a & b"])
        ensure_safe_batch_args("/usr/bin/git", ["commit", "-m", "fix a & b"])

    def test_empty_args_allowed(self):
        ensure_safe_batch_args(self.BATCH, [])


@unittest.skipUnless(os.name == "nt", "cmd.exe re-parsing is Windows-specific")
class LiveBatchInjectionTests(unittest.TestCase):
    """End-to-end proof, on Windows only, that the guard blocks a real payload.

    Writes a throwaway .cmd that echoes its arguments, then confirms that
    without the guard cmd.exe would run a second command -- and that the guard
    refuses the argument that makes it happen.
    """

    def test_guard_rejects_payload_that_cmd_would_execute(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "echoer.cmd"
            script.write_text("@echo off\r\necho ARGS=%*\r\n", encoding="utf-8")
            marker = Path(tmp) / "marker.txt"
            # Deliberately space-free. list2cmdline quotes any argument that
            # contains whitespace, which incidentally neutralises cmd's
            # metacharacters -- that accident is exactly why the guard cannot
            # rely on quoting and must reject the characters outright.
            payload = f"hello&echo.>{marker}"
            self.assertNotIn(" ", payload, "payload must stay unquoted by list2cmdline")

            # Without the guard, cmd.exe splits on '&' and runs the second half.
            subprocess.run([str(script), payload], capture_output=True, check=False)
            self.assertTrue(
                marker.exists(),
                "cmd.exe did not re-parse the argument; the premise of this "
                "test no longer holds on this platform",
            )

            # With the guard, the call never reaches the process spawn.
            with self.assertRaises(ValueError):
                ensure_safe_batch_args(str(script), [payload])


if __name__ == "__main__":
    unittest.main()
