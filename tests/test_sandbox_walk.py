"""Sandbox-escape regressions for tree-walking tools and the trust anchor.

Two classes of hole, both reproduced before the fix:

1. Windows directory junctions. `mklink /J` needs no admin rights, and a
   junction is NOT reported by Path.is_symlink(), so os.walk's
   followlinks=False does not stop it descending straight out of BASE_DIR.
   safe_path() itself was always correct (it resolves the junction and
   rejects), but grep_files / recursive list_dir / the orphan sweep never
   re-validated the paths os.walk handed them.

2. Case-insensitive filesystems. _ensure_writable compared the repo-context
   trust anchor's name case-sensitively, so on Windows/macOS a files:write-only
   client could create "Agent-Repo-Config.Local.Json" -- a different string,
   the same file -- and forge the approved git remote with no git scope at all.
"""

import asyncio
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ.setdefault("MCP_TOKEN", "unit-test-token")
os.environ.setdefault("MCP_BASE_DIR", str(PROJECT))
os.environ.setdefault("MCP_ALLOW_COMMANDS", "0")
os.environ.setdefault("MCP_SERVEO_HOSTNAME", "")
os.environ.setdefault("MCP_AUTH_MODE", "legacy")

import server  # noqa: E402
from core import is_inside, safe_path  # noqa: E402

SECRET = "SUPER_SECRET_JUNCTION_VALUE"


def make_junction(link: Path, target: Path) -> bool:
    """Create a directory junction (Windows) or symlink (POSIX). False if unable."""
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, text=True, check=False,
        )
        return result.returncode == 0 and link.exists()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return False
    return True


class _JunctionBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=str(server.BASE_DIR))
        self.root = Path(self._tmp.name)
        self.rel = self.root.relative_to(server.BASE_DIR).as_posix()
        self._outside_tmp = tempfile.TemporaryDirectory()
        self.outside = Path(self._outside_tmp.name)
        (self.outside / "secret.txt").write_text(SECRET + "\n", encoding="utf-8")
        (self.root / "inside.txt").write_text("ordinary content\n", encoding="utf-8")
        self.link = self.root / "escape_hatch"
        if not make_junction(self.link, self.outside):
            self.skipTest("cannot create a junction/symlink on this system")

    def tearDown(self):
        # Remove the link before the TemporaryDirectory cleanup so the cleanup
        # does not follow it and delete the "outside" tree through it.
        with __import__("contextlib").suppress(OSError):
            if self.link.is_symlink():
                self.link.unlink()
            else:
                os.rmdir(self.link)
        self._tmp.cleanup()
        self._outside_tmp.cleanup()


class JunctionPremiseTests(_JunctionBase):
    """Pin the platform behaviour the fix exists for. If these ever fail, the
    escape stopped being reachable and the guards below can be revisited."""

    def test_junction_is_not_reported_as_a_symlink_on_windows(self):
        if os.name != "nt":
            self.skipTest("POSIX uses a real symlink, which is_symlink() does see")
        self.assertFalse(self.link.is_symlink())

    def test_oswalk_descends_through_the_link(self):
        found = {
            name
            for _, _, files in os.walk(self.root, followlinks=False)
            for name in files
        }
        self.assertIn("secret.txt", found)

    def test_safe_path_itself_rejects_the_escape(self):
        with self.assertRaises(ValueError):
            safe_path(server.BASE_DIR, self.link / "secret.txt")
        self.assertFalse(is_inside(server.BASE_DIR, self.link / "secret.txt"))


class JunctionEscapeTests(_JunctionBase):
    def test_grep_files_does_not_read_through_the_link(self):
        out = asyncio.run(server.grep_files(SECRET, self.rel))
        self.assertNotIn(SECRET, out)

    def test_grep_files_still_finds_content_inside_the_workspace(self):
        out = asyncio.run(server.grep_files("ordinary content", self.rel))
        self.assertIn("inside.txt", out)

    def test_recursive_list_dir_does_not_list_through_the_link(self):
        out = asyncio.run(server.list_dir(self.rel, recursive=True))
        self.assertNotIn("secret.txt", out)
        self.assertIn("inside.txt", out)

    def test_orphan_sweep_does_not_unlink_through_the_link(self):
        victim = self.outside / "important.mcp-tmp"
        victim.write_text("not ours to delete\n", encoding="utf-8")
        os.utime(victim, (0, 0))  # older than any TTL
        server._last_orphan_sweep = float("-inf")
        server._cleanup_orphan_mcp_tmp()
        self.assertTrue(victim.exists(), "swept a file outside the workspace")


class TrustAnchorCasingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=str(server.BASE_DIR))
        self.root = Path(self._tmp.name)
        self.rel = self.root.relative_to(server.BASE_DIR).as_posix()

    def tearDown(self):
        self._tmp.cleanup()

    def test_canonical_name_is_refused(self):
        with self.assertRaises(ValueError):
            server._ensure_writable(self.root / server.REPO_CONTEXT_FILE)

    def test_mixed_case_name_is_refused(self):
        # The forgery payload: a different string, the same file on Windows.
        for name in (
            "Agent-Repo-Config.Local.Json",
            "AGENT-REPO-CONFIG.LOCAL.JSON",
            "agent-Repo-config.local.JSON",
        ):
            with self.assertRaises(ValueError, msg=name):
                server._ensure_writable(self.root / name)

    def test_write_file_refuses_mixed_case_trust_anchor(self):
        with self.assertRaises(ValueError):
            asyncio.run(
                server.write_file(
                    f"{self.rel}/Agent-Repo-Config.Local.Json",
                    '{"status": "configured"}',
                )
            )

    def test_dot_git_is_refused_in_any_casing(self):
        for part in (".git", ".GIT", ".Git"):
            with self.assertRaises(ValueError, msg=part):
                server._ensure_writable(self.root / part / "config")

    def test_ordinary_names_still_writable(self):
        server._ensure_writable(self.root / "agent-repo-config.json")
        server._ensure_writable(self.root / "notes.md")
        server._ensure_writable(self.root / "gitignore")


class DirectoryTargetTests(unittest.TestCase):
    """write_file/append_file on a directory returned a raw OSError from
    os.replace instead of the clean ValueError the rest of the API uses."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=str(server.BASE_DIR))
        self.root = Path(self._tmp.name)
        self.rel = self.root.relative_to(server.BASE_DIR).as_posix()
        (self.root / "adir").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_write_file_on_directory_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(server.write_file(f"{self.rel}/adir", "x"))
        self.assertIn("directory", str(ctx.exception))

    def test_append_file_on_directory_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(server.append_file(f"{self.rel}/adir", "x"))
        self.assertIn("directory", str(ctx.exception))

    def test_read_file_on_directory_raises_value_error(self):
        with self.assertRaises(ValueError):
            asyncio.run(server.read_file(f"{self.rel}/adir"))


if __name__ == "__main__":
    unittest.main()
