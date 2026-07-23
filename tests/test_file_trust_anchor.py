"""Security regression: file tools must not touch git-policy trust anchors.

The write tools previously validated only that a path stayed inside the
workspace (safe_path). That let a client forge the repo-context file
(agent-repo-config.local.json) to fake an approved repo context, or rewrite
anything under .git/ (e.g. .git/config) to change git's behaviour. Every
mutating file tool now routes its target through _ensure_writable().
"""

import asyncio
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

_ENV = {
    "MCP_TOKEN": "trust-anchor-test-token",
    "MCP_PORT": "8769",
    "MCP_ALLOW_COMMANDS": "1",
    "MCP_ALLOWED_COMMANDS": "git,python3",
    "MCP_SERVEO_HOSTNAME": "",
    "MCP_AUTH_MODE": "legacy",
}


def load_server(base_dir):
    env = dict(_ENV, MCP_BASE_DIR=str(base_dir))
    mock.patch.dict(os.environ, env).start()
    sys.modules.pop("server", None)
    return importlib.import_module("server")


class TrustAnchorGuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.server = load_server(self.workspace)

    def tearDown(self):
        self._tmp.cleanup()
        mock.patch.stopall()

    def test_write_into_git_dir_refused(self):
        with self.assertRaises(ValueError):
            asyncio.run(self.server.write_file(".git/config", "[core]\n"))

    def test_create_dir_inside_git_refused(self):
        with self.assertRaises(ValueError):
            asyncio.run(self.server.create_dir(".git/hooks"))

    def test_write_repo_context_file_refused(self):
        with self.assertRaises(ValueError):
            asyncio.run(
                self.server.write_file(self.server.REPO_CONTEXT_FILE, "{}")
            )

    def test_delete_repo_context_file_refused(self):
        # Pre-create it out-of-band so the tool cannot claim "not found".
        (self.workspace / self.server.REPO_CONTEXT_FILE).write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            asyncio.run(self.server.delete_file(self.server.REPO_CONTEXT_FILE))

    def test_move_repo_context_file_refused(self):
        (self.workspace / self.server.REPO_CONTEXT_FILE).write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            asyncio.run(
                self.server.move_file(self.server.REPO_CONTEXT_FILE, "stolen.json")
            )

    def test_copy_into_git_dir_refused(self):
        (self.workspace / "payload.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(ValueError):
            asyncio.run(self.server.copy_file("payload.txt", ".git/config"))

    def test_move_into_git_dir_refused(self):
        (self.workspace / "payload.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(ValueError):
            asyncio.run(self.server.move_file("payload.txt", ".git/hooks/pre-commit"))

    def test_ordinary_write_still_allowed(self):
        # Guard must not block legitimate writes.
        result = asyncio.run(self.server.write_file("notes/todo.txt", "hi"))
        self.assertIn("Wrote", result)


if __name__ == "__main__":
    unittest.main()
