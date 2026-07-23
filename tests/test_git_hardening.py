"""Security regressions for the git-command policy classifier.

These cover trust-boundary bypasses in _ensure_git_context_for_command and its
helpers:
  * Fix 2 - RCE / policy bypass via git global prefix options (-c, -C, ...)
    and `git config --edit` slipping past the read-only classifier.
  * Fix 3 - remote branch deletion via an empty-source `:branch` refspec.
  * Fix 4 - force-push (-f/--force/--force-with-lease) and a leading `+`
    forced-update refspec.
  * Fix 5 - fetch/pull refspecs that update arbitrary local refs.

Setup mirrors tests/test_repo_context.py: a real git repo on `main` bound to a
configured repo context with default_branch=main.
"""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import importlib
import os
import tempfile
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

# Patches os.environ (auto-restored in tearDown) instead of mutating it
# directly — a direct mutation here previously leaked MCP_AUTH_MODE=legacy
# etc. into later test modules that inherit os.environ.
_ENV = {
    "MCP_TOKEN": "git-hardening-test-token",
    "MCP_PORT": "8768",
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


@unittest.skipUnless(shutil.which("git"), "git is required for git-policy tests")
class GitHardeningTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        ws = self.workspace
        subprocess.run(["git", "init"], cwd=ws, check=True, capture_output=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=ws, check=True, capture_output=True)
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/example/project.git"],
            cwd=ws, check=True, capture_output=True,
        )
        self.server = load_server(ws)
        self.server._save_repo_context(
            cwd=ws, status="configured",
            repository_url="https://github.com/example/project.git",
            is_fork=False, upstream_url="", default_branch="main",
            branch_mode="default_branch", commit_branch="", git_enabled=True,
            disabled_reason="",
            last_detected_origin="https://github.com/example/project.git",
            last_detected_branch="main",
        )

    def tearDown(self):
        self._tmp.cleanup()
        mock.patch.stopall()


    def _check(self, args):
        self.server._ensure_git_context_for_command(self.workspace, list(args))

    # -- Fix 2: dangerous global options + config --edit ------------------
    def test_dash_c_core_editor_config_edit_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["-c", "core.editor=touch", "config", "--edit"])
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_dash_C_retarget_refused(self):
        # -C on the bound workspace: detection still succeeds, so the refusal
        # must come from the global-option guard itself.
        with self.assertRaises(ValueError) as ctx:
            self._check(["-C", str(self.workspace), "status"])
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_config_edit_classified_as_mutating(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["config", "--edit"])
        self.assertIn("mutating git config", str(ctx.exception))

    def test_config_edit_short_flag_classified_as_mutating(self):
        self.assertFalse(self.server._is_git_config_read_only(["-e"]))
        self.assertFalse(self.server._is_git_config_read_only(["--edit"]))

    # -- Fix 3: empty-source (delete) refspec -----------------------------
    def test_push_delete_branch_refspec_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["push", "origin", ":main"])
        self.assertIn("blocked", str(ctx.exception).lower())

    # -- Fix 4: force-push and leading-+ refspec --------------------------
    def test_push_force_flag_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["push", "--force", "origin", "main"])
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_push_force_short_flag_refused(self):
        with self.assertRaises(ValueError):
            self._check(["push", "-f", "origin", "main"])

    def test_push_force_with_lease_refused(self):
        with self.assertRaises(ValueError):
            self._check(["push", "--force-with-lease", "origin", "main"])

    def test_push_plus_refspec_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["push", "origin", "+main"])
        self.assertIn("blocked", str(ctx.exception).lower())

    # -- Fix 5: fetch/pull local-ref refspecs -----------------------------
    def test_fetch_arbitrary_local_ref_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["fetch", "origin", "main:refs/heads/evil"])
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_fetch_plus_refspec_refused(self):
        with self.assertRaises(ValueError):
            self._check(["fetch", "origin", "+main:main"])

    def test_pull_arbitrary_local_ref_refused(self):
        with self.assertRaises(ValueError):
            self._check(["pull", "origin", "main:refs/heads/evil"])

    def test_fetch_target_branch_refspec_allowed(self):
        # A refspec that only updates the configured target branch is fine.
        self._check(["fetch", "origin", "main:refs/heads/main"])


if __name__ == "__main__":
    unittest.main()
