import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def load_server(workspace: Path):
    os.environ["MCP_TOKEN"] = "repo-context-test-token"
    os.environ["MCP_BASE_DIR"] = str(workspace)
    os.environ["MCP_PORT"] = "8765"
    os.environ["MCP_ALLOW_COMMANDS"] = "1"
    os.environ["MCP_ALLOWED_COMMANDS"] = "git,python"
    os.environ["MCP_SERVEO_HOSTNAME"] = ""
    sys.modules.pop("server", None)
    return importlib.import_module("server")


class RepoContextTests(unittest.TestCase):
    def test_normalize_repo_url_matches_https_and_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = load_server(Path(tmp))
            self.assertEqual(
                server._normalize_repo_url(
                    "https://github.com/LEADBERG-studio/notion-local-mcp-easy.git"
                ),
                "github.com/leadberg-studio/notion-local-mcp-easy",
            )
            self.assertEqual(
                server._normalize_repo_url(
                    "git@github.com:LEADBERG-studio/notion-local-mcp-easy.git"
                ),
                "github.com/leadberg-studio/notion-local-mcp-easy",
            )

    def test_missing_git_repo_prompts_for_user_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            server = load_server(workspace)
            summary = server._repo_context_summary(workspace)
            self.assertIn("repo context status: missing", summary)
            self.assertIn("init_new_repo, attach_to_remote, or disable_git", summary)

    def test_disable_git_persists_and_blocks_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            server = load_server(workspace)
            result = server._setup_git_context_sync(
                workspace,
                mode="disable_git",
                disable_reason="user chose to keep git off",
            )
            self.assertIn("Saved disabled git policy", result)
            config = server._load_repo_context()
            self.assertEqual(config["status"], "disabled")
            self.assertFalse(config["git_enabled"])
            self.assertEqual(config["disabled_reason"], "user chose to keep git off")
            with self.assertRaises(ValueError) as caught:
                server._ensure_git_context_for_command(workspace)
            self.assertIn("disabled by user", str(caught.exception))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_attach_to_remote_initializes_repo_and_allows_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            server = load_server(workspace)
            result = server._setup_git_context_sync(
                workspace,
                mode="attach_to_remote",
                repository_url="https://github.com/example/project.git",
                fork_status="fork",
                default_branch="main",
            )
            self.assertIn("initialized git repository", result)
            detected = server._detect_git_repo(workspace)
            self.assertTrue(detected["repo_present"])
            self.assertEqual(
                detected["normalized_origin_url"],
                "github.com/example/project",
            )
            config = server._load_repo_context()
            self.assertEqual(config["status"], "configured")
            self.assertTrue(config["is_fork"])
            server._ensure_git_context_for_command(workspace)

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_bind_existing_repo_without_git_repo_tells_user_to_choose(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            server = load_server(workspace)
            with self.assertRaises(ValueError) as caught:
                server._setup_git_context_sync(
                    workspace,
                    mode="bind_existing_repo",
                    repository_url="https://github.com/example/project.git",
                    fork_status="not_fork",
                )
            self.assertIn("init_new_repo, attach_to_remote, or disable_git", str(caught.exception))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_bind_existing_repo_can_force_update_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(
                ["git", "remote", "add", "origin", "https://github.com/example/old-project.git"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            server = load_server(workspace)
            result = server._setup_git_context_sync(
                workspace,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/new-project.git",
                fork_status="not_fork",
                force_origin_update=True,
            )
            self.assertIn("updated remote origin", result)
            detected = server._detect_git_repo(workspace)
            self.assertEqual(
                detected["normalized_origin_url"],
                "github.com/example/new-project",
            )
            server._ensure_git_context_for_command(workspace)

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_specified_branch_blocks_commit_on_other_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            server = load_server(workspace)
            server._setup_git_context_sync(
                workspace,
                mode="attach_to_remote",
                repository_url="https://github.com/example/project.git",
                fork_status="fork",
                default_branch="main",
                branch_mode="specified_branch",
                commit_branch="stablefix",
            )
            with self.assertRaises(ValueError) as caught:
                server._ensure_git_context_for_command(workspace, ["commit", "-m", "test"])
            self.assertIn("configured to commit on stablefix", str(caught.exception))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_origin_mismatch_blocks_git_after_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(
                ["git", "branch", "-M", "main"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "remote", "add", "origin", "https://github.com/example/project.git"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            server = load_server(workspace)
            server._save_repo_context(
                status="configured",
                repository_url="https://github.com/example/project.git",
                is_fork=False,
                upstream_url="",
                default_branch="main",
                branch_mode="default_branch",
                commit_branch="",
                git_enabled=True,
                disabled_reason="",
                last_detected_origin="https://github.com/example/project.git",
                last_detected_branch="main",
            )
            subprocess.run(
                ["git", "remote", "set-url", "origin", "https://github.com/example/other-project.git"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            with self.assertRaises(ValueError) as caught:
                server._ensure_git_context_for_command(workspace)
            self.assertIn("repo context check: mismatch", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
