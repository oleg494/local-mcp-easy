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
    # Do not inherit oauth/dual from an active MCP session: the per-tool scope
    # gate would reject direct in-process tool calls that have no auth context.
    os.environ["MCP_AUTH_MODE"] = "legacy"
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

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_configure_requires_confirm_defaults_for_inferred_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/project.git"], cwd=workspace, check=True, capture_output=True)
            server = load_server(workspace)
            import asyncio
            with self.assertRaises(ValueError) as caught:
                asyncio.run(
                    server.configure_repo_context(
                        repository_url="https://github.com/example/project.git",
                        is_fork=False,
                        cwd=str(workspace),
                    )
                )
            self.assertIn("confirm_defaults=true", str(caught.exception))

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
                server._ensure_git_context_for_command(workspace, ["status"])
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
            server._ensure_git_context_for_command(workspace, ["status"])

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
            with self.assertRaises(ValueError) as caught:
                server._setup_git_context_sync(
                    workspace,
                    mode="bind_existing_repo",
                    repository_url="https://github.com/example/new-project.git",
                    fork_status="not_fork",
                    default_branch="main",
                    force_origin_update=True,
                )
            self.assertIn("confirm_reconfigure=true", str(caught.exception))
            result = server._setup_git_context_sync(
                workspace,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/new-project.git",
                fork_status="not_fork",
                force_origin_update=True,
                confirm_reconfigure=True,
                confirm_defaults=True,
            )
            self.assertIn("updated remote origin", result)
            detected = server._detect_git_repo(workspace)
            self.assertEqual(
                detected["normalized_origin_url"],
                "github.com/example/new-project",
            )
            server._ensure_git_context_for_command(workspace, ["status"])

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
            self.assertIn("configured to work on stablefix", str(caught.exception))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_mutating_git_commands_respect_repo_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/project.git"], cwd=workspace, check=True, capture_output=True)
            server = load_server(workspace)
            server._save_repo_context(
                cwd=workspace,
                status="configured",
                repository_url="https://github.com/example/project.git",
                is_fork=False,
                upstream_url="",
                default_branch="main",
                branch_mode="specified_branch",
                commit_branch="stablefix",
                git_enabled=True,
                disabled_reason="",
                last_detected_origin="https://github.com/example/project.git",
                last_detected_branch="main",
            )
            for args in (["reset", "--hard"], ["checkout", "-B", "other"], ["config", "user.name", "oops"]):
                with self.assertRaises(ValueError):
                    server._ensure_git_context_for_command(workspace, list(args))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_push_multi_ref_modes_are_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/project.git"], cwd=workspace, check=True, capture_output=True)
            server = load_server(workspace)
            server._save_repo_context(
                cwd=workspace, status="configured",
                repository_url="https://github.com/example/project.git",
                is_fork=False, upstream_url="", default_branch="main",
                branch_mode="default_branch", commit_branch="", git_enabled=True,
                disabled_reason="", last_detected_origin="https://github.com/example/project.git",
                last_detected_branch="main",
            )
            for args in (["push", "--all", "origin"], ["push", "--mirror", "origin"], ["push", "--tags", "origin"], ["push", "--delete", "origin", "main"]):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    server._ensure_git_context_for_command(workspace, list(args))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_push_without_remote_validates_effective_branch_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/project.git"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "evil", "https://github.com/example/other.git"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "config", "branch.main.remote", "evil"], cwd=workspace, check=True, capture_output=True)
            server = load_server(workspace)
            server._save_repo_context(
                cwd=workspace, status="configured",
                repository_url="https://github.com/example/project.git",
                is_fork=False, upstream_url="", default_branch="main",
                branch_mode="default_branch", commit_branch="", git_enabled=True,
                disabled_reason="", last_detected_origin="https://github.com/example/project.git",
                last_detected_branch="main",
            )
            with self.assertRaises(ValueError) as caught:
                server._ensure_git_context_for_command(workspace, ["push"])
            self.assertIn("outside the approved repo context", str(caught.exception))
            subprocess.run(["git", "config", "branch.main.remote", "origin"], cwd=workspace, check=True, capture_output=True)
            server._ensure_git_context_for_command(workspace, ["push"])

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_git_dash_c_target_repo_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            other_repo = workspace / "other"
            other_repo.mkdir()
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/project.git"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "init"], cwd=other_repo, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=other_repo, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/other-project.git"], cwd=other_repo, check=True, capture_output=True)
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
            with self.assertRaises(ValueError) as caught:
                server._ensure_git_context_for_command(workspace, ["-C", str(other_repo), "status"])
            self.assertIn("repo context status: missing", str(caught.exception))

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_configure_repo_context_respects_nested_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            nested_repo = workspace / "nested"
            nested_repo.mkdir()
            subprocess.run(["git", "init"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "nested-main"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/nested-project.git"], cwd=nested_repo, check=True, capture_output=True)
            server = load_server(workspace)
            import asyncio
            asyncio.run(
                server.configure_repo_context(
                    repository_url="https://github.com/example/nested-project.git",
                    is_fork=False,
                    default_branch="nested-main",
                    cwd=str(nested_repo),
                )
            )
            self.assertFalse((workspace / server.REPO_CONTEXT_FILE).exists())
            self.assertTrue((nested_repo / server.REPO_CONTEXT_FILE).is_file())
            nested_config = server._load_repo_context(nested_repo)
            self.assertEqual(nested_config["normalized_repository_url"], "github.com/example/nested-project")

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_nested_repos_get_separate_local_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            nested_repo = workspace / "nested"
            nested_repo.mkdir()
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/root-project.git"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "init"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "nested-main"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/nested-project.git"], cwd=nested_repo, check=True, capture_output=True)
            server = load_server(workspace)
            server._setup_git_context_sync(
                workspace,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/root-project.git",
                fork_status="not_fork",
                default_branch="main",
            )
            server._setup_git_context_sync(
                nested_repo,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/nested-project.git",
                fork_status="not_fork",
                default_branch="nested-main",
            )
            root_config = server._load_repo_context(workspace)
            nested_config = server._load_repo_context(nested_repo)
            self.assertEqual(root_config["normalized_repository_url"], "github.com/example/root-project")
            self.assertEqual(nested_config["normalized_repository_url"], "github.com/example/nested-project")
            self.assertTrue((workspace / server.REPO_CONTEXT_FILE).is_file())
            self.assertTrue((nested_repo / server.REPO_CONTEXT_FILE).is_file())
            server._ensure_git_context_for_command(workspace, ["status"])
            server._ensure_git_context_for_command(nested_repo, ["status"])

    @unittest.skipUnless(shutil.which("git"), "git is required for repo-context git tests")
    def test_workspace_info_lists_nested_repos(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            nested_repo = workspace / "nested"
            nested_repo.mkdir()
            subprocess.run(["git", "init"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "main"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/root-project.git"], cwd=workspace, check=True, capture_output=True)
            subprocess.run(["git", "init"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-M", "nested-main"], cwd=nested_repo, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/nested-project.git"], cwd=nested_repo, check=True, capture_output=True)
            server = load_server(workspace)
            server._setup_git_context_sync(
                workspace,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/root-project.git",
                fork_status="not_fork",
                default_branch="main",
                confirm_defaults=True,
            )
            server._setup_git_context_sync(
                nested_repo,
                mode="bind_existing_repo",
                repository_url="https://github.com/example/nested-project.git",
                fork_status="not_fork",
                default_branch="nested-main",
                confirm_defaults=True,
            )
            import asyncio
            overview = asyncio.run(server.workspace_info())
            self.assertIn("root repo:", overview)
            self.assertIn("nested repos: 1", overview)
            self.assertIn("nested", overview)

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
                server._ensure_git_context_for_command(workspace, ["status"])
            self.assertIn("repo context check: mismatch", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
