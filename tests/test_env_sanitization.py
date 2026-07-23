"""Security regression: child processes must not inherit server secrets.

Child processes spawned by run_command/start_command and the git subprocess
helpers used to inherit the server's full os.environ, leaking MCP_TOKEN and the
OAuth owner code/scopes into arbitrary allow-listed programs. The server now
scrubs those keys via _sanitized_env() while keeping the rest (PATH, ...) intact.

The module is re-imported per test with a known env (mirrors
tests/test_command_jobs.py / tests/test_repo_context.py).
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

# Isolated from the real os.environ: leaking MCP_OAUTH_OWNER_GRANT_SCOPES (etc.)
# into later test modules that do `os.environ.copy()` (e.g. test_oauth_flow.py's
# ServerProcess) silently changes their server's owner grant. Every test below
# patches os.environ instead of mutating it directly.
_ENV = {
    "MCP_TOKEN": "super-secret-token",
    "MCP_PORT": "8767",
    "MCP_ALLOW_COMMANDS": "1",
    "MCP_ALLOWED_COMMANDS": "git,python3",
    "MCP_SERVEO_HOSTNAME": "",
    "MCP_AUTH_MODE": "legacy",
    "MCP_OAUTH_OWNER_CODE": "owner-code-secret",
    "MCP_OAUTH_OWNER_GRANT_SCOPES": "mcp:files:write mcp:git",
    "MCP_OAUTH_STATE_DIR": "",
}


def load_server(base_dir):
    env = dict(_ENV, MCP_BASE_DIR=str(base_dir))
    mock.patch.dict(os.environ, env).start()
    sys.modules.pop("server", None)
    return importlib.import_module("server")


class SanitizedEnvUnitTests(unittest.TestCase):
    def tearDown(self):
        mock.patch.stopall()

    def test_secret_keys_removed_but_path_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = load_server(Path(tmp))
            env = server._sanitized_env()
            self.assertNotIn("MCP_TOKEN", env)
            self.assertNotIn("MCP_OAUTH_OWNER_CODE", env)
            self.assertNotIn("MCP_OAUTH_OWNER_GRANT_SCOPES", env)
            # Any MCP_OAUTH_* key must be dropped, even ones we did not enumerate.
            self.assertFalse(any(k.startswith("MCP_OAUTH_") for k in env))
            # Non-secret environment (PATH, ...) is preserved untouched.
            self.assertIn("PATH", env)
            self.assertEqual(env.get("PATH"), os.environ.get("PATH"))


class SpawnedProcessEnvTests(unittest.TestCase):
    def tearDown(self):
        mock.patch.stopall()

    def test_run_command_child_cannot_see_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = load_server(Path(tmp))
            code = (
                "import os;"
                "print('TOKEN=' + repr(os.environ.get('MCP_TOKEN')));"
                "print('OWNER=' + repr(os.environ.get('MCP_OAUTH_OWNER_CODE')));"
                "print('SCOPES=' + repr(os.environ.get('MCP_OAUTH_OWNER_GRANT_SCOPES')));"
                "print('HASPATH=' + repr(bool(os.environ.get('PATH'))))"
            )
            result = asyncio.run(
                server.run_command(program="python3", args=["-c", code])
            )
            self.assertIn("exit code: 0", result)
            self.assertIn("TOKEN=None", result)
            self.assertIn("OWNER=None", result)
            self.assertIn("SCOPES=None", result)
            self.assertIn("HASPATH=True", result)


if __name__ == "__main__":
    unittest.main()
