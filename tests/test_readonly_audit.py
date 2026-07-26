"""2.4.0 additions: read-only mode, the audit log, secret redaction, and the
MCP tool annotations.

Read-only mode has to be a structural guarantee, not a policy check: the
mutating tools must not be registered at all, so no scope grant, replayed
token or client bug can reach one. These tests assert the registry itself,
not just that a call is refused.
"""

import asyncio
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

_BASE_ENV = {
    "MCP_TOKEN": "readonly-audit-test-token-1234567890",
    "MCP_PORT": "8791",
    "MCP_ALLOW_COMMANDS": "1",
    "MCP_SERVEO_HOSTNAME": "",
    "MCP_AUTH_MODE": "legacy",
    "MCP_READ_ONLY": "0",
    "MCP_AUDIT_LOG": "",
}

WRITE_TOOLS = {
    "write_file", "append_file", "edit_file", "create_dir", "delete_file",
    "copy_file", "move_file", "run_command", "start_command", "cancel_command",
    "configure_repo_context", "setup_git_context",
}
READ_TOOLS = {
    "workspace_info", "list_dir", "file_info", "read_file", "tail_file",
    "glob_files", "grep_files", "repo_context_status", "inspect_git_repository",
}


def load_server(base_dir, **overrides):
    env = dict(_BASE_ENV, MCP_BASE_DIR=str(base_dir), **overrides)
    mock.patch.dict(os.environ, env).start()
    sys.modules.pop("server", None)
    return importlib.import_module("server")


def tool_names(srv):
    return {t.name for t in asyncio.run(srv.mcp.list_tools())}


class _ServerCase(unittest.TestCase):
    OVERRIDES: dict = {}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.server = load_server(self.workspace, **self.OVERRIDES)

    def tearDown(self):
        self._tmp.cleanup()
        mock.patch.stopall()
        sys.modules.pop("server", None)


class NormalModeRegistryTests(_ServerCase):
    def test_all_tools_registered(self):
        names = tool_names(self.server)
        self.assertTrue(WRITE_TOOLS <= names, WRITE_TOOLS - names)
        self.assertTrue(READ_TOOLS <= names, READ_TOOLS - names)


class ReadOnlyModeTests(_ServerCase):
    OVERRIDES = {"MCP_READ_ONLY": "1"}

    def test_mutating_tools_are_not_registered_at_all(self):
        names = tool_names(self.server)
        leaked = WRITE_TOOLS & names
        self.assertEqual(leaked, set(), f"mutating tools reachable in read-only mode: {leaked}")

    def test_read_tools_still_registered(self):
        names = tool_names(self.server)
        self.assertTrue(READ_TOOLS <= names, READ_TOOLS - names)

    def test_every_registered_tool_declares_read_only(self):
        for spec in asyncio.run(self.server.mcp.list_tools()):
            self.assertTrue(
                spec.annotations and spec.annotations.readOnlyHint,
                f"{spec.name} is registered in read-only mode without readOnlyHint",
            )

    def test_workspace_info_reports_the_mode(self):
        out = asyncio.run(self.server.workspace_info())
        self.assertIn("read-only mode", out)


class ToolAnnotationTests(_ServerCase):
    def setUp(self):
        super().setUp()
        self.specs = {t.name: t for t in asyncio.run(self.server.mcp.list_tools())}

    def test_every_tool_has_annotations(self):
        missing = [name for name, spec in self.specs.items() if spec.annotations is None]
        self.assertEqual(missing, [])

    def test_read_tools_are_marked_read_only_and_not_destructive(self):
        for name in READ_TOOLS:
            ann = self.specs[name].annotations
            self.assertTrue(ann.readOnlyHint, name)
            self.assertFalse(ann.destructiveHint, name)

    def test_write_tools_are_not_marked_read_only(self):
        for name in WRITE_TOOLS:
            self.assertFalse(self.specs[name].annotations.readOnlyHint, name)

    def test_destructive_tools_are_flagged(self):
        for name in ("delete_file", "write_file", "edit_file", "move_file", "run_command"):
            self.assertTrue(self.specs[name].annotations.destructiveHint, name)

    def test_command_tools_are_open_world(self):
        for name in ("run_command", "start_command"):
            self.assertTrue(self.specs[name].annotations.openWorldHint, name)

    def test_a_read_only_tool_cannot_be_declared_destructive(self):
        with self.assertRaises(RuntimeError):
            self.server.tool(self.server.SCOPE_FILES_READ, destructive=True)


class SecretRedactionTests(_ServerCase):
    def test_master_token_is_redacted_from_tool_output(self):
        leaked = f"config contains token={self.server.TOKEN} here"
        self.assertNotIn(self.server.TOKEN, self.server._clip(leaked))
        self.assertIn("[redacted]", self.server._clip(leaked))

    def test_ordinary_output_is_untouched(self):
        self.assertEqual(self.server._clip("nothing secret here"), "nothing secret here")

    def test_grep_output_cannot_leak_the_token(self):
        (self.workspace / "leak.env").write_text(
            f"MCP_TOKEN={self.server.TOKEN}\n", encoding="utf-8"
        )
        out = asyncio.run(self.server.grep_files("MCP_TOKEN", "."))
        self.assertIn("leak.env", out)
        self.assertNotIn(self.server.TOKEN, out)

    def test_short_values_are_not_used_as_redaction_patterns(self):
        # A 3-character secret would mangle unrelated output for no benefit.
        with mock.patch.object(self.server, "_SECRETS", ("ab",)):
            self.assertEqual(self.server._redact_secrets("cabbage"), "c[redacted]bage")
        self.assertTrue(all(len(s) >= 8 for s in self.server._SECRETS))


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.log = self.workspace / "audit.jsonl"
        self.server = load_server(self.workspace, MCP_AUDIT_LOG=str(self.log))

    def tearDown(self):
        self._tmp.cleanup()
        mock.patch.stopall()
        sys.modules.pop("server", None)

    def _records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line]

    def test_successful_call_is_recorded(self):
        asyncio.run(self.server.list_dir("."))
        records = self._records()
        self.assertTrue(records)
        entry = records[-1]
        self.assertEqual(entry["tool"], "list_dir")
        self.assertEqual(entry["outcome"], "ok")
        self.assertEqual(entry["client"], "legacy")
        self.assertIn("ts", entry)

    def test_failed_call_is_recorded_with_the_reason(self):
        with self.assertRaises(ValueError):
            asyncio.run(self.server.read_file("../../etc/passwd"))
        entry = self._records()[-1]
        self.assertEqual(entry["tool"], "read_file")
        self.assertEqual(entry["outcome"], "error")
        self.assertIn("ValueError", entry["detail"])

    def test_arguments_are_recorded_and_truncated(self):
        (self.workspace / "big.txt").write_text("x", encoding="utf-8")
        asyncio.run(self.server.write_file("big.txt", "y" * 5000))
        entry = self._records()[-1]
        self.assertEqual(entry["args"]["path"], "big.txt")
        self.assertLessEqual(len(entry["args"]["content"]), 200)

    def test_secrets_never_reach_the_log(self):
        with self.assertRaises(ValueError):
            asyncio.run(self.server.read_file(f"../{self.server.TOKEN}"))
        self.assertNotIn(self.server.TOKEN, self.log.read_text(encoding="utf-8"))

    def test_an_unwritable_log_never_breaks_the_tool(self):
        with mock.patch.object(self.server, "AUDIT_LOG_PATH", str(self.workspace / "no" / "such" / "dir" / "a.jsonl")):
            out = asyncio.run(self.server.list_dir("."))
        self.assertIsInstance(out, str)

    def test_disabled_by_default(self):
        srv = load_server(self.workspace)
        self.assertEqual(srv.AUDIT_LOG_PATH, "")
        asyncio.run(srv.list_dir("."))  # must not raise or create anything


if __name__ == "__main__":
    unittest.main()
