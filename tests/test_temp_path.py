"""The @temp/ virtual path scheme -- previously untested end to end.

_resolve_temp_path is the only traversal guard for `@temp/`, and it maps onto
the server's own directory (SERVER_DIR/temp), not BASE_DIR, so safe_path never
sees these paths. A regression here escapes the workspace by definition.
"""

import asyncio
import os
import sys
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


class ResolveTempPathTests(unittest.TestCase):
    def test_resolves_under_the_temp_dir(self):
        resolved = server._resolve_temp_path("@temp/report.txt")
        self.assertEqual(resolved.parent.resolve(), server._temp_dir().resolve())
        self.assertEqual(resolved.name, "report.txt")

    def test_backslashes_are_normalised(self):
        resolved = server._resolve_temp_path("@temp\\report.txt")
        self.assertEqual(resolved.name, "report.txt")

    def test_traversal_is_rejected(self):
        for bad in (
            "@temp/../secret",
            "@temp/..",
            "@temp/sub/x",
            "@temp/sub\\x",
            "@temp/",
            "@temp/   ",
            "@temp/..\\..\\secret",
        ):
            with self.assertRaises(ValueError, msg=bad):
                server._resolve_temp_path(bad)

    def test_non_temp_path_is_rejected(self):
        with self.assertRaises(ValueError):
            server._resolve_temp_path("notes.txt")


class ResolveReadFilePathTests(unittest.TestCase):
    def test_temp_prefix_routes_to_the_temp_dir(self):
        resolved, is_temp = server._resolve_read_file_path("@temp/x.txt")
        self.assertTrue(is_temp)
        self.assertEqual(resolved.parent.resolve(), server._temp_dir().resolve())

    def test_ordinary_path_routes_through_the_workspace_guard(self):
        resolved, is_temp = server._resolve_read_file_path("README.md")
        self.assertFalse(is_temp)
        self.assertEqual(resolved, server.BASE_DIR / "README.md")

    def test_ordinary_path_outside_workspace_is_rejected(self):
        with self.assertRaises(ValueError):
            server._resolve_read_file_path("../../etc/passwd")


class TempRoundTripTests(unittest.TestCase):
    """A saved tool output must be readable back through @temp/, and must be
    deleted once it has been read completely (the is_complete unlink branch)."""

    def setUp(self):
        self.path = server._tool_output_path("temp-roundtrip-test")
        self.path.write_text("line one\nline two\n", encoding="utf-8")
        self.virtual = server._temp_virtual_path(self.path)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_virtual_path_shape(self):
        self.assertTrue(self.virtual.startswith("@temp/"))
        self.assertNotIn("/", self.virtual[len("@temp/"):])

    def test_read_back_and_consume(self):
        out = asyncio.run(server.read_file(self.virtual))
        self.assertIn("line one", out)
        self.assertIn("line two", out)
        # Fully read => the temp file is cleaned up behind us.
        self.assertFalse(self.path.exists())

    def test_partial_read_keeps_the_file(self):
        out = asyncio.run(server.read_file(self.virtual, limit=1))
        self.assertIn("line one", out)
        self.assertTrue(self.path.exists())


class TailFileTests(unittest.TestCase):
    def setUp(self):
        self.path = server._tool_output_path("tail-test")
        self.path.write_text("".join(f"line {n}\n" for n in range(1, 31)), encoding="utf-8")
        self.virtual = server._temp_virtual_path(self.path)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_returns_the_last_n_lines(self):
        out = asyncio.run(server.tail_file(self.virtual, lines=3))
        self.assertIn("line 28", out)
        self.assertIn("line 30", out)
        self.assertNotIn("line 27", out)

    def test_reports_position_in_the_file(self):
        out = asyncio.run(server.tail_file(self.virtual, lines=3))
        self.assertIn("last 3 of 30 lines", out)
        self.assertIn("starting at line 28", out)

    def test_more_lines_requested_than_exist(self):
        out = asyncio.run(server.tail_file(self.virtual, lines=999))
        self.assertIn("line 1\n", out)
        self.assertIn("last 30 of 30 lines", out)

    def test_zero_or_negative_clamps_to_one(self):
        out = asyncio.run(server.tail_file(self.virtual, lines=0))
        self.assertIn("last 1 of 30 lines", out)

    def test_missing_file_raises(self):
        with self.assertRaises(ValueError):
            asyncio.run(server.tail_file("does-not-exist-anywhere.txt"))

    def test_outside_workspace_is_rejected(self):
        with self.assertRaises(ValueError):
            asyncio.run(server.tail_file("../../etc/passwd"))


if __name__ == "__main__":
    unittest.main()
