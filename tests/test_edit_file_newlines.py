import asyncio
import os
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import server


def _lone_cr(data: bytes) -> int:
    """Count carriage returns that are NOT part of a CRLF pair."""
    return data.count(b"\r") - data.count(b"\r\n")


class EditFileNewlineTests(unittest.TestCase):
    def _tmp(self, name: str) -> Path:
        return PROJECT / name

    def test_edit_file_does_not_accumulate_cr_on_crlf_file(self):
        path = self._tmp("temp-newline-edit.py")
        path.write_bytes(b"line one\r\nline two\r\nline three\r\n")
        try:
            self.assertEqual(_lone_cr(path.read_bytes()), 0)
            asyncio.run(server.edit_file(path.name, "line two", "line two v1"))
            after_first = _lone_cr(path.read_bytes())
            asyncio.run(server.edit_file(path.name, "line two v1", "line two v2"))
            after_second = _lone_cr(path.read_bytes())
            self.assertEqual(after_first, 0, f"edit_file introduced lone CR: {after_first}")
            self.assertEqual(after_second, 0, f"edit_file introduced lone CR: {after_second}")
            self.assertEqual(path.read_bytes().count(b"\r\n"), 3)
        finally:
            path.unlink(missing_ok=True)

    def test_write_file_keeps_lf_only_content(self):
        path = self._tmp("temp-newline-write-lf.txt")
        try:
            asyncio.run(server.write_file(path.name, "alpha\nbeta\ngamma\n"))
            self.assertEqual(path.read_bytes(), b"alpha\nbeta\ngamma\n")
        finally:
            path.unlink(missing_ok=True)

    def test_write_file_writes_crlf_verbatim(self):
        path = self._tmp("temp-newline-write-crlf.txt")
        try:
            asyncio.run(server.write_file(path.name, "alpha\r\nbeta\r\n"))
            self.assertEqual(path.read_bytes(), b"alpha\r\nbeta\r\n")
        finally:
            path.unlink(missing_ok=True)

    def test_append_file_does_not_accumulate_cr(self):
        path = self._tmp("temp-newline-append.py")
        path.write_bytes(b"line one\r\nline two\r\n")
        try:
            for i in range(3):
                asyncio.run(server.append_file(path.name, f"added {i}\r\n"))
            self.assertEqual(_lone_cr(path.read_bytes()), 0)
        finally:
            path.unlink(missing_ok=True)

    def test_atomic_write_text_preserves_crlf(self):
        path = self._tmp("temp-newline-atomic.txt")
        try:
            server._atomic_write_text(path, "one\r\ntwo\r\n")
            self.assertEqual(path.read_bytes(), b"one\r\ntwo\r\n")
            self.assertEqual(_lone_cr(path.read_bytes()), 0)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
