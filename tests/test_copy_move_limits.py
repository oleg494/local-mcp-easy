import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import server


class CopyMoveSizeCapTests(unittest.TestCase):
    """§4d: copy_file/move_file reject sources larger than
    MAX_COPY_MOVE_BYTES. The cap prevents a client holding mcp:files:write
    from exhausting disk by duplicating a multi-GB artifact. It must sit
    AFTER the _ensure_writable trust-anchor guard (added in 2.2.1), never
    replace it.
    """

    def setUp(self):
        # Work inside BASE_DIR so the workspace path guards accept the paths.
        self._tmp = tempfile.TemporaryDirectory(dir=str(server.BASE_DIR))
        self.root = Path(self._tmp.name)
        self.rel = self.root.relative_to(server.BASE_DIR).as_posix()

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name: str, size: int) -> str:
        (self.root / name).write_bytes(b"x" * size)
        return f"{self.rel}/{name}"

    def test_default_cap_is_100_mib(self):
        self.assertEqual(server.MAX_COPY_MOVE_BYTES, 100 * 1024 * 1024)

    def test_copy_file_rejects_oversized_source(self):
        src = self._write("big.bin", 200)
        with mock.patch.object(server, "MAX_COPY_MOVE_BYTES", 100):
            with self.assertRaises(ValueError) as ctx:
                asyncio.run(server.copy_file(src, f"{self.rel}/big-copy.bin"))
        self.assertIn("size", str(ctx.exception).lower())
        self.assertFalse((self.root / "big-copy.bin").exists())

    def test_copy_file_allows_under_cap(self):
        src = self._write("small.bin", 50)
        with mock.patch.object(server, "MAX_COPY_MOVE_BYTES", 100):
            out = asyncio.run(server.copy_file(src, f"{self.rel}/small-copy.bin"))
        self.assertIn("Copied", out)
        self.assertTrue((self.root / "small-copy.bin").exists())

    def test_move_file_rejects_oversized_source(self):
        src = self._write("bigmove.bin", 200)
        with mock.patch.object(server, "MAX_COPY_MOVE_BYTES", 100):
            with self.assertRaises(ValueError) as ctx:
                asyncio.run(server.move_file(src, f"{self.rel}/bigmove-dst.bin"))
        self.assertIn("size", str(ctx.exception).lower())
        # Rejected before the move: source stays, destination is not created.
        self.assertTrue((self.root / "bigmove.bin").exists())
        self.assertFalse((self.root / "bigmove-dst.bin").exists())

    def test_move_file_allows_under_cap(self):
        src = self._write("smallmove.bin", 50)
        with mock.patch.object(server, "MAX_COPY_MOVE_BYTES", 100):
            out = asyncio.run(server.move_file(src, f"{self.rel}/smallmove-dst.bin"))
        self.assertIn("Moved", out)
        self.assertTrue((self.root / "smallmove-dst.bin").exists())
        self.assertFalse((self.root / "smallmove.bin").exists())


if __name__ == "__main__":
    unittest.main()
