import asyncio
import os
import sys
import tempfile
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


class AsyncFilesystemToolTests(unittest.TestCase):
    """Behaviour-preserving checks for the read-only fs tools that were moved
    onto asyncio.to_thread so their blocking I/O no longer stalls the loop."""

    def setUp(self):
        # Work inside BASE_DIR so the workspace path guards accept the paths.
        self._tmp = tempfile.TemporaryDirectory(dir=str(server.BASE_DIR))
        self.root = Path(self._tmp.name)
        self.rel = self.root.relative_to(server.BASE_DIR).as_posix()
        (self.root / "alpha.py").write_text("print('a')\n", encoding="utf-8")
        (self.root / "beta.txt").write_text("hello world\n", encoding="utf-8")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "gamma.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_A_list_dir_lists_entries(self):
        out = asyncio.run(server.list_dir(self.rel))
        self.assertIn("alpha.py", out)
        self.assertIn("beta.txt", out)
        self.assertIn("sub", out)

    def test_A_list_dir_recursive_includes_nested(self):
        out = asyncio.run(server.list_dir(self.rel, recursive=True))
        self.assertIn("alpha.py", out)
        self.assertIn(str(Path("sub") / "gamma.py"), out)

    def test_A_list_dir_rejects_non_directory(self):
        with self.assertRaises(ValueError):
            asyncio.run(server.list_dir(f"{self.rel}/alpha.py"))

    def test_A_glob_files_matches_pattern(self):
        out = asyncio.run(server.glob_files("**/*.py", self.rel))
        self.assertIn("alpha.py", out)
        self.assertIn(str(Path("sub") / "gamma.py"), out)
        self.assertNotIn("beta.txt", out)

    def test_A_file_info_reports_metadata(self):
        out = asyncio.run(server.file_info(f"{self.rel}/beta.txt"))
        self.assertIn("type: file", out)
        self.assertIn("beta.txt", out)

    def test_A_file_info_missing_path(self):
        out = asyncio.run(server.file_info(f"{self.rel}/nope.txt"))
        self.assertIn("Not found", out)


if __name__ == "__main__":
    unittest.main()
