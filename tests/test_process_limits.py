import asyncio
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
os.environ["MCP_TOKEN"] = "unit-test-token"
os.environ["MCP_BASE_DIR"] = str(PROJECT)
os.environ["MCP_ALLOW_COMMANDS"] = "0"
# Tests may run inside an active MCP session; do not inherit its stable hostname.
os.environ["MCP_SERVEO_HOSTNAME"] = ""

import server


class ProcessLimitTests(unittest.TestCase):
    def test_output_is_bounded_and_process_is_stopped(self):
        async def scenario():
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('x' * 400000)",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr, timed_out, truncated = await server._capture_process(
                process, 10
            )
            self.assertFalse(timed_out)
            self.assertTrue(truncated)
            self.assertLessEqual(
                len(stdout) + len(stderr), server.MAX_COMMAND_OUTPUT
            )
            self.assertIsNotNone(process.returncode)

        asyncio.run(scenario())

    def test_timeout_stops_process(self):
        async def scenario():
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import time; time.sleep(10)",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _, timed_out, _ = await server._capture_process(process, 1)
            self.assertTrue(timed_out)
            self.assertIsNotNone(process.returncode)

        asyncio.run(scenario())

    def test_capture_process_to_files_is_bounded(self):
        async def scenario():
            with tempfile.TemporaryDirectory() as directory:
                stdout_path = Path(directory) / "stdout.txt"
                stderr_path = Path(directory) / "stderr.txt"
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 400000)",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                timed_out, truncated = await server._capture_process_to_files(
                    process, stdout_path, stderr_path, 10
                )
                self.assertFalse(timed_out)
                self.assertTrue(truncated)
                total = stdout_path.stat().st_size + stderr_path.stat().st_size
                self.assertLessEqual(total, server.MAX_COMMAND_OUTPUT)
                self.assertIsNotNone(process.returncode)

        asyncio.run(scenario())

    def test_read_file_can_continue_oversized_line(self):
        test_file = PROJECT / "temp-long-line-test.txt"
        long_line = "x" * 12000
        test_file.write_text(long_line, encoding="utf-8")
        try:
            first = asyncio.run(server.read_file(path=test_file.name, limit=1))
            self.assertIn("next char offset", first)
            self.assertIn("Call read_file", first)
            match = re.search(r"next offset (\d+)(?: \| next char offset (\d+))?", first)
            self.assertIsNotNone(match)
            next_offset = int(match.group(1))
            next_char_offset = int(match.group(2) or 0)
            self.assertEqual(next_offset, 0)
            self.assertGreater(next_char_offset, 0)
            second = asyncio.run(
                server.read_file(path=test_file.name, offset=next_offset, char_offset=next_char_offset, limit=1)
            )
            self.assertNotEqual(first, second)
        finally:
            test_file.unlink(missing_ok=True)

    def test_read_file_rejects_too_large_text_file(self):
        test_file = PROJECT / "temp-too-large-text.txt"
        oversized = "a" * (server.MAX_TEXT_FILE + 1024)
        test_file.write_text(oversized, encoding="utf-8")
        try:
            with self.assertRaises(ValueError) as caught:
                asyncio.run(server.read_file(path=test_file.name))
            self.assertIn("File is too large", str(caught.exception))
        finally:
            test_file.unlink(missing_ok=True)

    def test_commands_default_to_disabled(self):
        self.assertFalse(server.ALLOW_COMMANDS)


class AtomicWriteTests(unittest.TestCase):
    def test_atomic_write_replaces_content_and_leaves_no_temp(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "file.txt"
            target.write_text("old", encoding="utf-8")
            server._atomic_write_text(target, "новый текст")
            self.assertEqual(target.read_text(encoding="utf-8"), "новый текст")
            self.assertEqual(list(Path(directory).iterdir()), [target])


class HostCheckTests(unittest.TestCase):
    def test_localhost_allowed(self):
        self.assertTrue(server._host_allowed("127.0.0.1:8765"))
        self.assertTrue(server._host_allowed("localhost"))

    def test_serveo_suffix_allowed_without_stable_hostname(self):
        self.assertTrue(server._host_allowed("abc.serveousercontent.com"))

    def test_foreign_host_rejected(self):
        self.assertFalse(server._host_allowed("evil.example.com"))
        self.assertFalse(server._host_allowed(""))


if __name__ == "__main__":
    unittest.main()
