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
# Tests may run inside an active MCP session; do not inherit its stable hostname
# or auth mode. In oauth/dual the per-tool scope gate needs a request auth
# context, which direct in-process tool calls do not have.
os.environ["MCP_SERVEO_HOSTNAME"] = ""
os.environ["MCP_AUTH_MODE"] = "legacy"

import server


class ProcessLimitTests(unittest.TestCase):
    def test_timeout_stops_process(self):
        async def scenario():
            with tempfile.TemporaryDirectory() as directory:
                stdout_path = Path(directory) / "stdout.txt"
                stderr_path = Path(directory) / "stderr.txt"
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    "import time; time.sleep(10)",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                timed_out, _ = await server._capture_process_to_files(
                    process, stdout_path, stderr_path, 1
                )
                self.assertTrue(timed_out)
                self.assertIsNotNone(process.returncode)

        asyncio.run(scenario())

    @unittest.skipIf(os.name == "nt", "process groups are a POSIX concept")
    def test_kill_tree_never_signals_our_own_process_group(self):
        """A child that is NOT its own group leader must be killed alone.

        _kill_tree signals the process group so a timed-out `npm run x` cannot
        leave grandchildren behind. But a process spawned without
        start_new_session shares the SERVER's group, and signalling that group
        SIGKILLs the server itself. This happened: the timeout test above
        builds its own subprocess, and the first version of the group-kill took
        down the entire test run on every POSIX CI cell while Windows stayed
        green (taskkill /T targets one PID's tree, so it never had the bug).

        The assertion is simply that this test survives to make it.
        """
        import signal

        async def scenario():
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "import time; time.sleep(30)",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            # Precondition: the child shares our group, so a naive killpg here
            # would target the test runner.
            self.assertEqual(os.getpgid(process.pid), os.getpgid(0))
            self.assertNotEqual(os.getpgid(process.pid), process.pid)
            await server._kill_tree(process)
            self.assertIsNotNone(process.returncode)

        asyncio.run(scenario())
        # Reached only if we were not killed along with the child.
        self.assertTrue(signal.SIGKILL)

    @unittest.skipIf(os.name == "nt", "process groups are a POSIX concept")
    def test_kill_tree_reaps_grandchildren_of_a_session_leader(self):
        """The behaviour the group-kill exists for, on a correctly spawned child."""
        async def scenario():
            # Same spawn options _spawn_process uses.
            parent = await asyncio.create_subprocess_exec(
                sys.executable, "-c",
                "import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                "time.sleep(30)",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            self.assertEqual(os.getpgid(parent.pid), parent.pid)
            await asyncio.sleep(1.0)  # let the grandchild start
            group = os.getpgid(parent.pid)
            await server._kill_tree(parent)
            self.assertIsNotNone(parent.returncode)
            # The whole group is gone, grandchild included.
            with self.assertRaises(ProcessLookupError):
                os.killpg(group, 0)

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
