"""Tests for v2.2 background command jobs.

Covers:
  * security parity between run_command and start_command (both go through
    _prepare_command, so their allow-list / cwd / trusted-mode checks must be
    byte-for-byte identical),
  * the concurrency cap,
  * TTL + count-based pruning of finished jobs,
  * the graceful-shutdown hook (both the standalone cleanup and the lifespan
    wrapper installed on the app),
  * live end-to-end execution: a short job matches run_command, several jobs
    run in parallel with distinct ids, and a long job can be cancelled.

The module is re-imported per test with a known env (mirrors
tests/test_repo_context.py) so behaviour does not depend on import order in the
combined suite, and every test gets a fresh _JOBS registry.
"""

import asyncio
import contextlib
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def load_server(base_dir, *, allow_commands="1", max_jobs=None):
    os.environ["MCP_TOKEN"] = "command-jobs-test-token"
    os.environ["MCP_BASE_DIR"] = str(base_dir)
    os.environ["MCP_PORT"] = "8766"
    os.environ["MCP_ALLOW_COMMANDS"] = allow_commands
    os.environ["MCP_ALLOWED_COMMANDS"] = "git,python"
    os.environ["MCP_SERVEO_HOSTNAME"] = ""
    os.environ["MCP_AUTH_MODE"] = "legacy"
    if max_jobs is None:
        os.environ.pop("MCP_MAX_COMMAND_JOBS", None)
    else:
        os.environ["MCP_MAX_COMMAND_JOBS"] = str(max_jobs)
    sys.modules.pop("server", None)
    return importlib.import_module("server")


class _JobTestBase(unittest.TestCase):
    allow_commands = "1"
    max_jobs = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.server = load_server(
            self.tmp,
            allow_commands=self.allow_commands,
            max_jobs=self.max_jobs,
        )

    def tearDown(self):
        s = self.server
        for job in list(s._JOBS.values()):
            task = getattr(job, "task", None)
            if task is not None and not task.done():
                task.cancel()
            proc = getattr(job, "proc", None)
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
            with contextlib.suppress(Exception):
                s._delete_job_files(job)
        s._JOBS.clear()
        self._tmp.cleanup()

    # -- helpers --------------------------------------------------------
    def _parse_job_id(self, started_message):
        # First line is "Started job {job_id}: {command}".
        return started_message.splitlines()[0].split()[2].rstrip(":")

    def _new_job(self, job_id, *, status, finished_at=None, created_at=None,
                 write_files=True):
        s = self.server
        stdout = s._tool_output_path(f"jobtest-{job_id}-stdout")
        stderr = s._tool_output_path(f"jobtest-{job_id}-stderr")
        if write_files:
            stdout.write_text("out", encoding="utf-8")
            stderr.write_text("err", encoding="utf-8")
        job = s.CommandJob(
            job_id=job_id,
            program="python",
            args=[],
            cwd=".",
            executable="python",
            workdir=str(self.tmp),
            seconds=10,
            stdout_path=stdout,
            stderr_path=stderr,
            created_at=created_at if created_at is not None else s._now(),
        )
        job.status = status
        if status in s._TERMINAL_JOB_STATES:
            job.finished_at = finished_at if finished_at is not None else s._now()
        s._JOBS[job_id] = job
        return job


class SecurityParityTests(_JobTestBase):
    """run_command and start_command must reject identically."""

    def _assert_parity(self, program, args=None, cwd="."):
        with self.assertRaises(ValueError) as run_ctx:
            asyncio.run(self.server.run_command(program=program, args=args, cwd=cwd))
        with self.assertRaises(ValueError) as start_ctx:
            asyncio.run(self.server.start_command(program=program, args=args, cwd=cwd))
        self.assertEqual(str(run_ctx.exception), str(start_ctx.exception))
        return str(run_ctx.exception)

    def test_missing_program_rejected_identically(self):
        msg = self._assert_parity("")
        self.assertIn("Program is required", msg)

    def test_not_in_allowlist_rejected_identically(self):
        msg = self._assert_parity("curl", ["--version"])
        self.assertIn("is not allowed", msg)

    def test_path_qualified_rejected_identically(self):
        # basename is allow-listed ("python") but it is path-qualified, so both
        # tools must reject it before ever resolving/spawning.
        msg = self._assert_parity("sub/python", ["-c", "pass"])
        self.assertIn("Path-qualified", msg)

    def test_bad_cwd_rejected_identically(self):
        msg = self._assert_parity("python", ["-c", "pass"], cwd="does-not-exist")
        self.assertIn("cwd is not a directory", msg)


class DisabledModeParityTests(_JobTestBase):
    allow_commands = "0"

    def test_both_disabled_when_commands_off(self):
        with self.assertRaises(ValueError) as run_ctx:
            asyncio.run(self.server.run_command(program="python", args=["-c", "pass"]))
        with self.assertRaises(ValueError) as start_ctx:
            asyncio.run(self.server.start_command(program="python", args=["-c", "pass"]))
        self.assertEqual(str(run_ctx.exception), str(start_ctx.exception))
        self.assertIn("Command execution is disabled", str(run_ctx.exception))
        # Trusted mode really is off in this configuration.
        self.assertFalse(self.server.ALLOW_COMMANDS)


class ConcurrencyCapTests(_JobTestBase):
    def test_start_rejected_when_cap_reached(self):
        s = self.server
        s.MAX_CONCURRENT_JOBS = 2
        self._new_job("run-a", status="running", write_files=False)
        self._new_job("run-b", status="running", write_files=False)
        self.assertEqual(s._running_job_count(), 2)
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(s.start_command(program="python", args=["-c", "pass"]))
        self.assertIn("Too many background commands running (2/2)", str(ctx.exception))
        # No extra job was registered by the rejected call.
        self.assertEqual(len(s._JOBS), 2)

    def test_finished_jobs_do_not_count_against_cap(self):
        s = self.server
        s.MAX_CONCURRENT_JOBS = 1
        self._new_job("done-a", status="done")
        # A finished job must not block a new start.
        self.assertEqual(s._running_job_count(), 0)


class PruningTests(_JobTestBase):
    def test_ttl_prunes_expired_and_deletes_files(self):
        s = self.server
        old = self._new_job(
            "old", status="done",
            finished_at=s._now() - (s.JOB_RETENTION_SECONDS + 100),
        )
        fresh = self._new_job("fresh", status="done", finished_at=s._now())
        self.assertTrue(old.stdout_path.exists())
        s._prune_jobs()
        self.assertNotIn("old", s._JOBS)
        self.assertIn("fresh", s._JOBS)
        self.assertFalse(old.stdout_path.exists())
        self.assertFalse(old.stderr_path.exists())
        self.assertTrue(fresh.stdout_path.exists())

    def test_count_cap_keeps_newest_and_deletes_files(self):
        s = self.server
        s.MAX_TRACKED_JOBS = 3
        now = s._now()
        # finished_at = now - i, so i == 0 is newest.
        jobs = {
            i: self._new_job(f"j{i}", status="done", finished_at=now - i)
            for i in range(5)
        }
        s._prune_jobs()
        remaining = set(s._JOBS)
        self.assertEqual(remaining, {"j0", "j1", "j2"})
        # Evicted jobs had their capture files removed.
        self.assertFalse(jobs[3].stdout_path.exists())
        self.assertFalse(jobs[4].stderr_path.exists())

    def test_running_jobs_are_never_pruned(self):
        s = self.server
        s.MAX_TRACKED_JOBS = 1
        self._new_job("r", status="running", created_at=s._now() - 10_000,
                      write_files=False)
        s._prune_jobs()
        self.assertIn("r", s._JOBS)


class ShutdownHookTests(_JobTestBase):
    def test_shutdown_running_jobs_cancels_running(self):
        s = self.server
        job = self._new_job("run", status="running", write_files=False)
        asyncio.run(s._shutdown_running_jobs())
        self.assertEqual(job.status, "cancelled")
        self.assertIsNotNone(job.finished_at)

    def test_install_hook_wraps_lifespan_forwards_state_and_cleans_up(self):
        s = self.server
        sentinel = object()
        calls = []

        @contextlib.asynccontextmanager
        async def fake_base(scope_app):
            calls.append("base_enter")
            try:
                yield sentinel
            finally:
                calls.append("base_exit")

        class _App:
            pass

        app = _App()
        app.router = _App()
        app.router.lifespan_context = fake_base

        s._install_shutdown_hook(app)
        self.assertIsNot(app.router.lifespan_context, fake_base)

        job = self._new_job("run", status="running", write_files=False)

        async def _drive():
            async with app.router.lifespan_context(app) as state:
                # Base lifespan state is forwarded untouched.
                self.assertIs(state, sentinel)
                self.assertEqual(job.status, "running")

        asyncio.run(_drive())

        # Our cleanup runs on the way out, and the base lifespan still exits.
        self.assertEqual(calls, ["base_enter", "base_exit"])
        self.assertEqual(job.status, "cancelled")


class LiveExecutionTests(_JobTestBase):
    def test_short_job_result_matches_run_command(self):
        s = self.server
        code = "import sys; print('hello-job'); sys.stderr.write('warn-job')"

        async def _run():
            started = await s.start_command(program="python", args=["-c", code])
            job_id = self._parse_job_id(started)
            await s._JOBS[job_id].task
            status = await s.get_command_status(job_id=job_id)
            sync = await s.run_command(program="python", args=["-c", code])
            return job_id, status, sync

        job_id, status, sync = asyncio.run(_run())
        self.assertIn(f"job {job_id}: done", status)
        self.assertIn("exit code: 0", status)
        self.assertIn("hello-job", status)
        self.assertIn("warn-job", status)
        # Same underlying command body as the synchronous path.
        self.assertIn("exit code: 0", sync)
        self.assertIn("hello-job", sync)
        self.assertIn("warn-job", sync)

    def test_multiple_jobs_run_in_parallel_with_distinct_ids(self):
        s = self.server

        async def _run():
            ids = []
            for n in range(3):
                started = await s.start_command(
                    program="python", args=["-c", f"print('p{n}')"]
                )
                ids.append(self._parse_job_id(started))
            for job_id in ids:
                await s._JOBS[job_id].task
            statuses = [await s.get_command_status(job_id=j) for j in ids]
            return ids, statuses

        ids, statuses = asyncio.run(_run())
        self.assertEqual(len(set(ids)), 3)
        for status in statuses:
            self.assertIn("done", status)
            self.assertIn("exit code: 0", status)

    def test_long_job_can_be_cancelled(self):
        s = self.server
        code = "import time; time.sleep(30)"

        async def _run():
            started = await s.start_command(program="python", args=["-c", code])
            job_id = self._parse_job_id(started)
            job = s._JOBS[job_id]
            for _ in range(200):
                if job.proc is not None:
                    break
                await asyncio.sleep(0.05)
            running_status = await s.get_command_status(job_id=job_id)
            cancel_msg = await s.cancel_command(job_id=job_id)
            with contextlib.suppress(Exception):
                await job.task
            final_status = await s.get_command_status(job_id=job_id)
            return job, running_status, cancel_msg, final_status

        job, running_status, cancel_msg, final_status = asyncio.run(_run())
        self.assertIn("running", running_status)
        self.assertIn("cancelled", cancel_msg)
        self.assertIn("cancelled", final_status)
        self.assertIsNotNone(job.proc)
        self.assertIsNotNone(job.proc.returncode)

    def test_cancel_unknown_job_raises(self):
        s = self.server
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(s.cancel_command(job_id="nope"))
        self.assertIn("No background job", str(ctx.exception))

    def test_list_commands_reports_tracked_jobs(self):
        s = self.server
        self._new_job("listed", status="done")
        listing = asyncio.run(s.list_commands())
        self.assertIn("listed", listing)
        self.assertIn("done", listing)

    def test_get_status_unknown_job_raises(self):
        s = self.server
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(s.get_command_status(job_id="nope"))
        self.assertIn("No background job", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
