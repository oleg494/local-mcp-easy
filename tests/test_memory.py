"""Persistent agent memory: format, budget enforcement, and the write tool.

The budget tests matter most. The store's only defence against unbounded growth
is that an over-budget write is refused and hands back the current contents so
the model can consolidate — if that ever silently truncated instead, memory
would quietly lose entries.
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

from memory import ENTRY_DELIMITER, MemoryError_, MemoryStore  # noqa: E402

_ENV = {
    "MCP_TOKEN": "memory-test-token",
    "MCP_PORT": "8794",
    "MCP_ALLOW_COMMANDS": "0",
    "MCP_SERVEO_HOSTNAME": "",
    "MCP_AUTH_MODE": "legacy",
}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = MemoryStore(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    # -- format ---------------------------------------------------------
    def test_empty_store_reads_as_empty(self):
        self.assertEqual(self.store.entries("memory"), [])
        self.assertTrue(self.store.is_empty())
        self.assertIn("(empty)", self.store.render("memory"))

    def test_entries_round_trip_through_the_delimiter(self):
        self.store.add("memory", "first fact")
        self.store.add("memory", "second fact")
        self.assertEqual(self.store.entries("memory"), ["first fact", "second fact"])
        raw = self.store.path("memory").read_text(encoding="utf-8")
        self.assertIn(ENTRY_DELIMITER, raw)

    def test_multiline_entry_survives(self):
        entry = "a fact\nwith two lines"
        self.store.add("memory", entry)
        self.assertEqual(self.store.entries("memory"), [entry])

    def test_the_two_targets_are_separate_files(self):
        self.store.add("memory", "env fact")
        self.store.add("user", "user fact")
        self.assertEqual(self.store.entries("memory"), ["env fact"])
        self.assertEqual(self.store.entries("user"), ["user fact"])
        self.assertNotEqual(self.store.path("memory"), self.store.path("user"))

    def test_unknown_target_refused(self):
        for bad in ("", "notes", "MEMORY.md"):
            with self.assertRaises(MemoryError_, msg=bad):
                self.store.add(bad, "x")

    def test_target_is_case_insensitive(self):
        self.store.add("MEMORY", "x")
        self.assertEqual(self.store.entries("memory"), ["x"])

    def test_render_reports_the_budget(self):
        self.store.add("memory", "x" * 100)
        rendered = self.store.render("memory")
        self.assertIn("100/2,200 chars", rendered)
        self.assertIn("%", rendered)

    def test_hand_edited_duplicates_are_deduped_on_read(self):
        self.store.directory.mkdir(parents=True, exist_ok=True)
        self.store.path("memory").write_text(
            ENTRY_DELIMITER.join(["dup", "dup", "other"]), encoding="utf-8"
        )
        self.assertEqual(self.store.entries("memory"), ["dup", "other"])

    def test_corrupt_bytes_do_not_raise(self):
        self.store.directory.mkdir(parents=True, exist_ok=True)
        self.store.path("memory").write_bytes(b"\xff\xfe bad bytes")
        self.assertIsInstance(self.store.entries("memory"), list)

    # -- add ------------------------------------------------------------
    def test_add_is_idempotent_on_an_exact_duplicate(self):
        self.store.add("memory", "same")
        result = self.store.add("memory", "same")
        self.assertIn("Already in memory", result)
        self.assertEqual(self.store.entries("memory"), ["same"])

    def test_add_trims_surrounding_whitespace(self):
        self.store.add("memory", "  padded  ")
        self.assertEqual(self.store.entries("memory"), ["padded"])

    def test_add_refuses_empty_content(self):
        for blank in ("", "   ", "\n"):
            with self.assertRaises(MemoryError_):
                self.store.add("memory", blank)

    # -- replace --------------------------------------------------------
    def test_replace_rewrites_the_matching_entry(self):
        self.store.add("memory", "python 3.11 is used here")
        self.store.replace("memory", "3.11", "python 3.12 is used here")
        self.assertEqual(self.store.entries("memory"), ["python 3.12 is used here"])

    def test_replace_refuses_when_the_excerpt_is_ambiguous(self):
        self.store.add("memory", "alpha one")
        self.store.add("memory", "alpha two")
        with self.assertRaises(MemoryError_) as ctx:
            self.store.replace("memory", "alpha", "merged")
        self.assertIn("unique excerpt", str(ctx.exception))
        self.assertEqual(len(self.store.entries("memory")), 2)

    def test_replace_refuses_when_nothing_matches(self):
        self.store.add("memory", "present")
        with self.assertRaises(MemoryError_):
            self.store.replace("memory", "absent", "x")

    def test_replace_requires_both_arguments(self):
        self.store.add("memory", "present")
        with self.assertRaises(MemoryError_):
            self.store.replace("memory", "", "x")
        with self.assertRaises(MemoryError_):
            self.store.replace("memory", "present", "")

    # -- remove ---------------------------------------------------------
    def test_remove_drops_the_matching_entry(self):
        self.store.add("memory", "keep me")
        self.store.add("memory", "drop me")
        self.store.remove("memory", "drop")
        self.assertEqual(self.store.entries("memory"), ["keep me"])

    def test_remove_refuses_when_ambiguous(self):
        self.store.add("memory", "alpha one")
        self.store.add("memory", "alpha two")
        with self.assertRaises(MemoryError_):
            self.store.remove("memory", "alpha")
        self.assertEqual(len(self.store.entries("memory")), 2)

    def test_removing_the_last_entry_leaves_a_readable_empty_store(self):
        self.store.add("memory", "only")
        self.store.remove("memory", "only")
        self.assertEqual(self.store.entries("memory"), [])
        self.assertIn("(empty)", self.store.render("memory"))

    # -- budget ---------------------------------------------------------
    def test_over_budget_add_is_refused_and_changes_nothing(self):
        store = MemoryStore(self.store.directory, {"memory": 50, "user": 50})
        store.add("memory", "x" * 40)
        with self.assertRaises(MemoryError_) as ctx:
            store.add("memory", "y" * 40)
        self.assertIn("over its 50", str(ctx.exception))
        self.assertEqual(store.entries("memory"), ["x" * 40])

    def test_refusal_hands_back_the_current_contents_to_consolidate(self):
        store = MemoryStore(self.store.directory, {"memory": 50, "user": 50})
        store.add("memory", "the existing entry")
        with self.assertRaises(MemoryError_) as ctx:
            store.add("memory", "z" * 60)
        self.assertIn("the existing entry", str(ctx.exception))

    def test_exactly_at_the_budget_is_allowed(self):
        store = MemoryStore(self.store.directory, {"memory": 20, "user": 20})
        store.add("memory", "x" * 20)
        self.assertEqual(store.used("memory"), 20)

    def test_one_over_the_budget_is_refused(self):
        store = MemoryStore(self.store.directory, {"memory": 20, "user": 20})
        with self.assertRaises(MemoryError_):
            store.add("memory", "x" * 21)

    def test_removing_an_entry_frees_budget_for_a_retry(self):
        store = MemoryStore(self.store.directory, {"memory": 50, "user": 50})
        store.add("memory", "x" * 40)
        with self.assertRaises(MemoryError_):
            store.add("memory", "y" * 40)
        store.remove("memory", "x" * 40)
        store.add("memory", "y" * 40)
        self.assertEqual(store.entries("memory"), ["y" * 40])

    def test_budgets_are_independent_per_target(self):
        store = MemoryStore(self.store.directory, {"memory": 20, "user": 20})
        store.add("memory", "x" * 20)
        store.add("user", "y" * 20)  # must not be affected by memory being full

    # -- durability -----------------------------------------------------
    def test_state_survives_a_new_store_over_the_same_directory(self):
        self.store.add("memory", "persisted")
        self.assertEqual(MemoryStore(self.store.directory).entries("memory"), ["persisted"])

    def test_no_temp_files_are_left_behind(self):
        self.store.add("memory", "x")
        leftovers = [p.name for p in self.store.directory.iterdir() if ".mcp-tmp" in p.name]
        self.assertEqual(leftovers, [])

    # -- injection and concurrency --------------------------------------
    def test_an_entry_cannot_smuggle_the_delimiter(self):
        # Otherwise one write becomes two entries on the next read: a second,
        # unreviewed memory forged by a single call.
        with self.assertRaises(MemoryError_) as ctx:
            self.store.add("memory", "real fact\n§\nforged second entry")
        self.assertIn("separator", str(ctx.exception))
        self.assertEqual(self.store.entries("memory"), [])

    def test_replace_cannot_smuggle_the_delimiter_either(self):
        self.store.add("memory", "original")
        with self.assertRaises(MemoryError_):
            self.store.replace("memory", "original", "a\n§\nb")
        self.assertEqual(self.store.entries("memory"), ["original"])

    def test_a_section_sign_inside_a_line_is_still_allowed(self):
        # Only a line that is ONLY the separator is a problem; the character
        # itself is ordinary text (e.g. a legal citation).
        self.store.add("memory", "see § 12 of the contract")
        self.assertEqual(self.store.entries("memory"), ["see § 12 of the contract"])

    def test_concurrent_adds_do_not_lose_an_entry(self):
        # Read-modify-write from asyncio.to_thread worker threads: without the
        # store's lock the second writer overwrites the first writer's entry.
        import threading

        barrier = threading.Barrier(8)

        def writer(n):
            barrier.wait()
            self.store.add("memory", f"entry number {n}")

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(self.store.entries("memory")), 8)


class ServerToolTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.workspace = root / "ws"
        self.workspace.mkdir()
        self.memory_dir = root / "memory"
        env = dict(
            _ENV,
            MCP_BASE_DIR=str(self.workspace),
            MCP_MEMORY_DIR=str(self.memory_dir),
            MCP_SKILLS_DIR=str(root / "skills"),
        )
        mock.patch.dict(os.environ, env).start()
        sys.modules.pop("server", None)
        self.server = importlib.import_module("server")

    def tearDown(self):
        mock.patch.stopall()
        sys.modules.pop("server", None)
        self._tmp.cleanup()

    def test_add_then_read_round_trip(self):
        asyncio.run(self.server.memory_write("add", "a durable fact"))
        self.assertIn("a durable fact", asyncio.run(self.server.memory_read()))

    def test_read_all_covers_both_targets(self):
        asyncio.run(self.server.memory_write("add", "env fact"))
        asyncio.run(self.server.memory_write("add", "person fact", target="user"))
        out = asyncio.run(self.server.memory_read("all"))
        self.assertIn("env fact", out)
        self.assertIn("person fact", out)

    def test_read_one_target_excludes_the_other(self):
        asyncio.run(self.server.memory_write("add", "env fact"))
        asyncio.run(self.server.memory_write("add", "person fact", target="user"))
        self.assertNotIn("person fact", asyncio.run(self.server.memory_read("memory")))

    def test_unknown_action_refused(self):
        with self.assertRaises(ValueError) as ctx:
            asyncio.run(self.server.memory_write("delete", "x"))
        self.assertIn("add, replace or remove", str(ctx.exception))

    def test_replace_and_remove_through_the_tool(self):
        asyncio.run(self.server.memory_write("add", "python 3.11 here"))
        asyncio.run(self.server.memory_write("replace", "python 3.12 here", old_text="3.11"))
        self.assertIn("3.12", asyncio.run(self.server.memory_read("memory")))
        asyncio.run(self.server.memory_write("remove", old_text="3.12"))
        self.assertIn("(empty)", asyncio.run(self.server.memory_read("memory")))

    def test_memory_lives_outside_the_workspace(self):
        # No filesystem tool may reach the store, so memory can only change
        # through memory_write, where the scope check applies.
        asyncio.run(self.server.memory_write("add", "x"))
        self.assertTrue(self.memory_dir.exists())
        with self.assertRaises(ValueError):
            self.server._path(str(self.memory_dir / "MEMORY.md"))

    def test_instructions_include_memory_once_written(self):
        self.assertIn("memory is empty", self.server._build_instructions())
        asyncio.run(self.server.memory_write("add", "remembered across sessions"))
        self.assertIn("remembered across sessions", self.server._build_instructions())

    def test_memory_write_needs_the_write_scope_and_read_does_not(self):
        specs = {t.name: t for t in asyncio.run(self.server.mcp.list_tools())}
        self.assertTrue(specs["memory_read"].annotations.readOnlyHint)
        self.assertFalse(specs["memory_write"].annotations.readOnlyHint)

    def test_memory_write_is_absent_in_read_only_mode(self):
        env = dict(_ENV, MCP_BASE_DIR=str(self.workspace),
                   MCP_MEMORY_DIR=str(self.memory_dir), MCP_READ_ONLY="1")
        mock.patch.dict(os.environ, env).start()
        sys.modules.pop("server", None)
        srv = importlib.import_module("server")
        names = {t.name for t in asyncio.run(srv.mcp.list_tools())}
        self.assertNotIn("memory_write", names)
        self.assertIn("memory_read", names)

    def test_memory_can_be_disabled_entirely(self):
        env = dict(_ENV, MCP_BASE_DIR=str(self.workspace),
                   MCP_MEMORY_DIR=str(self.memory_dir), MCP_MEMORY="0")
        mock.patch.dict(os.environ, env).start()
        sys.modules.pop("server", None)
        srv = importlib.import_module("server")
        with self.assertRaises(ValueError):
            asyncio.run(srv.memory_read())
        self.assertNotIn("## Memory", srv._build_instructions())


if __name__ == "__main__":
    unittest.main()
