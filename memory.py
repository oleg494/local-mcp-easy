"""Persistent agent memory: two flat files, no database, no embeddings.

MEMORY.md holds what the agent learned about the environment and the work;
USER.md holds what it learned about the person. Entries inside a file are plain
text separated by a lone `§` line. That is the whole format -- no ids, no
timestamps, no vectors.

That is a deliberate choice, not a shortcut waiting to be upgraded. Recall here
means "the entire store is put in front of the model", so there is nothing to
rank and nothing to search: an embedding index would add a dependency, a build
step and a failure mode to answer a query that is never asked. What keeps the
store useful is the budget below, which forces consolidation instead of growth.

Budgets are measured in characters, not entries. A cap on entry count would let
one rambling entry crowd out ten useful ones, whereas the character cap makes
the real constraint -- context window space -- the thing being managed. Over
budget, a write is refused and the current contents are handed back so the
model can shorten or drop something and retry.

The store lives outside the workspace, so no filesystem tool can reach it: a
client edits memory only through the memory_write tool, which means every
change passes the OAuth scope check.
"""

from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path

from core import atomic_write_text

ENTRY_DELIMITER = "\n§\n"

TARGETS = ("memory", "user")
TARGET_LABELS = {
    "memory": "MEMORY (what you have learned about this environment and work)",
    "user": "USER (what you have learned about the person you work with)",
}
DEFAULT_LIMITS = {"memory": 2200, "user": 1375}


class MemoryError_(ValueError):
    """A memory operation was refused. Surfaces to the client as-is."""


def _validate_target(target: str) -> str:
    target = (target or "").strip().lower()
    if target not in TARGETS:
        raise MemoryError_(f"target must be one of {', '.join(TARGETS)}; got {target!r}")
    return target


class MemoryStore:
    """Two files under `directory`, read and written whole.

    Whole-file rewrites are correct here because the files are capped at a few
    kilobytes by construction; the atomic write underneath means a crash can
    never leave a half-written store.
    """

    def __init__(self, directory: Path, limits: dict[str, int] | None = None):
        self.directory = Path(directory)
        self.limits = dict(DEFAULT_LIMITS, **(limits or {}))
        # Every mutation is read-modify-write of a whole file, and tool calls
        # reach it from asyncio.to_thread worker threads. Without this, two
        # concurrent memory_write calls both read the old entry list and the
        # second write silently discards the first.
        self._lock = threading.Lock()

    def path(self, target: str) -> Path:
        return self.directory / f"{_validate_target(target).upper()}.md"

    def limit(self, target: str) -> int:
        return self.limits[_validate_target(target)]

    # -- reading --------------------------------------------------------
    def entries(self, target: str) -> list[str]:
        try:
            raw = self.path(target).read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            return []
        seen: dict[str, None] = {}
        for chunk in raw.split(ENTRY_DELIMITER):
            entry = chunk.strip()
            # dict preserves insertion order, so this dedupes while keeping the
            # first occurrence -- a store hand-edited into duplicates heals on
            # the next write instead of wasting budget forever.
            if entry:
                seen.setdefault(entry, None)
        return list(seen)

    def used(self, target: str) -> int:
        return len(ENTRY_DELIMITER.join(self.entries(target)))

    def render(self, target: str) -> str:
        """The block handed to the model, with its own budget stated.

        Showing the usage percentage is what lets the model decide to
        consolidate before it hits a refusal.
        """
        target = _validate_target(target)
        entries = self.entries(target)
        limit = self.limit(target)
        used = len(ENTRY_DELIMITER.join(entries))
        pct = round(100 * used / limit) if limit else 0
        head = f"=== {TARGET_LABELS[target]} [{pct}% — {used:,}/{limit:,} chars] ==="
        if not entries:
            return f"{head}\n(empty)"
        return head + "\n" + ENTRY_DELIMITER.join(entries)

    def render_all(self) -> str:
        return "\n\n".join(self.render(target) for target in TARGETS)

    def is_empty(self) -> bool:
        return not any(self.entries(target) for target in TARGETS)

    # -- writing --------------------------------------------------------
    def _save(self, target: str, entries: list[str]) -> None:
        limit = self.limit(target)
        payload = ENTRY_DELIMITER.join(entries)
        if len(payload) > limit:
            raise MemoryError_(
                f"Refused: this would put {target} at {len(payload):,} characters, "
                f"over its {limit:,} limit. Shorten or remove an entry first — "
                f"the current contents are:\n\n{self.render(target)}"
            )
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.path(target)
        atomic_write_text(path, payload + "\n" if payload else "")
        with contextlib.suppress(OSError):
            # Memory can hold anything the user told the agent, so it is
            # owner-only on POSIX. Windows already restricts %LOCALAPPDATA%.
            os.chmod(path, 0o600)

    def _clean(self, content: str, label: str = "content") -> str:
        """Normalise one entry, refusing anything that would corrupt the file.

        An entry containing the delimiter would silently become two entries on
        the next read -- letting a single write forge a second, unreviewed
        memory. Cheaper to refuse than to escape, since a lone section sign on
        its own line is never something a real memory needs.
        """
        content = (content or "").strip()
        if not content:
            raise MemoryError_(f"{label} is required")
        if ENTRY_DELIMITER.strip("\n") in content.split("\n"):
            raise MemoryError_(
                "An entry cannot contain a line that is only '§' — that is the "
                "separator between entries. Rephrase, or use two writes."
            )
        return content

    def add(self, target: str, content: str) -> str:
        target = _validate_target(target)
        content = self._clean(content)
        with self._lock:
            entries = self.entries(target)
            if content in entries:
                return f"Already in {target}; nothing added."
            entries.append(content)
            self._save(target, entries)
            return f"Added to {target} ({len(ENTRY_DELIMITER.join(entries)):,}/{self.limit(target):,} chars)."

    def replace(self, target: str, old_text: str, content: str) -> str:
        """Rewrite the single entry containing `old_text`.

        Substring matching rather than an id keeps the tool callable from what
        the model can already see in the rendered block. Ambiguity is refused
        rather than resolved by guessing, because silently rewriting the wrong
        memory is worse than making the caller be specific.
        """
        target = _validate_target(target)
        old_text = (old_text or "").strip()
        if not old_text:
            raise MemoryError_("old_text is required for replace")
        content = self._clean(content)
        with self._lock:
            entries = self.entries(target)
            index = self._single_match(entries, old_text, target)
            entries[index] = content
            self._save(target, entries)
            return f"Replaced 1 entry in {target} ({len(ENTRY_DELIMITER.join(entries)):,}/{self.limit(target):,} chars)."

    def remove(self, target: str, old_text: str) -> str:
        target = _validate_target(target)
        old_text = (old_text or "").strip()
        if not old_text:
            raise MemoryError_("old_text is required for remove")
        with self._lock:
            entries = self.entries(target)
            entries.pop(self._single_match(entries, old_text, target))
            self._save(target, entries)
            return f"Removed 1 entry from {target} ({len(ENTRY_DELIMITER.join(entries)):,}/{self.limit(target):,} chars)."

    @staticmethod
    def _single_match(entries: list[str], old_text: str, target: str) -> int:
        matches = [i for i, entry in enumerate(entries) if old_text in entry]
        if not matches:
            raise MemoryError_(f"No entry in {target} contains {old_text!r}.")
        if len(matches) > 1:
            raise MemoryError_(
                f"{len(matches)} entries in {target} contain {old_text!r}. "
                "Use a longer, unique excerpt."
            )
        return matches[0]
