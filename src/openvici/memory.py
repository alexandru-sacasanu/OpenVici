"""Long-term memory: two small Markdown files the user can read and edit.

``MEMORY.md`` holds what the agent learned about the work; ``USER.md`` holds
what it learned about the user. Both have a hard size cap. When a file is
full, a write fails and says so; nothing is compacted or dropped behind the
user's back.

Every entry is one line and carries where it came from::

    - Deploys go through the staging branch <!-- id:4f1c9a session:20261116-0102-ab12 -->

That trailing comment is the lineage that makes ``forget --session`` work:
an entry is removed when any session that wrote or rewrote it is forgotten.
Lines a person typed by hand have no comment and belong to no session.

Memory is also the most durable prompt-injection target in the system: what
is written here is placed in front of the model in every later session. See
``tools/memory.py`` for the gate on writes.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

TARGETS = {"memory": "MEMORY.md", "user": "USER.md"}
DEFAULT_LIMITS = {"memory": 2200, "user": 1375}
MAX_ENTRY_CHARS = 500
_LINE = re.compile(r"^- (?P<text>.*?)(?: <!-- id:(?P<id>[0-9a-f]+) session:(?P<sessions>[\w,-]*) -->)?$")
_TITLES = {"memory": "# Memory", "user": "# User"}


class MemoryError_(Exception):
    """A memory operation that could not be done; the message is for the model."""


class MemoryFull(MemoryError_):
    pass


@dataclass(frozen=True)
class Entry:
    id: str
    text: str
    sessions: tuple[str, ...] = ()


def clean_text(text: str) -> str:
    text = " ".join(text.split())
    if text.startswith("- "):
        text = text[2:].strip()
    if not text:
        raise MemoryError_("the entry is empty")
    if len(text) > MAX_ENTRY_CHARS:
        raise MemoryError_(f"an entry may be at most {MAX_ENTRY_CHARS} characters; this one is {len(text)}")
    if "<!--" in text or "-->" in text:
        raise MemoryError_("entries may not contain HTML comment markers")
    if any(ord(ch) < 32 for ch in text):
        raise MemoryError_("entries may not contain control characters")
    return text


class MemoryStore:
    def __init__(self, directory: str | os.PathLike[str], limits: dict[str, int] | None = None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}

    # -- reading ---------------------------------------------------------------

    def entries(self, target: str) -> list[Entry]:
        path = self._path(target)
        if not path.exists():
            return []
        out: list[Entry] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _LINE.match(line)
            if match and match["id"]:
                sessions = tuple(s for s in match["sessions"].split(",") if s)
                out.append(Entry(match["id"], match["text"], sessions))
            else:  # typed by hand: keep it, with no lineage
                text = line[2:] if line.startswith("- ") else line
                out.append(Entry(secrets.token_hex(3), text))
        return out

    def usage(self, target: str) -> tuple[int, int]:
        return _size(self.entries(target)), self.limits[target]

    def snapshot(self) -> str:
        """Both files as the model should see them: text only, no lineage."""
        blocks = []
        for target, title in (("user", "About the user"), ("memory", "Notes from earlier sessions")):
            entries = self.entries(target)
            if entries:
                blocks.append(f"{title}:\n" + "\n".join(f"- {e.text}" for e in entries))
        return "\n\n".join(blocks)

    # -- writing ---------------------------------------------------------------

    def add(self, target: str, text: str, session_id: str) -> Entry:
        text = clean_text(text)
        entries = self.entries(target)
        if any(e.text == text for e in entries):
            raise MemoryError_("that exact entry is already saved")
        entry = Entry(secrets.token_hex(3), text, (session_id,))
        self._save(target, entries + [entry])
        return entry

    def replace(self, target: str, old_text: str, new_text: str, session_id: str) -> Entry:
        new_text = clean_text(new_text)
        entries = self.entries(target)
        index = self._find(entries, old_text)
        old = entries[index]
        sessions = old.sessions if session_id in old.sessions else old.sessions + (session_id,)
        entries[index] = Entry(old.id, new_text, sessions)
        self._save(target, entries)
        return entries[index]

    def remove(self, target: str, old_text: str) -> Entry:
        entries = self.entries(target)
        index = self._find(entries, old_text)
        removed = entries.pop(index)
        self._save(target, entries)
        return removed

    def forget_session(self, session_id: str) -> int:
        """Remove every entry that session wrote or rewrote. Returns how many."""
        removed = 0
        for target in TARGETS:
            entries = self.entries(target)
            kept = [e for e in entries if session_id not in e.sessions]
            if len(kept) != len(entries):
                removed += len(entries) - len(kept)
                self._save(target, kept, enforce_limit=False)
        return removed

    def mentions_session(self, session_id: str) -> bool:
        return any(session_id in e.sessions for t in TARGETS for e in self.entries(t))

    # -- internals -------------------------------------------------------------

    def _path(self, target: str) -> Path:
        if target not in TARGETS:
            raise MemoryError_(f"unknown memory target '{target}' (use 'memory' or 'user')")
        return self.directory / TARGETS[target]

    @staticmethod
    def _find(entries: list[Entry], needle: str) -> int:
        needle = " ".join(needle.split())
        if not needle:
            raise MemoryError_("old_text is empty")
        hits = [i for i, e in enumerate(entries) if needle in e.text]
        if not hits:
            raise MemoryError_("no saved entry contains that text")
        if len(hits) > 1:
            raise MemoryError_(f"{len(hits)} entries contain that text; quote more of the one you mean")
        return hits[0]

    def _save(self, target: str, entries: list[Entry], enforce_limit: bool = True) -> None:
        used, limit = _size(entries), self.limits[target]
        if enforce_limit and used > limit:
            raise MemoryFull(
                f"{TARGETS[target]} is full: this would use {used} of {limit} characters. Nothing was saved. "
                "Remove or shorten an existing entry first, or tell the user it does not fit.")
        lines = [_TITLES[target], ""]
        for e in entries:
            lines.append(f"- {e.text} <!-- id:{e.id} session:{','.join(e.sessions)} -->")
        path = self._path(target)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)


def _size(entries: list[Entry]) -> int:
    return sum(len(e.text) + 1 for e in entries)
