"""Past conversations, searchable, and deletable for real.

One SQLite file holds what the user and the assistant said in each session,
with a full-text index (FTS5) over it. Tool results are deliberately not
stored: they are the bulk of the untrusted content (web pages, command
output) and the place secrets are most likely to appear.

Forgetting a session deletes its rows and its index entries, and the
database runs with ``secure_delete`` and is vacuumed afterwards, so the text
is gone from the file itself, not merely unlinked from a table.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .messages import Message

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    started_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    role TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_session ON messages(session_id);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(text, content='messages', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
"""


class SessionError(Exception):
    pass


@dataclass(frozen=True)
class SessionInfo:
    id: str
    started_at: float
    messages: int
    first_line: str


@dataclass(frozen=True)
class Hit:
    session_id: str
    role: str
    snippet: str
    created_at: float


def new_session_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


class SessionStore:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fresh = not self.path.exists()
        try:
            self.db = sqlite3.connect(self.path)
            self.db.execute("PRAGMA secure_delete = ON")
            self.db.execute("PRAGMA foreign_keys = ON")
            self.db.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise SessionError(f"cannot open the session database {self.path}: {exc}") from None
        if fresh:
            os.chmod(self.path, 0o600)

    def close(self) -> None:
        self.db.close()

    def record(self, session_id: str, messages: list[Message]) -> int:
        """Store the user and assistant text of ``messages``. Returns rows written."""
        rows = [(session_id, m.role, m.text, time.time())
                for m in messages if m.role in ("user", "assistant") and m.text.strip()]
        if not rows:
            return 0
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO sessions(id, started_at) VALUES (?, ?)",
                            (session_id, time.time()))
            self.db.executemany(
                "INSERT INTO messages(session_id, role, text, created_at) VALUES (?, ?, ?, ?)", rows)
        return len(rows)

    def list(self, limit: int = 50) -> list[SessionInfo]:
        rows = self.db.execute(
            """SELECT s.id, s.started_at, COUNT(m.id),
                      COALESCE((SELECT text FROM messages WHERE session_id = s.id AND role = 'user'
                                ORDER BY id LIMIT 1), '')
               FROM sessions s LEFT JOIN messages m ON m.session_id = s.id
               GROUP BY s.id ORDER BY s.started_at DESC LIMIT ?""", (limit,)).fetchall()
        return [SessionInfo(r[0], r[1], r[2], " ".join(r[3].split())[:80]) for r in rows]

    def search(self, query: str, limit: int = 8, exclude_session: str | None = None) -> list[Hit]:
        """Full-text search. Each word is matched literally: the query is never
        interpreted as FTS5 syntax. All words must match; if nothing does, any
        word may."""
        terms = ['"' + t.replace('"', '""') + '"' for t in query.split()[:12]]
        if not terms:
            return []
        for joiner in (" AND ", " OR "):
            rows = self.db.execute(
                """SELECT m.session_id, m.role, snippet(messages_fts, 0, '', '', ' … ', 24), m.created_at
                   FROM messages_fts JOIN messages m ON m.id = messages_fts.rowid
                   WHERE messages_fts MATCH ? AND m.session_id IS NOT ?
                   ORDER BY bm25(messages_fts) LIMIT ?""",
                (joiner.join(terms), exclude_session, limit)).fetchall()
            if rows or len(terms) == 1:
                return [Hit(*r) for r in rows]
        return []

    def forget(self, session_id: str) -> int:
        """Delete a session's messages and index entries, then vacuum so the
        text leaves the file. Returns messages deleted."""
        with self.db:
            deleted = self.db.execute("DELETE FROM messages WHERE session_id = ?", (session_id,)).rowcount
            self.db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            self.db.execute("INSERT INTO messages_fts(messages_fts) VALUES ('optimize')")
        self.db.execute("VACUUM")
        return deleted

    def has_session(self, session_id: str) -> bool:
        row = self.db.execute(
            "SELECT (SELECT COUNT(*) FROM sessions WHERE id = ?) + (SELECT COUNT(*) FROM messages WHERE session_id = ?)",
            (session_id, session_id)).fetchone()
        return bool(row[0])
