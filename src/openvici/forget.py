"""Forget one session everywhere it left a trace this program controls.

Removed: the session's stored messages, their search-index entries, and every
long-term memory entry that session wrote or rewrote.

Not removed, and reported as such: the audit log (append-only by design; it
holds action records such as file paths, URLs and the first 200 characters
of commands, never conversation text), files the agent wrote in the
workspace, and whatever the model provider retained on its side.
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .memory import MemoryStore
from .sessions import SessionStore


@dataclass(frozen=True)
class ForgetReport:
    session_id: str
    known: bool
    messages_deleted: int
    memory_entries_removed: int
    verified: bool


def forget_session(session_id: str, sessions: SessionStore, memory: MemoryStore, audit: AuditLog) -> ForgetReport:
    known = sessions.has_session(session_id) or memory.mentions_session(session_id)
    messages = sessions.forget(session_id)
    entries = memory.forget_session(session_id)
    verified = not sessions.has_session(session_id) and not memory.mentions_session(session_id)
    audit.append(actor="human", action="session.forget", target=session_id,
                 decision="allow" if verified else "error",
                 detail={"messages": messages, "memory_entries": entries})
    return ForgetReport(session_id, known, messages, entries, verified)
