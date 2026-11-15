"""Append-only, hash-chained audit log.

Each entry carries the hash of the entry before it, so editing or removing an
entry in the middle of the file breaks every later hash and ``verify`` reports
where the chain stops matching.

What the chain does NOT prove on its own: that the tail was not cut off, or
that the whole file was not rewritten from scratch by someone who can write
it. Both need a copy of ``head()`` kept somewhere this process cannot write
(another machine, a git remote, a printed note). ``verify(checkpoint=...)``
checks the file against such a copy.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_TAIL_BYTES = 1 << 16
_MAX_DETAIL_CHARS = 8000


class AuditError(Exception):
    """The log cannot be trusted or written. Callers must not proceed."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head: str
    error: str | None = None


def _canonical(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(f"{prev_hash}\n{_canonical(body)}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        decision: str,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write one entry and return it. Raises AuditError rather than
        writing onto a chain it cannot read."""
        detail = detail or {}
        if len(_canonical(detail)) > _MAX_DETAIL_CHARS:
            raise AuditError("audit detail too large; log a digest instead")

        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            prev_seq, prev_hash = self._read_tail(fd)
            body = {
                "seq": prev_seq + 1,
                "ts": time.time(),
                "actor": actor,
                "action": action,
                "target": target,
                "decision": decision,
                "detail": detail,
                "prev": prev_hash,
            }
            entry = {**body, "hash": _entry_hash(prev_hash, body)}
            os.write(fd, (_canonical(entry) + "\n").encode())
            os.fsync(fd)
            return entry
        finally:
            os.close(fd)

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the last entry; (-1, GENESIS) for an empty log."""
        if not self.path.exists():
            return -1, GENESIS
        fd = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            return self._read_tail(fd)
        finally:
            os.close(fd)

    def verify(self, checkpoint: tuple[int, str] | None = None) -> VerifyResult:
        """Recompute the whole chain. With ``checkpoint`` (a ``head()`` value
        saved earlier, elsewhere), also require that entry to still be there
        unchanged, which catches truncation and full rewrites."""
        prev_hash, count, seen_checkpoint = GENESIS, 0, checkpoint is None
        if self.path.exists():
            with open(self.path, "rb") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                for lineno, raw in enumerate(fh, start=1):
                    try:
                        entry = json.loads(raw)
                        claimed = entry.pop("hash")
                    except (ValueError, KeyError, AttributeError):
                        return VerifyResult(False, count, prev_hash, f"line {lineno}: unreadable entry")
                    if entry.get("seq") != count:
                        return VerifyResult(False, count, prev_hash, f"line {lineno}: expected seq {count}")
                    if entry.get("prev") != prev_hash:
                        return VerifyResult(False, count, prev_hash, f"line {lineno}: broken link to previous entry")
                    if _entry_hash(prev_hash, entry) != claimed:
                        return VerifyResult(False, count, prev_hash, f"line {lineno}: content does not match its hash")
                    if checkpoint is not None and checkpoint[0] == count:
                        if checkpoint[1] != claimed:
                            return VerifyResult(False, count, prev_hash, f"line {lineno}: differs from checkpoint")
                        seen_checkpoint = True
                    prev_hash, count = claimed, count + 1
        if not seen_checkpoint and checkpoint != (-1, GENESIS):
            return VerifyResult(False, count, prev_hash, "checkpoint entry is missing (log truncated or replaced)")
        return VerifyResult(True, count, prev_hash)

    @staticmethod
    def _read_tail(fd: int) -> tuple[int, str]:
        size = os.fstat(fd).st_size
        if size == 0:
            return -1, GENESIS
        start = max(0, size - _TAIL_BYTES)
        data = os.pread(fd, size - start, start)
        if not data.endswith(b"\n"):
            raise AuditError("audit log ends mid-entry; refusing to append to a damaged chain")
        last = data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            entry = json.loads(last)
            return int(entry["seq"]), str(entry["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("last audit entry is unreadable; refusing to append") from exc
