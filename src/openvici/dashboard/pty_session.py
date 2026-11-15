"""A terminal session for the dashboard's chat tab.

The chat tab is not a reimplementation of the chat: it is the real
``openvici chat`` process attached to a pseudo-terminal, so approval prompts,
tool output and everything else behave exactly as in a terminal.

The command is fixed when the server starts. No request can choose what runs
here; the dashboard is not a remote shell.
"""

from __future__ import annotations

import fcntl
import os
import pty
import signal
import struct
import subprocess
import termios
import threading
from collections import deque

BUFFER_BYTES = 512 * 1024
MAX_INPUT_BYTES = 64 * 1024


class PtySession:
    def __init__(self, argv: list[str], env: dict[str, str], cwd: str, cols: int = 100, rows: int = 30):
        self._master, slave = pty.openpty()
        self._set_size(cols, rows)
        try:
            self.process = subprocess.Popen(
                argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=cwd, close_fds=True,
                start_new_session=True,
                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        finally:
            os.close(slave)
        self._chunks: deque[bytes] = deque()
        self._base = 0          # stream offset of the first byte still buffered
        self._size = 0          # bytes currently buffered
        self._closed = False
        self._cond = threading.Condition()
        threading.Thread(target=self._pump, daemon=True).start()

    # -- output ----------------------------------------------------------------

    def _pump(self) -> None:
        while True:
            try:
                data = os.read(self._master, 65536)
            except OSError:
                data = b""
            with self._cond:
                if not data:
                    self._closed = True
                    self._cond.notify_all()
                    break
                self._chunks.append(data)
                self._size += len(data)
                while self._size > BUFFER_BYTES and len(self._chunks) > 1:
                    dropped = self._chunks.popleft()
                    self._size -= len(dropped)
                    self._base += len(dropped)
                self._cond.notify_all()
        self.process.wait()

    def read_from(self, offset: int, timeout: float) -> tuple[bytes, int, bool]:
        """(new bytes, next offset, finished). Blocks up to ``timeout`` when
        there is nothing new. An offset older than the buffer starts at its
        oldest byte."""
        with self._cond:
            end = self._base + self._size
            if offset >= end and not self._closed:
                self._cond.wait(timeout)
                end = self._base + self._size
            offset = max(offset, self._base)
            if offset >= end:
                return b"", end, self._closed
            data = b"".join(self._chunks)[offset - self._base:]
            return data, end, False

    # -- input -----------------------------------------------------------------

    def write(self, data: bytes) -> None:
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError("input too large")
        view = memoryview(data)
        while view:
            view = view[os.write(self._master, view):]

    def resize(self, cols: int, rows: int) -> None:
        self._set_size(cols, rows)

    def _set_size(self, cols: int, rows: int) -> None:
        cols, rows = max(20, min(int(cols), 500)), max(5, min(int(rows), 200))
        fcntl.ioctl(self._master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    # -- lifecycle -------------------------------------------------------------

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def close(self) -> None:
        if self.alive:
            try:
                os.killpg(self.process.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            os.close(self._master)
        except OSError:
            pass
