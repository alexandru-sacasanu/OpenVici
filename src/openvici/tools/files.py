"""read_file and write_file, confined to the workspace.

These run in the agent process on the host, not in the container, so they
are the one place where a path the model chose touches the real filesystem.
The model can also create symlinks from inside the sandbox
(``ln -s ~/.ssh/id_rsa notes.txt``) and then ask for that "file".

So paths are never resolved and then checked. Each component is opened
relative to the directory before it with O_NOFOLLOW, starting from the
workspace root. A symlink anywhere on the way is refused, ``..`` is refused,
and there is no window between a check and the open for a link to be
swapped in.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from ..audit import AuditLog
from .base import Confirm, Tool, ToolError, refuse

MAX_READ_BYTES = 400_000
MAX_WRITE_BYTES = 1_000_000
_CONTAINER_ROOT = "/workspace"
# writing here can make the *host* run code later (git hooks, git config)
_ASK_BEFORE_WRITING = {".git"}


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def parts(self, path: str) -> list[str]:
        if "\x00" in path:
            raise ToolError("path contains a null byte")
        if path == _CONTAINER_ROOT or path.startswith(_CONTAINER_ROOT + "/"):
            path = path[len(_CONTAINER_ROOT):].lstrip("/")
        pure = PurePosixPath(path)
        if pure.is_absolute():
            raise ToolError("use a path relative to the workspace (or under /workspace)")
        parts = [p for p in pure.parts if p != "."]
        if not parts:
            raise ToolError("path is empty")
        if ".." in parts:
            raise ToolError("'..' is not allowed in paths")
        return parts

    def open(self, path: str, flags: int, *, create_parents: bool = False) -> int:
        parts = self.parts(path)
        current = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in parts[:-1]:
                try:
                    nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                except FileNotFoundError:
                    if not create_parents:
                        raise
                    os.mkdir(name, 0o755, dir_fd=current)
                    nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = nxt
            return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644, dir_fd=current)
        except OSError as exc:
            raise ToolError(_explain(exc, path)) from None
        finally:
            os.close(current)


def _explain(exc: OSError, path: str) -> str:
    if exc.errno in (errno.ELOOP, errno.EMLINK):
        return f"{path}: symlinks are not followed"
    if exc.errno == errno.ENOTDIR:
        return f"{path}: a part of this path is not a directory (or is a symlink)"
    if exc.errno == errno.ENOENT:
        return f"{path}: no such file"
    if exc.errno == errno.EISDIR:
        return f"{path}: is a directory"
    return f"{path}: {exc.strerror}"


def read_file_tool(workspace: Workspace, audit: AuditLog) -> Tool:
    def handler(args: dict) -> str:
        path = args["path"]
        fd = workspace.open(path, os.O_RDONLY)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ToolError(f"{path}: not a regular file")
            data = os.read(fd, MAX_READ_BYTES + 1)
        finally:
            os.close(fd)
        audit.append(actor="tool:read_file", action="file.read", target=path[:300], decision="allow")
        if b"\x00" in data[:8192]:
            raise ToolError(f"{path}: looks like a binary file")
        text = data[:MAX_READ_BYTES].decode("utf-8", errors="replace")
        if len(data) > MAX_READ_BYTES:
            text += f"\n[file truncated at {MAX_READ_BYTES} bytes]"
        return text

    return Tool(
        "read_file", "Read a text file from the project folder. Symlinks are not followed.",
        {"type": "object", "properties": {"path": {"type": "string", "description": "Path relative to the project folder"}},
         "required": ["path"]},
        handler)


def write_file_tool(workspace: Workspace, audit: AuditLog, confirm: Confirm = refuse) -> Tool:
    def handler(args: dict) -> str:
        path, content = args["path"], args["content"]
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolError(f"content is {len(data)} bytes; the limit is {MAX_WRITE_BYTES}")
        parts = workspace.parts(path)
        target = path[:300]
        if parts[0] in _ASK_BEFORE_WRITING:
            approved = confirm(f"write {len(data)} bytes to {path}",
                               f"files under {parts[0]}/ can run code on your machine later")
            audit.append(actor="human", action="file.write.answer", target=target,
                         decision="allow" if approved else "deny")
            if not approved:
                raise ToolError(f"Writing to {path} was not approved by the user.")
        audit.append(actor="tool:write_file", action="file.write", target=target, decision="allow",
                     detail={"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        fd = workspace.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, create_parents=True)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ToolError(f"{path}: not a regular file")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        return f"Wrote {len(data)} bytes to {path}."

    return Tool(
        "write_file", "Create or overwrite a text file in the project folder. Parent folders are created.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path relative to the project folder"},
            "content": {"type": "string", "description": "The full new content of the file"}},
         "required": ["path", "content"]},
        handler)
