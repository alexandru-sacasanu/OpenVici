"""Floors: blocks that nothing can switch off.

They run before the allowlist and before any future "approve everything"
mode. There is deliberately no flag that skips them. Two kinds:

* hardline rules: a short list of commands whose only realistic outcome is an
  unrecoverable machine;
* the user's own ``approvals.deny`` globs ("never let the agent run this").

Both are pattern checks on text the model wrote. They prevent accidents. They
do not contain a model that is trying to get past them; the sandbox does.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass

from .analyze import Analysis, Segment

_CRITICAL_PATHS = {
    "/", "~", "$HOME", "${HOME}",
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var", "/home",
    "/root", "/opt", "/sys", "/proc", "/dev",
    "/System", "/Library", "/Applications", "/Users",
}
_BLOCK_DEVICE = re.compile(r"^/dev/(sd|hd|vd|xvd|nvme|mmcblk|disk|rdisk|dm-|md|loop)")
_FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*&[^}]*\}\s*;\s*:")
_RAW_DEVICE_WRITE = re.compile(r">\s*/dev/(sd|hd|vd|xvd|nvme|mmcblk|disk|rdisk)")


@dataclass(frozen=True)
class FloorHit:
    rule: str
    detail: str


def check_hardline(analysis: Analysis) -> FloorHit | None:
    if _FORK_BOMB.search(analysis.raw):
        return FloorHit("fork-bomb", "defines a function that calls itself in the background")
    if _RAW_DEVICE_WRITE.search(analysis.raw):
        return FloorHit("raw-device-write", "redirects output onto a disk device")
    for seg in analysis.segments:
        hit = _check_segment(seg)
        if hit:
            return hit
    return None


def match_user_deny(analysis: Analysis, globs: list[str]) -> str | None:
    """The first ``approvals.deny`` glob that matches, tried case-insensitively
    against every spelling of the command (so ``r\\m`` and ``sudo rm`` are
    seen as ``rm``)."""
    patterns = [g.strip().lower() for g in globs if g.strip()]
    for text in analysis.texts():
        for pattern in patterns:
            if fnmatch.fnmatchcase(text.lower(), pattern):
                return pattern
    return None


def _check_segment(seg: Segment) -> FloorHit | None:
    if seg.sudo_stdin:
        return FloorHit("sudo-stdin", "feeds a password to sudo on stdin")
    if not seg.argv:
        return None
    prog, args = seg.program, seg.argv[1:]

    if prog == "rm":
        if "--no-preserve-root" in args:
            return FloorHit("rm-root", "rm --no-preserve-root")
        target = _critical_target(args)
        if _is_recursive(args) and target:
            return FloorHit("rm-critical-path", f"recursive rm of {target}")
    elif prog in {"chmod", "chown", "chgrp"}:
        target = _critical_target(args)
        if _is_recursive(args) and target:
            return FloorHit("recursive-perms-critical-path", f"recursive {prog} of {target}")
    elif prog.startswith("mkfs") or prog in {"wipefs", "blkdiscard"}:
        return FloorHit("format-device", f"{prog} erases a filesystem")
    elif prog == "dd":
        for arg in args:
            if arg.startswith("of=") and _BLOCK_DEVICE.match(arg[3:]):
                return FloorHit("dd-device", f"dd onto {arg[3:]}")
    elif prog == "shred":
        for arg in args:
            if _BLOCK_DEVICE.match(arg):
                return FloorHit("shred-device", f"shred of {arg}")
    return None


def _is_recursive(args: tuple[str, ...]) -> bool:
    for arg in args:
        if arg == "--":
            break
        if arg == "--recursive":
            return True
        if arg.startswith("-") and not arg.startswith("--") and ("r" in arg or "R" in arg):
            return True
    return False


def _critical_target(args: tuple[str, ...]) -> str | None:
    for arg in args:
        if arg.startswith("-"):
            continue
        path = arg
        while path.endswith("/*"):
            path = path[:-2] or "/"
        if path.startswith("/"):
            path = "/" + posixpath.normpath(path).lstrip("/")  # "/etc/.." and "/." are "/"
        elif len(path) > 1:
            path = path.rstrip("/") or "/"
        if path in _CRITICAL_PATHS:
            return arg
    return None
