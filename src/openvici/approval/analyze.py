"""Turn a shell command string into something rules can be written against.

This is a heuristic reading of an attacker-influenced string, not a shell
parser. Shell is Turing-complete; anything here can be defeated by a command
built to defeat it (``a=rm; $a -rf /``). Its job is to catch mistakes and the
cheap tricks (quoting, wrappers, ``bash -c``, substitutions), and to say when
it could not understand a command so that nothing unclear is auto-approved.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

MAX_COMMAND_CHARS = 50_000
_MAX_DEPTH = 4
_OPERATOR_CHARS = set("();<>|&\n")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SAFE_REDIRECT_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr"}

# wrapper -> flags that swallow the following token
_WRAPPERS: dict[str, set[str]] = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D", "-R", "-T",
             "--user", "--group", "--host", "--prompt", "--chdir"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "--unset", "--chdir"},
    "exec": {"-a"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "xargs": {"-I", "-n", "-P", "-d", "-L", "-s", "-E"},
    "stdbuf": {"-i", "-o", "-e"},
    "command": set(), "builtin": set(), "nohup": set(), "time": set(), "setsid": set(),
}
_PRIVILEGE_WRAPPERS = {"sudo", "doas"}


@dataclass(frozen=True)
class Segment:
    """One simple command: ``argv`` after wrappers and ``VAR=x`` prefixes are
    peeled off, with ``argv[0]`` reduced to its basename."""

    argv: tuple[str, ...]
    text: str
    writes_file: bool = False
    privileged: bool = False
    sudo_stdin: bool = False

    @property
    def program(self) -> str:
        return self.argv[0] if self.argv else ""


@dataclass
class Analysis:
    raw: str
    parsed: bool = True
    segments: list[Segment] = field(default_factory=list)
    has_substitution: bool = False
    has_dynamic_program: bool = False

    def texts(self) -> list[str]:
        """Every spelling of the command a glob rule should be tried against."""
        seen: dict[str, None] = {" ".join(self.raw.split()): None}
        for seg in self.segments:
            seen[seg.text] = None
            seen[" ".join(seg.argv)] = None
        return [t for t in seen if t]


def analyze(command: str) -> Analysis:
    result = Analysis(raw=command)
    if len(command) > MAX_COMMAND_CHARS:
        result.parsed = False
        return result
    _collect(command, result, depth=0)
    return result


def _collect(command: str, out: Analysis, depth: int) -> None:
    if depth > _MAX_DEPTH:
        out.parsed = False
        return
    command = command.replace("\\\n", "")
    if "`" in command:
        out.has_substitution = True
        _collect(command.replace("`", "\n"), out, depth + 1)
        return
    try:
        tokens = _tokenize(command)
    except ValueError:
        out.parsed = False
        return

    current: list[str] = []
    writes = False
    i = 0
    while i < len(tokens):
        tok, is_op = tokens[i]
        if not is_op:
            current.append(tok)
            i += 1
            continue
        nxt = tokens[i + 1][0] if i + 1 < len(tokens) and not tokens[i + 1][1] else None
        if "(" in tok:
            out.has_substitution = True
        if set(tok) <= set("<>&") and ("<" in tok or ">" in tok):
            # a redirect: stays inside the current segment
            is_fd_dup = tok.endswith("&") and nxt is not None and (nxt.isdigit() or nxt == "-")
            if ">" in tok and not is_fd_dup and nxt not in _SAFE_REDIRECT_TARGETS:
                writes = True
            if current and current[-1].isdigit():
                current.pop()  # the "2" of "2>"
            i += 2 if nxt is not None else 1
            continue
        _finish(current, writes, out, depth)
        current, writes = [], ">" in tok
        i += 1
    _finish(current, writes, out, depth)


def _tokenize(command: str) -> list[tuple[str, bool]]:
    """(token, is_operator). Newlines separate commands; ``#`` is kept as a
    plain character because shlex would drop ``foo#bar; rm`` as a comment
    where a real shell runs the ``rm``."""
    lex = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    out = []
    while True:
        tok = lex.get_token()
        if tok is None:
            break
        out.append((tok, bool(tok) and set(tok) <= _OPERATOR_CHARS))
    return out


def _finish(words: list[str], writes: bool, out: Analysis, depth: int) -> None:
    if not words:
        return
    text = " ".join(words)
    if words and words[-1].endswith("$"):
        out.has_substitution = True  # the "$" of "$(...)"
    argv, privileged, sudo_stdin = _peel(list(words))
    if not argv:
        out.segments.append(Segment((), text, writes, privileged, sudo_stdin))
        return
    argv[0] = os.path.basename(argv[0]) or argv[0]
    if "$" in argv[0]:
        out.has_dynamic_program = True
    out.segments.append(Segment(tuple(argv), text, writes, privileged, sudo_stdin))

    inner = _inner_script(argv)
    if inner is not None:
        out.has_substitution = True
        _collect(inner, out, depth + 1)


def _peel(words: list[str]) -> tuple[list[str], bool, bool]:
    """Drop ``VAR=x`` prefixes and wrappers such as ``sudo -u root``."""
    privileged = sudo_stdin = False
    for _ in range(8):
        while words and _ASSIGNMENT.match(words[0]):
            words.pop(0)
        if not words:
            break
        name = os.path.basename(words[0])
        if name not in _WRAPPERS:
            break
        takes_value = _WRAPPERS[name]
        words.pop(0)
        if name in _PRIVILEGE_WRAPPERS:
            privileged = True
        while words and (words[0].startswith("-") or _ASSIGNMENT.match(words[0])):
            flag = words.pop(0)
            if flag == "--":
                break
            if name == "sudo" and (flag == "--stdin" or (not flag.startswith("--") and "S" in flag)):
                sudo_stdin = True
            if flag in takes_value and words:
                words.pop(0)
        if name == "timeout" and words:
            words.pop(0)  # the duration
    return words, privileged, sudo_stdin


def _inner_script(argv: list[str]) -> str | None:
    """The script text of ``bash -c '...'`` or ``eval ...``, if any."""
    if argv[0] == "eval" and len(argv) > 1:
        return " ".join(argv[1:])
    if argv[0] in _SHELLS:
        for idx, arg in enumerate(argv[1:], start=1):
            if not arg.startswith("-"):
                return None
            if not arg.startswith("--") and "c" in arg:
                return argv[idx + 1] if idx + 1 < len(argv) else None
    return None
