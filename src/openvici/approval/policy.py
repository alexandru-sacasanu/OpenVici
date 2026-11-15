"""The approval decision for one shell command.

Order, and nothing reorders it:

1. floors (hardline rules, then the user's deny globs) -> DENY
2. the user's allow globs, only for commands that were fully understood -> ALLOW
3. everything else -> ASK a human

A command is never auto-allowed when the analysis could not read it, when it
contains a substitution, a computed program name, privilege escalation or a
write redirect. Those always go to a human.
"""

from __future__ import annotations

import enum
import fnmatch
from dataclasses import dataclass, field

from .analyze import Analysis, analyze
from .floors import check_hardline, match_user_deny


class Decision(enum.Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    rule: str
    reason: str
    understood: bool = False  # ASK only: the command was fully analysed and merely lacks an allow rule


@dataclass(frozen=True)
class ApprovalPolicy:
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)

    def evaluate(self, command: str) -> Verdict:
        if not command.strip():
            return Verdict(Decision.DENY, "empty", "empty command")
        analysis = analyze(command)

        hit = check_hardline(analysis)
        if hit:
            return Verdict(Decision.DENY, f"hardline:{hit.rule}", hit.detail)
        pattern = match_user_deny(analysis, self.deny)
        if pattern:
            return Verdict(Decision.DENY, "user-deny", f"matches your deny rule '{pattern}'")

        blocker = _why_not_auto(analysis)
        if blocker:
            return Verdict(Decision.ASK, "needs-human", blocker)
        if self.allow and all(_allowed(seg.text, self.allow) for seg in analysis.segments):
            return Verdict(Decision.ALLOW, "user-allow", "every part matches your allow rules")
        return Verdict(Decision.ASK, "needs-human", "not covered by an allow rule", understood=True)


def _why_not_auto(analysis: Analysis) -> str | None:
    if not analysis.parsed:
        return "the command could not be fully read (unbalanced quotes, too long or too nested)"
    if not analysis.segments:
        return "no runnable command found"
    if analysis.has_substitution:
        return "contains a command substitution or nested shell"
    if analysis.has_dynamic_program:
        return "the program name is computed from a variable"
    for seg in analysis.segments:
        if seg.privileged:
            return "asks for elevated privileges"
        if seg.writes_file:
            return "redirects output into a file"
        if not seg.argv:
            return "contains a part with no program"
    return None


def _allowed(text: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(text, g.strip()) for g in globs if g.strip())
