"""The one path by which a shell command gets run.

    floors -> allow rules -> [smart reviewer] -> human -> scoped credentials -> sandbox

with an audit entry at each step. If the audit log cannot be written the
command does not run.

Two things happen only on the ASK branch:

* a command too long for a person to read in a prompt is not shown and not
  run; it is saved as a script in the workspace so the user can open it, and
  the agent is told to ask for that script to be run instead;
* if a smart reviewer is configured and the command was fully understood,
  the reviewer may approve it. See ``approval/smart.py`` for why that is the
  only thing it may do.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from typing import Callable

from .approval import ApprovalPolicy, Decision, Verdict
from .approval.smart import SmartReviewer
from .audit import AuditLog
from .credentials import CredentialBroker
from .sandbox import ExecResult, Sandbox

Approver = Callable[[str, Verdict], bool]
Stash = Callable[[str], str]  # saves the command text, returns the path the agent can refer to

MAX_PROMPT_CHARS = 4000
STASH_DIR = ".openvici/pending"


def deny_all(command: str, verdict: Verdict) -> bool:
    """Default approver: with no human attached, an ASK is a no."""
    return False


@dataclass(frozen=True)
class Outcome:
    ran: bool
    verdict: Verdict
    result: ExecResult | None = None
    message: str = ""


class Executor:
    def __init__(self, policy: ApprovalPolicy, sandbox: Sandbox, broker: CredentialBroker,
                 audit: AuditLog, approver: Approver = deny_all, *,
                 reviewer: SmartReviewer | None = None, stash: Stash | None = None,
                 is_tainted: Callable[[], bool] = lambda: False):
        self.policy, self.sandbox, self.broker = policy, sandbox, broker
        self.audit, self.approver = audit, approver
        self.reviewer, self.stash, self.is_tainted = reviewer, stash, is_tainted

    def run_shell(self, tool: str, command: str) -> Outcome:
        verdict = self.policy.evaluate(command)
        target = self._describe(command)
        self.audit.append(actor=f"tool:{tool}", action="approval.verdict", target=target,
                          decision=verdict.decision.value,
                          detail={"rule": verdict.rule, "reason": verdict.reason})

        if verdict.decision is Decision.DENY:
            return Outcome(False, verdict, message=(
                f"BLOCKED ({verdict.rule}): {verdict.reason}. This cannot be approved or overridden; "
                "do not retry or rephrase it."))

        if verdict.decision is Decision.ASK:
            if len(command) > MAX_PROMPT_CHARS and self.stash:
                path = self.stash(command)
                self.audit.append(actor=f"tool:{tool}", action="approval.stashed", target=target,
                                  decision="ask", detail={"path": path, "chars": len(command)})
                return Outcome(False, verdict, message=(
                    f"Not run: at {len(command)} characters this command is too long to show the user for "
                    f"approval. It was saved unchanged as {path}. Tell the user so they can read it; if they "
                    f"agree, run it with: sh {path}"))
            auto, shown = self._review(command, target, verdict)
            if not auto:
                approved = bool(self.approver(command, shown))
                self.audit.append(actor="human", action="approval.answer", target=target,
                                  decision="allow" if approved else "deny")
                if not approved:
                    return Outcome(False, verdict, message="Not approved by the operator.")

        env = self.broker.env_for(tool)
        self.audit.append(actor=f"tool:{tool}", action="exec.start", target=target,
                          decision="allow", detail={"isolated": self.sandbox.isolated})
        result = self.sandbox.run(command, env)
        result = ExecResult(result.exit_code, self.broker.redact(result.stdout),
                            self.broker.redact(result.stderr), result.timed_out)
        self.audit.append(actor=f"tool:{tool}", action="exec.end", target=target, decision="allow",
                          detail={"exit_code": result.exit_code, "timed_out": result.timed_out})
        return Outcome(True, verdict, result)

    def _review(self, command: str, target: str, verdict: Verdict) -> tuple[bool, Verdict]:
        """(run without asking, verdict to show the human). The first is True
        only when the reviewer said APPROVE for a fully understood command, in
        an isolated sandbox, in a session that has read no web content. A
        stashed script is never eligible: the reviewer would be judging
        ``sh file`` without seeing the file."""
        if (self.reviewer is None or not verdict.understood or not self.sandbox.isolated
                or STASH_DIR in command):
            return False, verdict
        review = self.reviewer.review(command)
        tainted = self.is_tainted()
        approved = review.approve and not tainted
        self.audit.append(actor="reviewer", action="approval.smart", target=target,
                          decision="allow" if approved else "ask",
                          detail={"answer": review.label, "reason": self.broker.redact(review.reason),
                                  "tainted": tainted})
        if approved:
            return True, verdict
        if review.approve:
            note = "reviewer would approve, but this session has read web content"
        elif review.label in ("deny", "escalate") and review.reason:
            note = f"reviewer says {review.label}: {review.reason}"
        else:
            note = f"reviewer: {review.label}" + (f" ({review.reason})" if review.reason else "")
        return False, dataclasses.replace(verdict, reason=f"{verdict.reason}; {note}")

    def _describe(self, command: str) -> str:
        digest = hashlib.sha256(command.encode()).hexdigest()[:16]
        return f"sha256:{digest} {self.broker.redact(command)[:200]}"
