"""The one path by which a shell command gets run.

approval verdict -> (human, if asked) -> scoped credentials -> sandbox,
with an audit entry at each step. If the audit log cannot be written the
command does not run.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from .approval import ApprovalPolicy, Decision, Verdict
from .audit import AuditLog
from .credentials import CredentialBroker
from .sandbox import ExecResult, Sandbox

Approver = Callable[[str, Verdict], bool]


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
                 audit: AuditLog, approver: Approver = deny_all):
        self.policy, self.sandbox, self.broker = policy, sandbox, broker
        self.audit, self.approver = audit, approver

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
            approved = bool(self.approver(command, verdict))
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

    def _describe(self, command: str) -> str:
        digest = hashlib.sha256(command.encode()).hexdigest()[:16]
        return f"sha256:{digest} {self.broker.redact(command)[:200]}"
