"""openvici check | run | audit verify | audit head"""

from __future__ import annotations

import argparse
import sys

from .approval import ApprovalPolicy, Verdict
from .audit import AuditError, AuditLog
from .config import ConfigError, load_config
from .credentials import CredentialBroker, CredentialError
from .executor import Executor
from .sandbox import SandboxError, make_sandbox


def _ask_on_tty(command: str, verdict: Verdict) -> bool:
    if not sys.stdin.isatty():
        return False
    print(f"\nThe agent wants to run:\n  {command}\nWhy you are asked: {verdict.reason}", file=sys.stderr)
    return input("Run it? [y/N] ").strip().lower() == "y"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openvici")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="show the approval verdict for a command without running it")
    p_check.add_argument("command")
    p_run = sub.add_parser("run", help="run a command through approval, credentials and the sandbox")
    p_run.add_argument("--tool", default="shell")
    p_run.add_argument("command")
    p_audit = sub.add_parser("audit", help="inspect the audit log")
    p_audit.add_argument("what", choices=["verify", "head"])
    p_audit.add_argument("--checkpoint", help="SEQ:HASH from an earlier `audit head`, kept elsewhere")
    args = parser.parse_args(argv)

    try:
        config = load_config()
        policy = ApprovalPolicy(deny=config.deny, allow=config.allow)
        audit = AuditLog(config.audit_path)

        if args.cmd == "check":
            verdict = policy.evaluate(args.command)
            print(f"{verdict.decision.value.upper()}  [{verdict.rule}]  {verdict.reason}")
            return 0

        if args.cmd == "audit":
            if args.what == "head":
                seq, digest = audit.head()
                print(f"{seq}:{digest}")
                return 0
            checkpoint = None
            if args.checkpoint:
                seq, _, digest = args.checkpoint.partition(":")
                checkpoint = (int(seq), digest)
            result = audit.verify(checkpoint)
            print(f"{'OK' if result.ok else 'FAILED'}  {result.entries} entries" +
                  (f"  {result.error}" if result.error else ""))
            return 0 if result.ok else 1

        sandbox = make_sandbox(config.sandbox_mode, config.sandbox)
        broker = CredentialBroker(config.credentials_path, config.grants, audit)
        outcome = Executor(policy, sandbox, broker, audit, _ask_on_tty).run_shell(args.tool, args.command)
        if not outcome.ran:
            print(outcome.message, file=sys.stderr)
            return 2
        sys.stdout.write(outcome.result.stdout)
        sys.stderr.write(outcome.result.stderr)
        return outcome.result.exit_code
    except (ConfigError, SandboxError, CredentialError, AuditError, ValueError) as exc:
        print(f"openvici: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
