"""openvici chat | sessions | memory | forget | check | run | audit"""

from __future__ import annotations

import argparse
import sys

from .agent import Agent
from .approval import ApprovalPolicy, Verdict
from .audit import AuditError, AuditLog
from .config import Config, ConfigError, load_config
from .context import ContextEngine
from .credentials import CredentialBroker, CredentialError
from .executor import Executor
from .forget import forget_session
from .memory import TARGETS, MemoryStore
from .sessions import SessionError, SessionStore, new_session_id
from .providers import ProviderError, make_provider
from .sandbox import SandboxError, make_sandbox
from .tools import (SessionState, ToolRegistry, Workspace, memory_tool, read_file_tool,
                    session_search_tool, shell_tool, web_fetch_tool, write_file_tool)


def _ask_on_tty(command: str, verdict: Verdict) -> bool:
    if not sys.stdin.isatty():
        return False
    print(f"\nThe agent wants to run:\n  {command}\nWhy you are asked: {verdict.reason}", file=sys.stderr)
    return input("Run it? [y/N] ").strip().lower() == "y"


def _confirm_on_tty(action: str, reason: str) -> bool:
    if not sys.stdin.isatty():
        return False
    print(f"\nThe agent wants to: {action}\nWhy you are asked: {reason}", file=sys.stderr)
    return input("Allow it? [y/N] ").strip().lower() == "y"


def build_agent(config: Config, audit: AuditLog, session: SessionState, sessions: SessionStore,
                approver=_ask_on_tty, confirm=_confirm_on_tty) -> Agent:
    broker = CredentialBroker(config.credentials_path, config.grants, audit)
    api_key = ""
    if config.model.credential:
        granted = broker.env_for("model")
        if config.model.credential not in granted:
            raise CredentialError(
                f"[model] credential = \"{config.model.credential}\" must be listed under "
                "[credentials.grants] model = [...]")
        api_key = granted[config.model.credential]
    provider = make_provider(config.model.provider, config.model.name, api_key,
                             config.model.base_url, config.model.max_tokens)
    sandbox = make_sandbox(config.sandbox_mode, config.sandbox)
    executor = Executor(ApprovalPolicy(deny=config.deny, allow=config.allow), sandbox, broker, audit, approver)
    workspace = Workspace(sandbox.policy.workspace)
    memory = MemoryStore(config.memory_dir, config.memory_limits)
    tools = ToolRegistry([
        read_file_tool(workspace, audit),
        write_file_tool(workspace, audit, confirm),
        shell_tool(executor),
        web_fetch_tool(config.web, audit, confirm, on_content=lambda: setattr(session, "tainted", True)),
        memory_tool(memory, session, audit, confirm, config.memory_write_approval, broker.redact),
        session_search_tool(sessions, session),
    ])
    context = ContextEngine(max_chars=config.context_chars, memory_snapshot=memory.snapshot())
    return Agent(provider, tools, context, config.max_steps)


def _chat(config: Config, audit: AuditLog) -> int:
    sessions = SessionStore(config.sessions_path)
    session = SessionState(new_session_id())
    agent = build_agent(config, audit, session, sessions)
    print(f"OpenVici, session {session.id}. Ctrl-D or /exit to leave.", file=sys.stderr)
    while True:
        try:
            line = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 0
        if line in ("/exit", "/quit"):
            return 0
        if not line:
            continue
        before = len(agent.history)
        try:
            reply = agent.run_turn(line, on_tool_call=lambda c: print(
                f"  [{c.name}] {str(c.arguments)[:160]}", file=sys.stderr))
        except ProviderError as exc:
            print(f"model error: {exc}", file=sys.stderr)
            continue
        sessions.record(session.id, agent.history[before:])
        print(f"\n{reply}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openvici")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("chat", help="talk to the agent")
    p_sessions = sub.add_parser("sessions", help="list or search earlier sessions")
    p_sessions.add_argument("what", choices=["list", "search"])
    p_sessions.add_argument("query", nargs="?", default="")
    sub.add_parser("memory", help="show long-term memory and how full it is")
    p_forget = sub.add_parser("forget", help="delete a session's messages and the memories it wrote")
    p_forget.add_argument("--session", required=True)
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

        if args.cmd == "chat":
            return _chat(config, audit)

        if args.cmd == "sessions":
            store = SessionStore(config.sessions_path)
            if args.what == "list":
                for info in store.list():
                    print(f"{info.id}  {info.messages:>4} msgs  {info.first_line}")
            else:
                for hit in store.search(args.query):
                    print(f"{hit.session_id}  {hit.role:<9}  {' '.join(hit.snippet.split())}")
            return 0

        if args.cmd == "memory":
            memory = MemoryStore(config.memory_dir, config.memory_limits)
            for target, filename in TARGETS.items():
                used, limit = memory.usage(target)
                print(f"{filename}  {used}/{limit} characters  ({memory.directory / filename})")
                for entry in memory.entries(target):
                    print(f"  - {entry.text}  [{', '.join(entry.sessions) or 'typed by hand'}]")
            return 0

        if args.cmd == "forget":
            report = forget_session(args.session, SessionStore(config.sessions_path),
                                    MemoryStore(config.memory_dir, config.memory_limits), audit)
            if not report.known:
                print(f"No session {report.session_id} found; nothing to delete.")
                return 1
            print(f"Deleted {report.messages_deleted} messages and {report.memory_entries_removed} memory entries "
                  f"from session {report.session_id}.")
            print("Verified: no trace left in the session database or memory files." if report.verified
                  else "WARNING: verification failed; some data from this session is still present.")
            print("Not touched: the audit log (action records only), files written in the workspace, "
                  "and anything your model provider keeps.")
            return 0 if report.verified else 1

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
    except (ConfigError, SandboxError, CredentialError, AuditError, ProviderError, SessionError, ValueError) as exc:
        print(f"openvici: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
