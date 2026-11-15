"""openvici setup | doctor | chat | dashboard | sessions | memory | forget | check | run | audit"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .agent import Agent
from .approval import ApprovalPolicy, Verdict
from .approval.smart import SmartReviewer
from .audit import AuditError, AuditLog
from .config import Config, ConfigError, load_config
from .context import ContextEngine
from .dashboard import DashboardError, DashboardServer
from .credentials import CredentialBroker, CredentialError
from .executor import Executor
from .forget import forget_session
from .memory import TARGETS, MemoryStore
from .sessions import SessionError, SessionStore, new_session_id
from .providers import ProviderError, make_provider
from .redact import chain, redact_patterns
from .sandbox import SandboxError, make_sandbox
from .tools import (SessionState, ToolRegistry, Workspace, memory_tool, read_file_tool,
                    session_search_tool, shell_tool, stash_command, web_fetch_tool, write_file_tool)


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

    def api_key(credential: str) -> str:
        if not credential:
            return ""
        granted = broker.env_for("model")
        if credential not in granted:
            raise CredentialError(f"credential \"{credential}\" must be listed under "
                                  "[credentials.grants] model = [...]")
        return granted[credential]

    m = config.model
    provider = make_provider(m.provider, m.name, api_key(m.credential), m.base_url, m.max_tokens)
    reviewer = None
    if config.smart.enabled:
        sm = config.smart
        reviewer = SmartReviewer(
            make_provider(sm.provider or m.provider, sm.name or m.name, api_key(sm.credential or m.credential),
                          sm.base_url or m.base_url, max_tokens=100),
            sm.max_chars)
    sandbox = make_sandbox(config.sandbox_mode, config.sandbox)
    workspace = Workspace(sandbox.policy.workspace)
    executor = Executor(ApprovalPolicy(deny=config.deny, allow=config.allow), sandbox, broker, audit, approver,
                        reviewer=reviewer, stash=lambda command: stash_command(workspace, command),
                        is_tainted=lambda: session.tainted)
    memory = MemoryStore(config.memory_dir, config.memory_limits)
    tools = ToolRegistry([
        read_file_tool(workspace, audit),
        write_file_tool(workspace, audit, confirm),
        shell_tool(executor),
        web_fetch_tool(config.web, audit, confirm, on_content=lambda: setattr(session, "tainted", True)),
        memory_tool(memory, session, audit, confirm, config.memory_write_approval, broker.redact),
        session_search_tool(sessions, session),
    ], redact=chain(broker.redact, redact_patterns) if config.redact_patterns else broker.redact)
    context = ContextEngine(max_chars=config.context_chars, memory_snapshot=memory.snapshot())
    return Agent(provider, tools, context, config.max_steps)


WELCOME = """Welcome to OpenVici. A few things to know before your first message:

  - The agent works in the folder you started it from. It can read and write files there.
  - Shell commands run in an isolated container with no network. Before one runs you are
    shown the exact command and asked y/N, unless it matches a rule you allowed.
  - Web pages outside your allowed domains are also shown to you before they are fetched.
  - It can keep short notes between sessions. `openvici memory` shows them.

Things to try:
  explain what this project does
  find where the config file is loaded and add a comment explaining it
  run the tests and tell me what fails

Type /help for commands, /exit to leave.
"""

HELP = """Commands inside the chat:
  /help     this text
  /exit     leave (Ctrl-D also works)

When the agent asks "Run it? [y/N]": y runs that one command, anything else refuses it.
A line starting with BLOCKED means a safety rule stopped the command; that cannot be overridden.

Outside the chat:
  openvici dashboard            chat, settings and status in the browser
  openvici memory               what the agent remembers about you and your work
  openvici sessions search X    find something said in an earlier session
  openvici forget --session ID  delete a session and the notes it wrote
  openvici check "command"      see whether a command would run, ask or be blocked
  openvici doctor               check the installation
"""

FIRST_SESSION_NOTE = (
    "This is the user's first session with you. In your first reply, before anything else, say in two or "
    "three short sentences what you can do here (read and edit files in their project, run commands in a "
    "sandbox after they approve, look things up on the web, remember notes between sessions) and ask what "
    "they are working on. Do this once.")


def _chat(config: Config, audit: AuditLog) -> int:
    if not config.model.name:
        print("No model is set up yet. Run this first:\n\n  openvici setup\n", file=sys.stderr)
        return 3
    sessions = SessionStore(config.sessions_path)
    first_time = not sessions.list(1)
    session = SessionState(new_session_id())
    agent = build_agent(config, audit, session, sessions)
    if first_time:
        print(WELCOME, file=sys.stderr)
        agent.context.first_session_note = FIRST_SESSION_NOTE
    print(f"OpenVici, session {session.id}. /help for commands, /exit to leave.", file=sys.stderr)
    while True:
        try:
            line = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 0
        if line in ("/exit", "/quit"):
            return 0
        if line == "/help":
            print(HELP, file=sys.stderr)
            continue
        if line.startswith("/"):
            print(f"Unknown command {line.split()[0]}. Type /help.", file=sys.stderr)
            continue
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
    parser = argparse.ArgumentParser(
        prog="openvici", description="A personal AI agent that is isolated by default.",
        epilog="First time here? Run: openvici setup")
    parser.add_argument("--version", action="version", version=f"openvici {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="choose a model and get ready for the first conversation")
    sub.add_parser("doctor", help="check that the installation is ready")
    sub.add_parser("chat", help="talk to the agent")
    p_dash = sub.add_parser("dashboard", help="open the local web dashboard")
    p_dash.add_argument("--port", type=int, help="port on 127.0.0.1 (default: dashboard.port, 8765)")
    p_dash.add_argument("--no-open", action="store_true", help="print the link without opening a browser")
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
        if args.cmd == "setup":
            if not sys.stdin.isatty():
                print("openvici setup asks questions; run it in a terminal.", file=sys.stderr)
                return 2
            import getpass
            from .setup import run_setup
            return run_setup(input, getpass.getpass, print)
        if args.cmd == "doctor":
            from .doctor import report, run_checks
            text, code = report(run_checks())
            print(text)
            return code

        config = load_config()
        policy = ApprovalPolicy(deny=config.deny, allow=config.allow)
        audit = AuditLog(config.audit_path)

        if args.cmd == "chat":
            return _chat(config, audit)

        if args.cmd == "dashboard":
            server = DashboardServer(port=args.port if args.port is not None else config.dashboard_port)
            print("OpenVici dashboard, reachable from this machine only. Open this link:\n")
            print(f"  {server.url}\n")
            print("The link carries this session's access key; do not share it. Ctrl-C to stop.", flush=True)
            if not args.no_open:
                import webbrowser
                webbrowser.open(server.url)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.shutdown()
            return 0

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
    except (ConfigError, SandboxError, CredentialError, AuditError, ProviderError, SessionError, DashboardError,
            ValueError) as exc:
        print(f"openvici: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
