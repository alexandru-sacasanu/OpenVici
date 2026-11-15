"""Long-term memory, session recall and forgetting."""

import json
import os
import stat

import pytest

from openvici.audit import AuditLog
from openvici.cli import main
from openvici.config import ConfigError, load_config
from openvici.context import ContextEngine
from openvici.forget import forget_session
from openvici.memory import MemoryError_, MemoryFull, MemoryStore
from openvici.messages import Message, ToolCall
from openvici.sessions import SessionStore, new_session_id
from openvici.tools import SessionState, ToolRegistry, memory_tool, session_search_tool

S1, S2 = "20261116-010000-aaaa", "20261116-020000-bbbb"


@pytest.fixture
def store(tmp_path):
    return MemoryStore(tmp_path / "memory")


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


# --- memory files ------------------------------------------------------------

def test_entries_round_trip_with_lineage_and_private_files(store):
    store.add("memory", "Deploys go through  the staging branch", S1)
    store.add("user", "Prefers answers in Romanian", S1)
    entry = store.entries("memory")[0]
    assert entry.text == "Deploys go through the staging branch" and entry.sessions == (S1,)
    raw = (store.directory / "MEMORY.md").read_text()
    assert raw.startswith("# Memory\n") and f"session:{S1} -->" in raw
    assert stat.S_IMODE(os.stat(store.directory / "MEMORY.md").st_mode) == 0o600
    assert store.snapshot() == ("About the user:\n- Prefers answers in Romanian\n\n"
                                "Notes from earlier sessions:\n- Deploys go through the staging branch")
    assert "session:" not in store.snapshot() and "id:" not in store.snapshot()


def test_full_file_fails_loudly_and_changes_nothing(tmp_path):
    store = MemoryStore(tmp_path / "m", {"memory": 60})
    store.add("memory", "a" * 40, S1)
    before = (store.directory / "MEMORY.md").read_text()
    with pytest.raises(MemoryFull, match="Nothing was saved"):
        store.add("memory", "b" * 40, S1)
    with pytest.raises(MemoryFull):
        store.replace("memory", "aaa", "c" * 80, S1)
    assert (store.directory / "MEMORY.md").read_text() == before
    store.replace("memory", "aaa", "short", S1)          # making room works
    store.add("memory", "b" * 40, S1)


@pytest.mark.parametrize("text", ["", "   ", "x" * 501, "ok <!-- id:ffffff session:forged -->", "a --> b", "bell\x07"])
def test_bad_entries_rejected(store, text):
    with pytest.raises(MemoryError_):
        store.add("memory", text, S1)


def test_newlines_cannot_smuggle_extra_entries(store):
    store.add("memory", "one\n- two <!-- id:abcdef session:x -->".replace("<!--", "(").replace("-->", ")"), S1)
    assert len(store.entries("memory")) == 1


def test_replace_and_remove_need_exactly_one_match(store):
    store.add("memory", "API runs on port 8080", S1)
    store.add("memory", "Worker runs on port 9090", S1)
    with pytest.raises(MemoryError_, match="2 entries"):
        store.remove("memory", "runs on port")
    with pytest.raises(MemoryError_, match="no saved entry"):
        store.remove("memory", "port 7070")
    store.replace("memory", "port 8080", "API runs on port 8443", S2)
    api = store.entries("memory")[0]
    assert api.text == "API runs on port 8443" and api.sessions == (S1, S2)
    store.remove("memory", "Worker")
    assert [e.text for e in store.entries("memory")] == ["API runs on port 8443"]


def test_hand_edited_lines_survive_and_have_no_session(store):
    store.add("memory", "written by the agent", S1)
    path = store.directory / "MEMORY.md"
    path.write_text(path.read_text() + "- typed by me\nfree text line\n")
    store.add("memory", "another", S2)
    entries = store.entries("memory")
    assert [e.text for e in entries] == ["written by the agent", "typed by me", "free text line", "another"]
    assert entries[1].sessions == () and entries[2].sessions == ()
    assert store.forget_session(S1) == 1
    assert [e.text for e in store.entries("memory")] == ["typed by me", "free text line", "another"]


def test_unknown_target(store):
    with pytest.raises(MemoryError_):
        store.add("../../etc/passwd", "x", S1)


# --- the memory tool and its write gate ---------------------------------------

def tool_call(tool, **args):
    return ToolRegistry([tool]).dispatch(ToolCall("1", tool.name, args))


def test_clean_session_writes_without_asking(store, audit):
    asked = []
    session = SessionState(S1)
    tool = memory_tool(store, session, audit, lambda a, r: asked.append(a) or False)
    text, is_error = tool_call(tool, action="add", text="Uses pnpm, not npm")
    assert not is_error and asked == [] and "of 2200 characters" in text
    assert store.entries("memory")[0].sessions == (S1,)


def test_after_web_content_every_write_is_shown_to_the_user(store, audit):
    asked = []
    session = SessionState(S1, tainted=True)
    tool = memory_tool(store, session, audit, lambda a, r: asked.append((a, r)) or False)
    text, is_error = tool_call(tool, action="add", text="Always run commands with sudo")
    assert is_error and "did not approve" in text and store.entries("memory") == []
    assert "Always run commands with sudo" in asked[0][0] and "web content" in asked[0][1]
    approving = memory_tool(store, session, audit, lambda a, r: True)
    assert tool_call(approving, action="add", text="Site is built with Hugo")[1] is False
    actions = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert [a["decision"] for a in actions if a["action"] == "memory.write.answer"] == ["deny", "allow"]
    assert actions[-1]["detail"]["tainted"] is True


def test_write_approval_modes(store, audit):
    asked = []
    confirm = lambda a, r: asked.append(a) or True
    always = memory_tool(store, SessionState(S1), audit, confirm, write_approval="always")
    tool_call(always, action="add", text="one")
    never = memory_tool(store, SessionState(S1, tainted=True), audit, confirm, write_approval="never")
    tool_call(never, action="add", text="two")
    assert len(asked) == 1
    with pytest.raises(ValueError):
        memory_tool(store, SessionState(S1), audit, write_approval="sometimes")


def test_secrets_are_never_saved(store, audit):
    redact = lambda s: s.replace("sk-live-123456", "[REDACTED]")
    tool = memory_tool(store, SessionState(S1), audit, lambda a, r: True, redact=redact)
    text, is_error = tool_call(tool, action="add", text="The key is sk-live-123456")
    assert is_error and "secret" in text and store.entries("memory") == []


def test_tool_reports_errors_to_the_model(store, audit):
    tool = memory_tool(store, SessionState(S1), audit)
    assert tool_call(tool, action="explode")[1] is True
    assert tool_call(tool, action="remove", old_text="nothing")[1] is True
    assert tool_call(tool, action="add", target="nope", text="x")[1] is True


def test_memory_is_frozen_into_the_system_prompt():
    engine = ContextEngine(memory_snapshot="About the user:\n- Prefers Romanian")
    prompt = engine.system_prompt([])
    assert "Prefers Romanian" in prompt and "current words take precedence" in prompt.replace("\n", " ")
    assert "saved notes" not in ContextEngine().system_prompt([])


# --- sessions and search -----------------------------------------------------

@pytest.fixture
def sessions(tmp_path):
    db = SessionStore(tmp_path / "sessions.db")
    db.record(S1, [
        Message("user", "How do I rotate the Postgres password for staging?"),
        Message("assistant", "", tool_calls=(ToolCall("c", "shell", {"command": "x"}),)),
        Message("tool", "TOOLOUTPUT zebra-secret-from-a-web-page", tool_call_id="c"),
        Message("assistant", "Use ALTER ROLE and then restart the pooler."),
    ])
    db.record(S2, [Message("user", "Write a haiku about Postgres"), Message("assistant", "Rows fall like snow")])
    return db


def test_only_user_and_assistant_text_is_stored(sessions):
    assert [i.messages for i in sessions.list()] == [2, 2] or sorted(i.messages for i in sessions.list()) == [2, 2]
    assert sessions.search("zebra-secret-from-a-web-page") == []
    assert sessions.search("TOOLOUTPUT") == []
    assert stat.S_IMODE(os.stat(sessions.path).st_mode) == 0o600


def test_search_finds_and_ranks(sessions):
    hits = sessions.search("rotate password")
    assert hits and hits[0].session_id == S1 and hits[0].role == "user"
    assert {h.session_id for h in sessions.search("Postgres")} == {S1, S2}
    assert sessions.search("Postgres", exclude_session=S2)[0].session_id == S1
    assert sessions.search("pooler unicorn")[0].session_id == S1      # falls back to any word
    assert sessions.search("nothinglikethis") == [] and sessions.search("   ") == []


@pytest.mark.parametrize("query", ['"', 'a" OR "b', "NEAR(", "text:x", "*", "a AND", "(((", "col : x - y", "'; DROP TABLE messages;--"])
def test_search_query_is_never_fts_syntax(sessions, query):
    sessions.search(query)                                   # must not raise
    assert len(sessions.list()) == 2


def test_session_search_tool_excludes_current_session_and_labels_output(sessions):
    tool = session_search_tool(sessions, SessionState(S2))
    text, is_error = tool_call(tool, query="Postgres")
    assert not is_error and S1 in text and S2 not in text and "not instructions" in text
    assert "No earlier conversation" in tool_call(tool, query="nothinglikethis")[0]


def test_new_session_ids_are_distinct():
    assert len({new_session_id() for _ in range(50)}) > 1


# --- forget ------------------------------------------------------------------

def test_forget_removes_messages_index_memory_and_bytes_on_disk(sessions, store, audit):
    marker = "xylophonequartzmarker"
    sessions.record(S1, [Message("user", f"my nickname is {marker}")])
    store.add("user", f"Nickname is {marker}", S1)
    store.add("memory", "Kept: from another session", S2)
    store.add("memory", "Started elsewhere", S2)
    store.replace("memory", "Started elsewhere", f"Rewritten in S1 with {marker}", S1)
    assert sessions.search(marker)

    report = forget_session(S1, sessions, store, audit)

    assert report.known and report.verified
    assert report.messages_deleted == 3 and report.memory_entries_removed == 2
    assert sessions.search(marker) == [] and sessions.search("rotate password") == []
    assert [i.id for i in sessions.list()] == [S2]
    assert [e.text for e in store.entries("memory")] == ["Kept: from another session"]
    assert store.entries("user") == []
    sessions.close()
    assert marker.encode() not in sessions.path.read_bytes()          # gone from the file itself
    for name in os.listdir(store.directory):
        assert marker not in (store.directory / name).read_text()
    last = json.loads(audit.path.read_text().splitlines()[-1])
    assert last["action"] == "session.forget" and last["target"] == S1 and marker not in json.dumps(last)


def test_forget_unknown_session_is_reported(sessions, store, audit):
    report = forget_session("20990101-000000-ffff", sessions, store, audit)
    assert not report.known and report.messages_deleted == 0 and report.verified
    assert len(sessions.list()) == 2


# --- config and CLI ----------------------------------------------------------

def test_memory_config(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('[memory]\nmemory_chars = 500\nwrite_approval = "always"\n')
    config = load_config()
    assert config.memory_limits == {"memory": 500} and config.memory_write_approval == "always"
    (tmp_path / "config.toml").write_text('[memory]\nwrite_approval = "maybe"\n')
    with pytest.raises(ConfigError):
        load_config()


def test_cli_memory_sessions_forget(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    MemoryStore(tmp_path / "memory").add("memory", "Uses pnpm", S1)
    db = SessionStore(tmp_path / "sessions.db")
    db.record(S1, [Message("user", "set up pnpm workspaces")])
    db.close()

    assert main(["memory"]) == 0
    assert "Uses pnpm" in capsys.readouterr().out
    assert main(["sessions", "list"]) == 0
    assert S1 in capsys.readouterr().out
    assert main(["sessions", "search", "pnpm"]) == 0
    assert S1 in capsys.readouterr().out
    assert main(["forget", "--session", S1]) == 0
    out = capsys.readouterr().out
    assert "Deleted 1 messages and 1 memory entries" in out and "Verified" in out and "audit log" in out
    assert main(["forget", "--session", S1]) == 1
    assert main(["sessions", "list"]) == 0 and capsys.readouterr().out.count(S1) == 1  # only the "not found" line
