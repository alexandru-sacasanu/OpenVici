"""Setup wizard, doctor, and what a first-time user sees in chat."""

import json
import os
import stat

import pytest

from openvici import cli, setup
from openvici.audit import AuditLog
from openvici.config import load_config
from openvici.context import ContextEngine
from openvici.doctor import report, run_checks
from openvici.messages import Message, ModelTurn
from openvici.sessions import SessionStore


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path / "home"))
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.chdir(ws)
    monkeypatch.setattr(setup, "docker_state", lambda: (True, "Docker is running."))
    return tmp_path / "home"


def wizard(answers, secret="sk-test-key-123456"):
    answers = iter(answers)
    said = []
    code = setup.run_setup(lambda prompt: next(answers), lambda prompt: secret, said.append)
    return code, "\n".join(said)


# --- setup -------------------------------------------------------------------

def test_setup_for_a_hosted_model_writes_config_and_a_private_key_file(home):
    code, said = wizard(["1", "", "y", "n"])          # Anthropic, default model, allow read-only, skip test
    assert code == 0 and "openvici chat" in said
    config = load_config()
    assert config.model.provider == "anthropic" and config.model.name == "claude-sonnet-5-5"
    assert config.model.credential == "ANTHROPIC_API_KEY" and config.grants["model"] == ["ANTHROPIC_API_KEY"]
    assert "git status" in config.allow and "ls *" in config.allow
    creds = home / "credentials.json"
    assert json.loads(creds.read_text()) == {"ANTHROPIC_API_KEY": "sk-test-key-123456"}
    assert stat.S_IMODE(os.stat(creds).st_mode) == 0o600
    assert "sk-test-key" not in (home / "config.toml").read_text()      # the key is never in the config
    assert "sk-test-key" not in said
    audit = AuditLog(home / "audit.jsonl")
    assert '"target":"setup"' in audit.path.read_text() and audit.verify().ok


def test_setup_for_a_local_model_needs_no_key(home):
    code, _ = wizard(["3", "qwen2.5-coder", "n", "n"])
    config = load_config()
    assert config.model.base_url == "http://localhost:11434/v1" and config.model.name == "qwen2.5-coder"
    assert config.model.credential == "" and config.allow == [] and not (home / "credentials.json").exists()


def test_setup_reprompts_on_bad_input_and_custom_server(home):
    code, said = wizard(["9", "x", "4", "https://llm.example/v1", "", "my-model", "n", "n"])
    assert code == 0 and "Please type one of the numbers." in said and "A model name is needed" in said
    config = load_config()
    assert config.model.base_url == "https://llm.example/v1" and config.model.credential == "MODEL_API_KEY"


def test_running_setup_again_keeps_existing_settings_and_key(home):
    wizard(["1", "", "y", "n"])
    (home / "config.toml").write_text((home / "config.toml").read_text() + '\n[web]\nallow_domains = ["python.org"]\n')
    wizard(["1", "", "n", "n"], secret="")           # Enter at the key prompt keeps the stored key
    config = load_config()
    assert config.web.allow_domains == ["python.org"] and "git status" in config.allow
    assert json.loads((home / "credentials.json").read_text())["ANTHROPIC_API_KEY"] == "sk-test-key-123456"


def test_setup_says_plainly_when_docker_is_missing(home, monkeypatch):
    monkeypatch.setattr(setup, "docker_state", lambda: (False, "Docker is not installed."))
    _, said = wizard(["3", "m", "n", "n"])
    assert "Docker is not installed." in said and "shell commands stay off" in said


def test_model_test_reports_success_and_failure(home, monkeypatch):
    class Fake:
        def complete(self, system, messages, tools):
            return ModelTurn("ready")
    monkeypatch.setattr(setup, "make_provider", lambda *a, **k: Fake())
    _, said = wizard(["3", "m", "n", "y"])
    assert "The model answered: ready" in said
    monkeypatch.undo()
    monkeypatch.setenv("OPENVICI_HOME", str(home))
    message = setup.test_model({"provider": "anthropic", "name": "m", "base_url": "", "credential": "NOPE"})
    assert "did not work" in message and "openvici setup" in message


def test_setup_refuses_without_a_terminal(home, capsys):
    assert cli.main(["setup"]) == 2
    assert "run it in a terminal" in capsys.readouterr().err


# --- doctor ------------------------------------------------------------------

def test_doctor_on_a_fresh_install_points_to_setup(home, capsys):
    assert cli.main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "[FIX ] Model: none chosen yet. Run: openvici setup" in out and "1 thing(s) to fix" in out


def test_doctor_after_setup_is_ready(home, capsys):
    wizard(["1", "", "y", "n"])
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "Ready. Start with: openvici chat" in out and "[ok  ] API key" in out and "[ok  ] Audit log" in out


def test_doctor_catches_a_world_readable_key_file_and_a_missing_grant(home):
    wizard(["1", "", "n", "n"])
    (home / "credentials.json").chmod(0o644)
    assert any(not c.ok and "chmod 600" in c.detail for c in run_checks())
    (home / "credentials.json").chmod(0o600)
    (home / "config.toml").write_text('[model]\nname = "m"\ncredential = "ANTHROPIC_API_KEY"\n')
    assert any(not c.ok and "not granted" in c.detail for c in run_checks())


def test_doctor_treats_missing_docker_as_a_note_not_a_blocker(home, monkeypatch):
    wizard(["3", "m", "n", "n"])
    import openvici.doctor as doctor
    monkeypatch.setattr(doctor, "docker_state", lambda: (False, "Docker is not installed."))
    text, code = report(run_checks())
    assert code == 0 and "[note] Sandbox: Docker is not installed." in text


def test_doctor_reports_a_broken_config(home, capsys):
    home.mkdir()
    (home / "config.toml").write_text('[model]\nnmae = "x"\n')
    assert cli.main(["doctor"]) == 1
    assert "nmae" in capsys.readouterr().out


# --- first conversation ------------------------------------------------------

def test_chat_without_a_model_points_to_setup(home, capsys):
    assert cli.main(["chat"]) == 3
    assert "openvici setup" in capsys.readouterr().err


class Scripted:
    def __init__(self):
        self.systems = []

    def complete(self, system, messages, tools):
        self.systems.append(system)
        return ModelTurn("Hi! I can read and edit files here. What are you working on?")


def run_chat(home, monkeypatch, capsys, lines):
    wizard(["3", "m", "n", "n"])
    provider = Scripted()
    monkeypatch.setattr(cli, "make_provider", lambda *a, **k: provider)
    feed = iter(lines)

    def fake_input(prompt=""):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError
    monkeypatch.setattr("builtins.input", fake_input)
    code = cli.main(["chat"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err, provider


def test_first_session_shows_the_welcome_and_briefs_the_model_once(home, monkeypatch, capsys):
    code, out, err, provider = run_chat(home, monkeypatch, capsys, ["hello", "/exit"])
    assert code == 0 and "Welcome to OpenVici" in err and "Things to try" in err
    assert "first session" in provider.systems[0] and "What are you working on?" in out

    code, out, err, provider = run_chat(home, monkeypatch, capsys, ["hello again"])
    assert "Welcome to OpenVici" not in err and "first session" not in provider.systems[0]
    assert len(SessionStore(home / "sessions.db").list()) == 2


def test_help_and_unknown_slash_commands_do_not_reach_the_model(home, monkeypatch, capsys):
    code, out, err, provider = run_chat(home, monkeypatch, capsys, ["/help", "/frobnicate", "", "/quit"])
    assert "Commands inside the chat" in err and "openvici forget --session ID" in err
    assert "Unknown command /frobnicate. Type /help." in err and provider.systems == []


def test_first_session_note_is_part_of_the_system_prompt_only_when_set():
    assert "first session" not in ContextEngine().system_prompt([])
    assert ContextEngine(first_session_note="This is the user's first session.").system_prompt([]).count("first session") == 1
    assert ContextEngine().build([Message("user", "x")])
