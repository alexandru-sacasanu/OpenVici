"""Credentials, sandbox, config and the executor that ties them together."""

import json
import os
import shutil
import subprocess

import pytest

from openvici.approval import ApprovalPolicy, Decision
from openvici.audit import AuditLog
from openvici.config import ConfigError, load_config
from openvici.credentials import CredentialBroker, CredentialError
from openvici.executor import Executor
from openvici.sandbox import (HOST_EXEC_ENV, HOST_EXEC_PHRASE, DockerSandbox, ExecResult,
                              SandboxError, SandboxPolicy, SandboxUnavailable,
                              UnsafeHostExecutor, make_sandbox)

SECRET = "sk-search-123456"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"SEARCH_KEY": SECRET, "SMTP_PASSWORD": "hunter2-smtp"}))
    path.chmod(0o600)
    return path


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


# --- credentials -----------------------------------------------------------

def test_tool_gets_only_what_it_was_granted(store, tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    broker = CredentialBroker(store, {"web_search": ["SEARCH_KEY"]}, audit)
    assert broker.env_for("web_search") == {"SEARCH_KEY": SECRET}
    assert broker.env_for("shell") == {}
    assert SECRET not in audit.path.read_text()
    assert "SEARCH_KEY" in audit.path.read_text()


def test_world_readable_store_is_refused(store):
    store.chmod(0o644)
    with pytest.raises(CredentialError, match="chmod 600"):
        CredentialBroker(store, {"t": ["SEARCH_KEY"]}).env_for("t")


def test_grant_for_missing_secret_fails_loudly(store):
    with pytest.raises(CredentialError):
        CredentialBroker(store, {"t": ["NOPE"]}).env_for("t")


def test_redact(store):
    broker = CredentialBroker(store, {})
    assert broker.redact(f"key={SECRET}!") == "key=[REDACTED:SEARCH_KEY]!"


# --- sandbox ---------------------------------------------------------------

def test_docker_argv_is_locked_down(workspace):
    argv = DockerSandbox(SandboxPolicy(workspace)).build_argv("echo hi", ["SEARCH_KEY"], "n1")
    joined = " ".join(argv)
    for flag in ["--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--pids-limit 256", f"--user {os.getuid()}:{os.getgid()}", "--rm"]:
        assert flag in joined
    assert "--privileged" not in joined
    assert argv[-3:] == ["/bin/sh", "-c", "echo hi"]
    assert f"type=bind,src={workspace.resolve()},dst=/workspace" in argv
    assert argv[argv.index("SEARCH_KEY") - 1] == "--env"      # name only, never NAME=value
    assert not any(a.startswith("SEARCH_KEY=") for a in argv)


@pytest.mark.parametrize("network", ["host", "container:abc", "--privileged", ""])
def test_dangerous_networks_refused(workspace, network):
    with pytest.raises(SandboxError):
        DockerSandbox(SandboxPolicy(workspace, network=network))


def test_root_and_home_cannot_be_the_workspace(tmp_path):
    for bad in ["/", os.path.expanduser("~"), str(tmp_path / "missing")]:
        with pytest.raises(SandboxError):
            SandboxPolicy(workspace=__import__("pathlib").Path(bad)).validated()


def test_bad_env_name_refused(workspace):
    with pytest.raises(SandboxError):
        DockerSandbox(SandboxPolicy(workspace)).build_argv("true", ["X; rm"], "n")


def test_missing_docker_fails_closed(workspace):
    sandbox = DockerSandbox(SandboxPolicy(workspace), docker_bin="docker-that-does-not-exist")
    with pytest.raises(SandboxUnavailable):
        sandbox.run("echo hi", {})


def test_host_mode_needs_both_switches(workspace):
    policy = SandboxPolicy(workspace)
    with pytest.raises(SandboxError):
        make_sandbox("host-unsafe", policy, environ={})
    with pytest.raises(SandboxError):
        make_sandbox("host-unsafe", policy, environ={HOST_EXEC_ENV: "yes"})
    assert isinstance(make_sandbox("docker", policy, environ={HOST_EXEC_ENV: HOST_EXEC_PHRASE}), DockerSandbox)
    assert isinstance(make_sandbox("host-unsafe", policy, environ={HOST_EXEC_ENV: HOST_EXEC_PHRASE}),
                      UnsafeHostExecutor)


def test_host_executor_env_is_built_from_scratch(workspace, monkeypatch):
    monkeypatch.setenv("PARENT_ONLY_SECRET", "leak-me")
    result = UnsafeHostExecutor(SandboxPolicy(workspace)).run("env", {"GRANTED": "yes"})
    assert "GRANTED=yes" in result.stdout
    assert "PARENT_ONLY_SECRET" not in result.stdout


def _docker_works() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_works(), reason="docker daemon not available")
def test_real_container_is_isolated(workspace):
    sandbox = DockerSandbox(SandboxPolicy(workspace, image="alpine:3.20"))
    result = sandbox.run("id -u; touch /x 2>&1; echo ok > /workspace/out; echo $GRANTED", {"GRANTED": "v"})
    assert str(os.getuid()) in result.stdout and "v" in result.stdout
    assert "Read-only" in result.stdout
    assert (workspace / "out").read_text().strip() == "ok"


# --- config ----------------------------------------------------------------

def test_config_defaults_are_the_safe_ones(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    config = load_config()
    assert config.sandbox_mode == "docker" and config.sandbox.network == "none"
    assert config.allow == [] and config.grants == {}


def test_config_typo_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('[approvals]\ndney = ["rm*"]\n')
    with pytest.raises(ConfigError, match="dney"):
        load_config()


# --- executor --------------------------------------------------------------

class FakeSandbox:
    isolated = True

    def __init__(self, output=""):
        self.calls, self.output = [], output

    def run(self, command, env):
        self.calls.append((command, dict(env)))
        return ExecResult(0, self.output, "")


def _executor(tmp_path, store, sandbox, approver=None, **policy):
    audit = AuditLog(tmp_path / "audit.jsonl")
    broker = CredentialBroker(store, {"web_search": ["SEARCH_KEY"]}, audit)
    kwargs = {"approver": approver} if approver else {}
    return Executor(ApprovalPolicy(**policy), sandbox, broker, audit, **kwargs), audit


def test_denied_command_never_reaches_the_sandbox(tmp_path, store):
    sandbox = FakeSandbox()
    executor, audit = _executor(tmp_path, store, sandbox, approver=lambda c, v: True)
    outcome = executor.run_shell("shell", "rm -rf /")
    assert not outcome.ran and sandbox.calls == []
    assert outcome.verdict.decision is Decision.DENY
    assert audit.verify().ok


def test_ask_without_a_human_is_a_no(tmp_path, store):
    sandbox = FakeSandbox()
    executor, _ = _executor(tmp_path, store, sandbox)
    assert not executor.run_shell("shell", "python x.py").ran
    assert sandbox.calls == []


def test_approved_run_gets_scoped_env_and_redacted_output(tmp_path, store):
    sandbox = FakeSandbox(output=f"token is {SECRET}")
    executor, audit = _executor(tmp_path, store, sandbox, approver=lambda c, v: True)
    outcome = executor.run_shell("web_search", "python search.py")
    assert outcome.ran
    assert sandbox.calls == [("python search.py", {"SEARCH_KEY": SECRET})]
    assert SECRET not in outcome.result.stdout and "[REDACTED:SEARCH_KEY]" in outcome.result.stdout
    actions = [json.loads(line)["action"] for line in audit.path.read_text().splitlines()]
    assert actions == ["approval.verdict", "approval.answer", "credential.grant", "exec.start", "exec.end"]
    assert SECRET not in audit.path.read_text()
    assert audit.verify().ok


def test_allow_rule_skips_the_prompt_and_other_tools_get_no_secrets(tmp_path, store):
    sandbox = FakeSandbox()
    asked = []
    executor, _ = _executor(tmp_path, store, sandbox, approver=lambda c, v: asked.append(c) or False,
                            allow=["ls*"])
    assert executor.run_shell("shell", "ls -la").ran
    assert asked == [] and sandbox.calls == [("ls -la", {})]
