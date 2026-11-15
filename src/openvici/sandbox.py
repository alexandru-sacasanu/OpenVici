"""Where commands actually run. This is the security boundary.

Default: every command runs in a throwaway Docker container with no network,
a read-only root, no capabilities, as the calling user, seeing one mounted
workspace directory and nothing else of the host.

If Docker is missing or the daemon is down, execution fails. It does not fall
back to the host.

Running on the host is possible, and takes two deliberate steps: the config
must say ``mode = "host-unsafe"`` AND the environment must carry
``OPENVICI_ALLOW_HOST_EXEC=i-accept-no-isolation``. One alone is refused, so
neither a stray config edit nor a stray env var removes the boundary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

HOST_EXEC_ENV = "OPENVICI_ALLOW_HOST_EXEC"
HOST_EXEC_PHRASE = "i-accept-no-isolation"

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_FORBIDDEN_NETWORKS = {"host"}
_DOCKER_CLIENT_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")
_BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_MAX_OUTPUT = 200_000


class SandboxError(Exception):
    pass


class SandboxUnavailable(SandboxError):
    pass


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class SandboxPolicy:
    workspace: Path
    image: str = "python:3.12-slim"
    network: str = "none"
    memory: str = "1g"
    cpus: str = "2"
    pids_limit: int = 256
    timeout_s: int = 120
    workspace_writable: bool = True

    def validated(self) -> "SandboxPolicy":
        ws = self.workspace.expanduser().resolve()
        if not ws.is_dir():
            raise SandboxError(f"workspace {ws} is not a directory")
        if ws == Path("/") or ws == Path.home().resolve():
            raise SandboxError(f"refusing to expose {ws} as the workspace; pick a project folder")
        if "," in str(ws):
            raise SandboxError("workspace path may not contain a comma")
        check_network(self.network)
        if not self.image or self.image.startswith("-"):
            raise SandboxError("invalid image name")
        return SandboxPolicy(ws, self.image, self.network, self.memory, self.cpus,
                             self.pids_limit, self.timeout_s, self.workspace_writable)


def check_network(network: str) -> None:
    if network in _FORBIDDEN_NETWORKS or network.startswith("container:") or not _NETWORK_NAME.match(network):
        raise SandboxError(f"network '{network}' is not allowed; use 'none' or a named Docker network")


class Sandbox(Protocol):
    isolated: bool

    def run(self, command: str, env: Mapping[str, str]) -> ExecResult: ...


class DockerSandbox:
    isolated = True

    def __init__(self, policy: SandboxPolicy, docker_bin: str = "docker"):
        self.policy = policy.validated()
        self.docker_bin = docker_bin

    def build_argv(self, command: str, env_names: list[str], name: str) -> list[str]:
        p = self.policy
        for env_name in env_names:
            if not _ENV_NAME.match(env_name):
                raise SandboxError(f"invalid environment variable name: {env_name!r}")
        mount = f"type=bind,src={p.workspace},dst=/workspace" + ("" if p.workspace_writable else ",readonly")
        argv = [
            self.docker_bin, "run", "--rm", "--init", "--name", name,
            "--network", p.network,
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(p.pids_limit), "--memory", p.memory, "--cpus", p.cpus,
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--workdir", "/workspace", "--mount", mount,
            "--env", "HOME=/tmp", "--env", f"PATH={_BASE_PATH}",
        ]
        for env_name in env_names:
            # name only: the value travels in the docker client's environment,
            # so it never shows up in `ps` or shell history
            argv += ["--env", env_name]
        return argv + [p.image, "/bin/sh", "-c", command]

    def run(self, command: str, env: Mapping[str, str]) -> ExecResult:
        if shutil.which(self.docker_bin) is None:
            raise SandboxUnavailable("docker is not installed; refusing to run without isolation")
        name = f"openvici-{uuid.uuid4().hex[:12]}"
        argv = self.build_argv(command, list(env), name)
        client_env = {k: os.environ[k] for k in _DOCKER_CLIENT_ENV if k in os.environ}
        client_env.update(env)
        try:
            proc = subprocess.run(argv, env=client_env, capture_output=True, text=True,
                                  errors="replace", timeout=self.policy.timeout_s,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as exc:
            subprocess.run([self.docker_bin, "kill", name], capture_output=True, env=client_env)
            return ExecResult(124, _text(exc.stdout), _text(exc.stderr), timed_out=True)
        if proc.returncode == 125:
            raise SandboxUnavailable(f"docker could not start the container: {proc.stderr.strip()[:500]}")
        return ExecResult(proc.returncode, proc.stdout[:_MAX_OUTPUT], proc.stderr[:_MAX_OUTPUT])


class UnsafeHostExecutor:
    """No isolation. Exists so the trade-off is a visible, named choice."""

    isolated = False

    def __init__(self, policy: SandboxPolicy):
        self.policy = policy.validated()

    def run(self, command: str, env: Mapping[str, str]) -> ExecResult:
        child_env = {"PATH": _BASE_PATH, "HOME": str(self.policy.workspace), **env}
        try:
            proc = subprocess.run(["/bin/sh", "-c", command], env=child_env, cwd=self.policy.workspace,
                                  capture_output=True, text=True, errors="replace",
                                  timeout=self.policy.timeout_s, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(124, _text(exc.stdout), _text(exc.stderr), timed_out=True)
        return ExecResult(proc.returncode, proc.stdout[:_MAX_OUTPUT], proc.stderr[:_MAX_OUTPUT])


def make_sandbox(mode: str, policy: SandboxPolicy, environ: Mapping[str, str] | None = None) -> Sandbox:
    environ = os.environ if environ is None else environ
    if mode == "docker":
        return DockerSandbox(policy)
    if mode == "host-unsafe":
        if environ.get(HOST_EXEC_ENV) != HOST_EXEC_PHRASE:
            raise SandboxError(
                f"config asks for host-unsafe mode, but {HOST_EXEC_ENV}={HOST_EXEC_PHRASE} is not set. "
                "Both are required to run without isolation.")
        return UnsafeHostExecutor(policy)
    raise SandboxError(f"unknown sandbox mode '{mode}' (expected 'docker' or 'host-unsafe')")


def _text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return (value.decode(errors="replace") if isinstance(value, bytes) else value)[:_MAX_OUTPUT]
