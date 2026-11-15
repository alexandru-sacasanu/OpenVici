"""Configuration, read from one TOML file.

Unknown keys are an error. In a security config a typo that silently does
nothing (``approvals.dney``) is worse than a refusal to start.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .sandbox import SandboxPolicy
from .tools.web import WebPolicy


class ConfigError(Exception):
    pass


def home_dir() -> Path:
    return Path(os.environ.get("OPENVICI_HOME", "~/.openvici")).expanduser()


@dataclass(frozen=True)
class ModelConfig:
    provider: str = "anthropic"
    name: str = ""
    base_url: str = ""
    credential: str = ""  # name of the secret holding the API key; must be granted to "model"
    max_tokens: int = 4096


@dataclass(frozen=True)
class SmartApprovalConfig:
    """Empty provider/name/base_url/credential fall back to the [model] values."""
    enabled: bool = False
    provider: str = ""
    name: str = ""
    base_url: str = ""
    credential: str = ""
    max_chars: int = 2000


@dataclass(frozen=True)
class Config:
    home: Path
    sandbox_mode: str
    sandbox: SandboxPolicy
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    grants: dict[str, list[str]] = field(default_factory=dict)
    model: ModelConfig = field(default_factory=ModelConfig)
    web: WebPolicy = field(default_factory=WebPolicy)
    max_steps: int = 25
    context_chars: int = 400_000
    memory_limits: dict[str, int] = field(default_factory=dict)
    memory_write_approval: str = "tainted"
    smart: SmartApprovalConfig = field(default_factory=SmartApprovalConfig)
    redact_patterns: bool = True

    @property
    def memory_dir(self) -> Path:
        return self.home / "memory"

    @property
    def sessions_path(self) -> Path:
        return self.home / "sessions.db"

    @property
    def audit_path(self) -> Path:
        return self.home / "audit.jsonl"

    @property
    def credentials_path(self) -> Path:
        return self.home / "credentials.json"


_SCHEMA: dict[str, set[str]] = {
    "sandbox": {"mode", "workspace", "image", "network", "memory", "cpus", "pids_limit",
                "timeout_s", "workspace_writable"},
    "approvals": {"deny", "allow"},
    "credentials": {"grants"},
    "model": {"provider", "name", "base_url", "credential", "max_tokens"},
    "web": {"allow_domains", "deny_domains", "allowed_ports", "max_bytes", "timeout_s"},
    "agent": {"max_steps", "context_chars"},
    "memory": {"memory_chars", "user_chars", "write_approval"},
    "smart_approval": {"enabled", "provider", "name", "base_url", "credential", "max_chars"},
    "redaction": {"patterns"},
}


def load_config(path: Path | None = None) -> Config:
    home = home_dir()
    path = path or home / "config.toml"
    data: dict = {}
    if path.exists():
        try:
            data = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc

    for section, body in data.items():
        if section not in _SCHEMA:
            raise ConfigError(f"{path}: unknown section [{section}]")
        if not isinstance(body, dict):
            raise ConfigError(f"{path}: [{section}] must be a table")
        unknown = set(body) - _SCHEMA[section]
        if unknown:
            raise ConfigError(f"{path}: unknown key(s) in [{section}]: {', '.join(sorted(unknown))}")

    sb = dict(data.get("sandbox", {}))
    mode = sb.pop("mode", "docker")
    workspace = Path(sb.pop("workspace", os.getcwd()))
    try:
        policy = SandboxPolicy(workspace=workspace, **sb)
    except TypeError as exc:
        raise ConfigError(f"{path}: [sandbox] {exc}") from exc

    web = dict(data.get("web", {}))
    if "allowed_ports" in web:
        web["allowed_ports"] = tuple(web["allowed_ports"])
    for key in ("allow_domains", "deny_domains"):
        if key in web:
            _string_list(web[key], f"web.{key}")
    agent = data.get("agent", {})
    redact = data.get("redaction", {}).get("patterns", True)
    smart_raw = data.get("smart_approval", {})
    if not isinstance(redact, bool) or not isinstance(smart_raw.get("enabled", False), bool):
        raise ConfigError(f"{path}: redaction.patterns and smart_approval.enabled must be true or false")
    try:
        smart = SmartApprovalConfig(**smart_raw)
        model = ModelConfig(**data.get("model", {}))
        web_policy = WebPolicy(**web)
    except TypeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    mem = data.get("memory", {})
    write_approval = mem.get("write_approval", "tainted")
    if write_approval not in ("tainted", "always", "never"):
        raise ConfigError(f"{path}: memory.write_approval must be 'tainted', 'always' or 'never'")
    limits = {}
    for key, target in (("memory_chars", "memory"), ("user_chars", "user")):
        if key in mem:
            if not isinstance(mem[key], int) or isinstance(mem[key], bool) or mem[key] < 0:
                raise ConfigError(f"{path}: memory.{key} must be a non-negative integer")
            limits[target] = mem[key]

    approvals = data.get("approvals", {})
    grants = data.get("credentials", {}).get("grants", {})
    return Config(
        home=home,
        sandbox_mode=mode,
        sandbox=policy,
        deny=_string_list(approvals.get("deny", []), "approvals.deny"),
        allow=_string_list(approvals.get("allow", []), "approvals.allow"),
        grants={tool: _string_list(names, f"credentials.grants.{tool}") for tool, names in grants.items()},
        model=model,
        web=web_policy,
        max_steps=int(agent.get("max_steps", 25)),
        context_chars=int(agent.get("context_chars", 400_000)),
        memory_limits=limits,
        memory_write_approval=write_approval,
        smart=smart,
        redact_patterns=redact,
    )


def _string_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return value
