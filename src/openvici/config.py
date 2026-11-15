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


class ConfigError(Exception):
    pass


def home_dir() -> Path:
    return Path(os.environ.get("OPENVICI_HOME", "~/.openvici")).expanduser()


@dataclass(frozen=True)
class Config:
    home: Path
    sandbox_mode: str
    sandbox: SandboxPolicy
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    grants: dict[str, list[str]] = field(default_factory=dict)

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

    approvals = data.get("approvals", {})
    grants = data.get("credentials", {}).get("grants", {})
    return Config(
        home=home,
        sandbox_mode=mode,
        sandbox=policy,
        deny=_string_list(approvals.get("deny", []), "approvals.deny"),
        allow=_string_list(approvals.get("allow", []), "approvals.allow"),
        grants={tool: _string_list(names, f"credentials.grants.{tool}") for tool, names in grants.items()},
    )


def _string_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return value
