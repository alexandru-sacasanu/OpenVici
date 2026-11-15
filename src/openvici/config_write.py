"""Saving the config, for everything that edits it (setup wizard, dashboard).

A save is validated by the same loader the agent uses before it replaces the
file, keeps the previous version as ``config.toml.bak``, and is recorded in
the audit log.
"""

from __future__ import annotations

import os
from typing import Any

from .audit import AuditLog
from .config import ConfigError, check_raw, home_dir, load_config, read_raw
from .config_schema import KEYS, SPEC
from .toml_out import dump_toml


def config_path():
    return home_dir() / "config.toml"


def current_values() -> dict[str, dict[str, Any]]:
    """Every key with its current value: the file's where set, else the default."""
    raw = read_raw(config_path())
    return {s.name: {f.key: raw.get(s.name, {}).get(f.key, f.default) for f in s.fields} for s in SPEC}


def save_config(values: Any, source: str) -> list[str]:
    """Validate and save. Keys equal to their default are left out of the
    file. Returns the ``section.key`` names whose stored value changed."""
    if not isinstance(values, dict):
        raise ConfigError("config must be an object of sections")
    check_raw(values, "config")
    slim: dict[str, dict[str, Any]] = {}
    for section, body in values.items():
        kept = {k: v for k, v in body.items() if v != KEYS[section][k].default}
        if kept:
            slim[section] = kept
    path = config_path()
    before = read_raw(path) if path.exists() else {}
    changed = sorted(
        f"{s}.{k}" for s in set(before) | set(slim)
        for k in set(before.get(s, {})) | set(slim.get(s, {}))
        if before.get(s, {}).get(k) != slim.get(s, {}).get(k))
    if not changed:
        return []
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate = path.with_suffix(".toml.new")
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(dump_toml(slim))
    try:
        load_config(candidate)  # the real loader has the last word
    except ConfigError as exc:
        candidate.unlink(missing_ok=True)
        raise ConfigError(str(exc).replace(str(candidate), "config")) from None
    AuditLog(home_dir() / "audit.jsonl").append(
        actor="human", action="config.write", target=source, decision="allow",
        detail={"changed": changed[:50]})
    if path.exists():
        os.replace(path, path.with_suffix(".toml.bak"))
    os.replace(candidate, path)
    return changed
