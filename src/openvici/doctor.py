"""`openvici doctor`: is this installation ready, and if not, what to do."""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass

from .audit import AuditLog
from .config import ConfigError, home_dir, load_config
from .setup import docker_state


@dataclass(frozen=True)
class Check:
    ok: bool
    name: str
    detail: str
    required: bool = True


def run_checks() -> list[Check]:
    checks = [Check(sys.version_info >= (3, 11), "Python", f"{sys.version.split()[0]} (3.11 or newer is needed)")]
    try:
        config = load_config()
    except ConfigError as exc:
        return checks + [Check(False, "Settings", f"{exc}")]
    checks.append(Check(True, "Settings", str(home_dir() / "config.toml")))

    if config.model.name:
        checks.append(Check(True, "Model", f"{config.model.name} ({config.model.provider})"))
    else:
        checks.append(Check(False, "Model", "none chosen yet. Run: openvici setup"))

    if config.model.credential:
        path, name = config.credentials_path, config.model.credential
        if not path.exists():
            checks.append(Check(False, "API key", f"{path} does not exist. Run: openvici setup"))
        elif stat.S_IMODE(os.stat(path).st_mode) & 0o077:
            checks.append(Check(False, "API key", f"{path} is readable by other users. Run: chmod 600 {path}"))
        else:
            try:
                present = name in json.loads(path.read_text())
            except ValueError:
                present = False
            granted = name in config.grants.get("model", [])
            if present and granted:
                checks.append(Check(True, "API key", f"{name} is stored and granted to the model"))
            elif not present:
                checks.append(Check(False, "API key", f"{name} is not in {path}. Run: openvici setup"))
            else:
                checks.append(Check(False, "API key", f"{name} is not granted to \"model\" under "
                                                      "[credentials.grants]. Run: openvici setup"))

    if config.sandbox_mode == "docker":
        ok, note = docker_state()
        checks.append(Check(ok, "Sandbox", note, required=False))
    else:
        checks.append(Check(False, "Sandbox", "host-unsafe mode: commands run directly on this machine",
                            required=False))

    audit = AuditLog(config.audit_path).verify()
    checks.append(Check(audit.ok, "Audit log", f"{audit.entries} entries, chain intact" if audit.ok
                        else f"verification failed: {audit.error}"))

    from .dashboard.server import STATIC_DIR
    built = (STATIC_DIR / "index.html").is_file()
    checks.append(Check(built, "Dashboard", "ready" if built else
                        "interface not built. Run `npm install && npm run build` in dashboard/", required=False))
    return checks


def report(checks: list[Check]) -> tuple[str, int]:
    lines = []
    for check in checks:
        mark = "ok  " if check.ok else ("FIX " if check.required else "note")
        lines.append(f"[{mark}] {check.name}: {check.detail}")
    blocking = [c for c in checks if not c.ok and c.required]
    lines.append("")
    lines.append("Ready. Start with: openvici chat" if not blocking
                 else f"{len(blocking)} thing(s) to fix before the agent can run.")
    return "\n".join(lines), (1 if blocking else 0)
