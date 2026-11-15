"""Machine and agent health for the dashboard banner.

Alerts come back already ordered by what the user should deal with first:
a full disk before low memory (a full disk also breaks the audit log, and
then nothing runs), critical before warning.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Config
from ..memory import TARGETS, MemoryStore

GIB = 1 << 30
_ORDER = {("critical", "disk"): 0, ("critical", "memory"): 1, ("critical", "audit"): 2,
          ("warning", "sandbox"): 3, ("warning", "disk"): 4, ("warning", "memory"): 5}


def read_meminfo(path: str = "/proc/meminfo") -> tuple[int, int] | None:
    """(total, available) in bytes, or None where /proc/meminfo does not exist."""
    try:
        fields = {}
        for line in Path(path).read_text().splitlines():
            name, _, rest = line.partition(":")
            fields[name] = int(rest.split()[0]) * 1024
        return fields["MemTotal"], fields["MemAvailable"]
    except (OSError, KeyError, ValueError, IndexError):
        return None


def build_alerts(memory: tuple[int, int] | None, disks: list[dict[str, Any]],
                 docker_found: bool, sandbox_mode: str, audit_ok: bool, audit_error: str | None) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for disk in disks:
        free, total = disk["free"], disk["total"]
        share = free / total if total else 0
        if free < GIB or share < 0.02:
            alerts.append({"level": "critical", "kind": "disk",
                           "message": f"Disk almost full at {disk['path']}: {free / GIB:.1f} GB free. "
                                      "The audit log cannot be written on a full disk, and then nothing runs."})
        elif share < 0.10:
            alerts.append({"level": "warning", "kind": "disk",
                           "message": f"Disk space is low at {disk['path']}: {free / GIB:.1f} GB free."})
    if memory:
        total, available = memory
        share = available / total if total else 0
        if share < 0.05:
            alerts.append({"level": "critical", "kind": "memory",
                           "message": f"Memory almost exhausted: {available / GIB:.1f} GB available."})
        elif share < 0.15:
            alerts.append({"level": "warning", "kind": "memory",
                           "message": f"Memory is low: {available / GIB:.1f} GB available."})
    if not audit_ok:
        alerts.append({"level": "critical", "kind": "audit",
                       "message": f"The audit log failed verification: {audit_error}."})
    if sandbox_mode == "docker" and not docker_found:
        alerts.append({"level": "warning", "kind": "sandbox",
                       "message": "Docker was not found. Shell commands will be refused until it is installed."})
    seen: set[str] = set()
    unique = [a for a in alerts if not (a["message"] in seen or seen.add(a["message"]))]
    return sorted(unique, key=lambda a: _ORDER.get((a["level"], a["kind"]), 9))


def collect_status(config: Config) -> dict[str, Any]:
    disks: list[dict[str, Any]] = []
    devices: dict[int, dict[str, Any]] = {}
    for label, path in (("data", config.home), ("workspace", config.sandbox.workspace)):
        try:
            real = path if Path(path).exists() else Path(path).parent
            usage, device = shutil.disk_usage(real), os.stat(real).st_dev
        except OSError:
            continue
        if device in devices:  # same filesystem: one row, not two identical ones
            devices[device]["label"] += f" and {label}"
            continue
        devices[device] = {"label": label, "path": str(path), "free": usage.free, "total": usage.total}
        disks.append(devices[device])
    memory = read_meminfo()
    audit = AuditLog(config.audit_path).verify()
    docker_found = shutil.which("docker") is not None
    store = MemoryStore(config.memory_dir, config.memory_limits)
    notes = {}
    for target, filename in TARGETS.items():
        used, limit = store.usage(target)
        notes[filename] = {"used": used, "limit": limit}
    return {
        "alerts": build_alerts(memory, disks, docker_found, config.sandbox_mode, audit.ok, audit.error),
        "memory": {"total": memory[0], "available": memory[1]} if memory else None,
        "disks": disks,
        "sandbox": {"mode": config.sandbox_mode, "docker_found": docker_found,
                    "workspace": str(config.sandbox.workspace), "network": config.sandbox.network},
        "audit": {"ok": audit.ok, "entries": audit.entries, "error": audit.error},
        "notes": notes,
        "model": {"provider": config.model.provider, "name": config.model.name},
    }
