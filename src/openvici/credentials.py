"""Per-tool credentials, granted by name.

The model is positive: a tool receives the secrets listed for it under
``[credentials.grants]`` and nothing else. A tool with no entry receives
nothing. Child environments are built from an empty dict, never copied from
this process and then scrubbed, so a secret that nobody listed cannot leak by
being forgotten.

Limit worth knowing: this scopes what reaches *child processes*. Code loaded
into the agent's own Python process can read whatever the process can read.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .audit import AuditLog

_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MIN_REDACT_LEN = 6


class CredentialError(Exception):
    pass


class CredentialBroker:
    def __init__(self, store_path: str | os.PathLike[str], grants: dict[str, list[str]],
                 audit: AuditLog | None = None):
        self.store_path = Path(store_path)
        self.grants = {tool: list(names) for tool, names in grants.items()}
        self.audit = audit
        for tool, names in self.grants.items():
            for name in names:
                if not _NAME.match(name):
                    raise CredentialError(f"grant for '{tool}': '{name}' is not a valid credential name")

    def env_for(self, tool: str) -> dict[str, str]:
        """The secrets this tool was granted, and only those."""
        names = self.grants.get(tool, [])
        if not names:
            return {}
        store = self._load()
        missing = [n for n in names if n not in store]
        if missing:
            raise CredentialError(f"tool '{tool}' is granted {missing} but the store has no such entry")
        if self.audit:
            self.audit.append(actor=f"tool:{tool}", action="credential.grant",
                              target=",".join(names), decision="allow")
        return {n: store[n] for n in names}

    def redact(self, text: str) -> str:
        """Replace any stored secret value that appears in ``text``. A
        convenience for logs and model-visible output, not a guarantee: a
        secret that was encoded or split will pass."""
        try:
            store = self._load()
        except CredentialError:
            return text
        for name, value in sorted(store.items(), key=lambda kv: -len(kv[1])):
            if len(value) >= _MIN_REDACT_LEN:
                text = text.replace(value, f"[REDACTED:{name}]")
        return text

    def _load(self) -> dict[str, str]:
        if not self.store_path.exists():
            return {}
        info = self.store_path.stat()
        if info.st_uid != os.getuid():
            raise CredentialError(f"{self.store_path} is owned by another user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise CredentialError(f"{self.store_path} is readable by other users; run: chmod 600 {self.store_path}")
        try:
            data = json.loads(self.store_path.read_text())
        except ValueError as exc:
            raise CredentialError(f"{self.store_path} is not valid JSON") from exc
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise CredentialError(f"{self.store_path} must be a flat JSON object of strings")
        return data
