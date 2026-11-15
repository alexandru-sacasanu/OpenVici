"""Write the config back as TOML. The standard library can read TOML but not
write it; the config is flat enough (scalars, lists, one table of lists) that
a small emitter is safer than a dependency."""

from __future__ import annotations

import json
import re
from typing import Any

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(name: str) -> str:
    return name if _BARE_KEY.match(name) else json.dumps(name)


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)  # JSON string escapes are valid TOML basic-string escapes
    if isinstance(value, list):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def dump_toml(data: dict[str, dict[str, Any]]) -> str:
    out: list[str] = []
    for section, body in data.items():
        scalars = {k: v for k, v in body.items() if not isinstance(v, dict)}
        tables = {k: v for k, v in body.items() if isinstance(v, dict)}
        if scalars:
            out.append(f"[{_key(section)}]")
            out += [f"{_key(k)} = {_value(v)}" for k, v in scalars.items()]
            out.append("")
        for name, table in tables.items():
            if table:
                out.append(f"[{_key(section)}.{_key(name)}]")
                out += [f"{_key(k)} = {_value(v)}" for k, v in table.items()]
                out.append("")
    return "\n".join(out)
