"""Pattern-based redaction of things that look like secrets.

Applied to every tool result before the model sees it, on top of the exact
match against stored credentials. The aim is that a ``cat .env`` or a stack
trace with a token in it does not ship that token to the model provider and
into the conversation.

This is best effort. It recognises well-known token shapes and env-style
assignments; a secret in an unusual format, or one that has been encoded or
split, passes through. It is not what keeps secrets from a hostile model;
not granting them is.
"""

from __future__ import annotations

import re
from typing import Callable

MARK = "[REDACTED:{}]"

_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]
_BEARER = re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{12,}")
_URL_PASSWORD = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@\s/]{3,}(@)")
# env-style lines only (`API_KEY=...`), so ordinary source code is left alone
_ENV_ASSIGNMENT = re.compile(
    r"^(\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*)"
    r"(?!\s*$)(?![\"']?\$)(?!\[REDACTED)(.+)$", re.M)


def redact_patterns(text: str) -> str:
    for name, pattern in _TOKEN_PATTERNS:
        text = pattern.sub(MARK.format(name), text)
    text = _BEARER.sub(lambda m: m.group(1) + MARK.format("authorization"), text)
    text = _URL_PASSWORD.sub(lambda m: m.group(1) + MARK.format("password") + m.group(2), text)
    text = _ENV_ASSIGNMENT.sub(lambda m: m.group(1) + MARK.format("env-value"), text)
    return text


def chain(*redactors: Callable[[str], str]) -> Callable[[str], str]:
    def run(text: str) -> str:
        for redactor in redactors:
            text = redactor(text)
        return text
    return run
