"""The one description of every configuration key.

Three things are derived from it, so they cannot drift apart: which keys the
loader accepts, the type check on each value, and the dashboard's config
form. Adding a setting means adding one Field here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

TYPES = ("string", "integer", "boolean", "string_list", "integer_list", "choice", "grants")


@dataclass(frozen=True)
class Field:
    key: str
    type: str
    default: Any
    help: str
    choices: tuple[str, ...] = ()
    caution: str = ""  # shown next to the control when changing it weakens a protection


@dataclass(frozen=True)
class Section:
    name: str
    title: str
    help: str
    fields: tuple[Field, ...] = field(default=())


SPEC: tuple[Section, ...] = (
    Section("model", "Model", "Which model the agent talks to.", (
        Field("provider", "choice", "anthropic", "API format the model server speaks.",
              ("anthropic", "openai-compatible")),
        Field("name", "string", "", "Model name, as the provider calls it."),
        Field("base_url", "string", "", "Leave empty for the provider's own address. "
              "Plain http is accepted only for localhost."),
        Field("credential", "string", "", "Name of the secret that holds the API key. "
              "It must also be granted to \"model\" under Credentials."),
        Field("max_tokens", "integer", 4096, "Longest reply the model may give, in tokens."),
    )),
    Section("sandbox", "Sandbox", "Where shell commands run.", (
        Field("mode", "choice", "docker", "docker runs every command in a throwaway container.",
              ("docker", "host-unsafe"),
              caution="host-unsafe runs commands directly on this machine. It only takes effect if "
                      "OPENVICI_ALLOW_HOST_EXEC is also set in the environment."),
        Field("workspace", "string", "", "Project folder the agent may see. Empty means the folder "
              "you start OpenVici from."),
        Field("image", "string", "python:3.12-slim", "Container image commands run in."),
        Field("network", "string", "none", "Docker network for the container.",
              caution="Anything other than none gives commands network access."),
        Field("memory", "string", "1g", "Memory limit for the container."),
        Field("cpus", "string", "2", "CPU limit for the container."),
        Field("pids_limit", "integer", 256, "Most processes a command may start."),
        Field("timeout_s", "integer", 120, "Seconds before a command is stopped."),
        Field("workspace_writable", "boolean", True, "Whether commands may change files in the project folder."),
    )),
    Section("approvals", "Approvals", "Which commands run without asking, and which never run.", (
        Field("deny", "string_list", [], "Patterns that are always blocked, for example: git push*"),
        Field("allow", "string_list", [], "Patterns that run without asking, for example: ls*",
              caution="A broad pattern such as * removes the approval prompt for everything it matches."),
    )),
    Section("smart_approval", "Smart approval", "A second model that can approve routine commands for you.", (
        Field("enabled", "boolean", False, "Let a reviewer model approve routine commands.",
              caution="Fewer prompts, at the price of trusting a model's judgement on commands."),
        Field("provider", "choice", "", "Empty uses the main model's provider.",
              ("", "anthropic", "openai-compatible")),
        Field("name", "string", "", "Reviewer model. Empty uses the main model."),
        Field("base_url", "string", "", "Empty uses the main model's address."),
        Field("credential", "string", "", "Empty uses the main model's credential."),
        Field("max_chars", "integer", 2000, "Longer commands always go to you."),
    )),
    Section("web", "Web access", "What web_fetch may reach.", (
        Field("allow_domains", "string_list", [], "Domains fetched without asking."),
        Field("deny_domains", "string_list", [], "Domains never fetched."),
        Field("allowed_ports", "integer_list", [80, 443], "Ports web_fetch may connect to."),
        Field("max_bytes", "integer", 1_000_000, "Largest page read, in bytes."),
        Field("timeout_s", "integer", 20, "Seconds before a fetch gives up."),
    )),
    Section("memory", "Memory", "Long-term notes kept between sessions.", (
        Field("memory_chars", "integer", 2200, "Size limit of MEMORY.md, in characters."),
        Field("user_chars", "integer", 1375, "Size limit of USER.md, in characters."),
        Field("write_approval", "choice", "tainted", "When saving a note needs your approval: "
              "tainted = after the session has read web content.", ("tainted", "always", "never"),
              caution="never lets a web page plant notes that reach every future session."),
    )),
    Section("redaction", "Redaction", "Hiding secrets from the model.", (
        Field("patterns", "boolean", True, "Hide things that look like keys, tokens and passwords "
              "in tool results.", caution="Off means a cat of .env goes to the model provider as is."),
    )),
    Section("agent", "Agent", "Limits on a single turn.", (
        Field("max_steps", "integer", 25, "Most tool rounds per message."),
        Field("context_chars", "integer", 400_000, "Conversation budget, in characters."),
    )),
    Section("credentials", "Credentials", "Which tool may use which secret. The secrets themselves "
            "live in credentials.json and are never shown here.", (
        Field("grants", "grants", {}, "One line per tool: the names of the secrets it may use."),
    )),
    Section("dashboard", "Dashboard", "This page.", (
        Field("port", "integer", 8765, "Port on 127.0.0.1. Takes effect the next time the dashboard starts."),
    )),
)

KEYS: dict[str, dict[str, Field]] = {s.name: {f.key: f for f in s.fields} for s in SPEC}


def spec_as_json() -> list[dict[str, Any]]:
    return [asdict(section) for section in SPEC]


def type_problem(value: Any, spec: Field) -> str | None:
    """Why ``value`` is not acceptable for ``spec``, or None."""
    kind = spec.type
    is_int = isinstance(value, int) and not isinstance(value, bool)
    if kind == "string" and not isinstance(value, str):
        return "must be text"
    if kind == "integer" and not (is_int and value >= 0):
        return "must be a non-negative whole number"
    if kind == "boolean" and not isinstance(value, bool):
        return "must be true or false"
    if kind == "choice" and value not in spec.choices:
        return "must be one of: " + ", ".join(repr(c) for c in spec.choices)
    if kind == "string_list" and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
        return "must be a list of text values"
    if kind == "integer_list" and not (isinstance(value, list) and all(
            isinstance(v, int) and not isinstance(v, bool) and 0 < v < 65536 for v in value)):
        return "must be a list of port numbers"
    if kind == "grants" and not (isinstance(value, dict) and all(
            isinstance(k, str) and isinstance(v, list) and all(isinstance(n, str) for n in v)
            for k, v in value.items())):
        return "must map each tool to a list of secret names"
    return None
