"""`openvici setup`: the questions a new install needs answered, and nothing else.

It sets the model and its API key, reports whether the sandbox can run, and
offers a small set of read-only commands to run without asking. Everything
it writes goes through the same validated save as the dashboard, and the API
key goes to ``credentials.json`` (mode 600), never into the config file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Callable

from .config import home_dir
from .config_write import current_values, save_config
from .messages import Message
from .providers import ProviderError, make_provider

Ask = Callable[[str], str]
Say = Callable[[str], None]

PROVIDERS = [
    # label, provider, base_url, credential name, example model
    ("Anthropic (Claude)", "anthropic", "", "ANTHROPIC_API_KEY", "claude-sonnet-5-5"),
    ("OpenAI", "openai-compatible", "", "OPENAI_API_KEY", ""),
    ("A model on this machine (Ollama)", "openai-compatible", "http://localhost:11434/v1", "", ""),
    ("Another OpenAI-compatible server", "openai-compatible", None, "MODEL_API_KEY", ""),
]
STARTER_ALLOW = ["ls", "ls *", "pwd", "cat *", "head *", "tail *", "wc *", "grep *",
                 "git status", "git status *", "git diff", "git diff *", "git log", "git log *"]


def docker_state() -> tuple[bool, str]:
    """(usable, what to tell the user)."""
    if shutil.which("docker") is None:
        return False, ("Docker is not installed. The agent can chat and work with files, but it will refuse "
                       "to run shell commands until Docker is available: https://docs.docker.com/get-docker/")
    try:
        ok = subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    if ok:
        return True, "Docker is running. Shell commands will run in an isolated container."
    return False, ("Docker is installed but not running (or this user may not use it). Start Docker; until then "
                   "the agent will refuse to run shell commands.")


def store_secret(name: str, value: str) -> None:
    path = home_dir() / "credentials.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secrets: dict[str, str] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
            if isinstance(loaded, dict):
                secrets = loaded
        except ValueError:
            pass
    secrets[name] = value
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(secrets, fh, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _choose(ask: Ask, say: Say, question: str, options: list[str]) -> int:
    say(question)
    for index, option in enumerate(options, start=1):
        say(f"  {index}. {option}")
    while True:
        answer = ask(f"Choose 1-{len(options)}: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer) - 1
        say("Please type one of the numbers.")


def _yes(ask: Ask, question: str, default: bool = True) -> bool:
    answer = ask(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not answer else answer in ("y", "yes", "d", "da")


def run_setup(ask: Ask, ask_secret: Ask, say: Say) -> int:
    say("OpenVici setup. Three short steps; you can run this again at any time.\n")
    values = current_values()

    # 1. model
    say("Step 1 of 3: the model")
    label, provider, base_url, credential, example = PROVIDERS[
        _choose(ask, say, "Which model should the agent use?", [p[0] for p in PROVIDERS])]
    if base_url is None:
        base_url = ask("Server address (for example https://host.example/v1): ").strip()
    current = values["model"]["name"]
    suggestion = current or example
    while True:
        name = ask(f"Model name{f' [{suggestion}]' if suggestion else ''}: ").strip() or suggestion
        if name:
            break
        say("A model name is needed, exactly as your provider calls it.")
    if credential:
        key = ask_secret(f"API key for {label} (typing is hidden; Enter keeps the stored one): ").strip()
        if key:
            store_secret(credential, key)
            say(f"Key saved to {home_dir() / 'credentials.json'} (readable only by you).")
        grants = dict(values["credentials"]["grants"])
        grants["model"] = sorted(set(grants.get("model", [])) | {credential})
        values["credentials"]["grants"] = grants
    values["model"].update(provider=provider, name=name, base_url=base_url, credential=credential)

    # 2. sandbox
    say("\nStep 2 of 3: the sandbox")
    docker_ok, docker_note = docker_state()
    say(docker_note)

    # 3. approvals
    say("\nStep 3 of 3: approvals")
    say("By default the agent asks before every shell command. Commands that only read "
        "(ls, cat, grep, git status/diff/log) can be allowed to run without asking.")
    if _yes(ask, "Let those read-only commands run without asking?"):
        values["approvals"]["allow"] = sorted(set(values["approvals"]["allow"]) | set(STARTER_ALLOW))

    changed = save_config(values, source="setup")
    say(f"\nSettings saved to {home_dir() / 'config.toml'}." if changed else "\nSettings unchanged.")

    if _yes(ask, "Send a one-word test message to the model now?"):
        say(test_model(values["model"]))

    say("\nYou are set. Next:")
    say("  cd your-project-folder")
    say("  openvici chat          talk to the agent in this terminal")
    say("  openvici dashboard     the same chat, plus settings and status, in your browser")
    say("  openvici doctor        check the installation at any time")
    if not docker_ok:
        say("\nReminder: shell commands stay off until Docker is running.")
    return 0


def test_model(model: dict) -> str:
    try:
        api_key = ""
        if model["credential"]:
            path = home_dir() / "credentials.json"
            api_key = json.loads(path.read_text()).get(model["credential"], "") if path.exists() else ""
        provider = make_provider(model["provider"], model["name"], api_key, model["base_url"], max_tokens=20)
        turn = provider.complete("Reply with the single word: ready", [Message("user", "Are you there?")], [])
        return f"The model answered: {turn.text.strip()[:80] or '(empty reply)'}"
    except (ProviderError, ValueError, OSError) as exc:
        return (f"The test did not work: {exc}\nYour settings are saved; fix the model name or key and run "
                "`openvici setup` again.")
