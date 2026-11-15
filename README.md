# OpenVici

A personal AI agent for your own machine that is isolated by default. It reads and edits files in a
project folder, runs shell commands, looks things up on the web and remembers notes between sessions.
Every command runs inside a throwaway container, and you approve what it does.

OpenVici is early software (version 0.0.1). It runs on Linux and macOS; on Windows, use WSL2.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/alexandru-sacasanu/OpenVici/main/install.sh | sh
```

The installer needs Python 3.11 or newer and git. It creates a private environment in
`~/.openvici/venv`, links the `openvici` command into `~/.local/bin`, never uses sudo, and upgrades
OpenVici when you run it again. You can [read it first](install.sh); it is short.

Prefer to do it by hand?

```sh
python3 -m venv ~/.openvici/venv
~/.openvici/venv/bin/pip install git+https://github.com/alexandru-sacasanu/OpenVici.git
ln -s ~/.openvici/venv/bin/openvici ~/.local/bin/openvici
```

You also need [Docker](https://docs.docker.com/get-docker/) for shell commands. Without it the agent
still chats and works with files, and refuses to run commands. It does not fall back to running them
on your machine.

## First run

```sh
openvici setup
```

Setup asks three things: which model to use (Anthropic, OpenAI, a local model through Ollama, or any
OpenAI-compatible server), your API key, and whether read-only commands such as `ls` and `git status`
may run without asking. The key is stored in `~/.openvici/credentials.json`, readable only by you,
and never in the settings file.

Then go to a project and start talking:

```sh
cd my-project
openvici chat
```

The first time, OpenVici explains how it works and the agent introduces itself. Some things to try:

```
explain what this project does
find where the config file is loaded and add a comment explaining it
run the tests and tell me what fails
remember that I prefer short answers
```

If something does not work, `openvici doctor` checks the installation and says what to fix.

### What you will be asked

| You see | What it means |
| --- | --- |
| `The agent wants to run: ...  Run it? [y/N]` | A shell command that no rule of yours covers. `y` runs that one command. |
| `The agent wants to: fetch https://...` | A web page on a domain you have not allowed. The full address is shown because it can carry data out. |
| `The agent wants to: save in long-term memory ...` | A note to keep, in a session that has read web content. Web pages can try to plant notes. |
| `BLOCKED (...)` | A safety rule stopped the command. This cannot be approved or overridden. |

Inside the chat, `/help` lists the commands and `/exit` leaves.

## The dashboard

```sh
openvici dashboard
```

This prints a link and opens it in your browser: the same chat in a terminal, a settings form, and a
status page (model, sandbox, disk, memory, audit log). It listens only on `127.0.0.1`, and the link
carries an access key that changes every time the dashboard starts. To use it from another machine,
tunnel to it: `ssh -L 8765:127.0.0.1:8765 your-machine`.

## Commands

| Command | What it does |
| --- | --- |
| `openvici setup` | Choose a model and get ready for the first conversation |
| `openvici doctor` | Check that the installation is ready |
| `openvici chat` | Talk to the agent in the current folder |
| `openvici dashboard` | Chat, settings and status in the browser |
| `openvici memory` | Show what the agent remembers, and from which session |
| `openvici sessions list` / `search WORDS` | Browse or search earlier conversations |
| `openvici forget --session ID` | Delete a session and the notes it wrote |
| `openvici check "COMMAND"` | Show whether a command would run, ask or be blocked, without running it |
| `openvici audit verify` | Check that the audit log has not been altered |

## Settings

Settings live in `~/.openvici/config.toml`. The dashboard's Settings tab edits the same file, and
`openvici setup` covers the essentials. A typical file:

```toml
[model]
provider = "anthropic"
name = "claude-sonnet-5-5"
credential = "ANTHROPIC_API_KEY"

[credentials.grants]
model = ["ANTHROPIC_API_KEY"]

[approvals]
allow = ["ls *", "git status", "git diff *"]   # run without asking
deny = ["git push*"]                           # never run

[web]
allow_domains = ["python.org", "github.com"]   # fetched without asking
```

Every key, with its default and what it does, is in
[`src/openvici/config_schema.py`](src/openvici/config_schema.py). A key the file does not recognise
is an error, so a typo cannot silently switch a protection off.

## How it keeps you safe

The one real boundary is the operating system: commands run in a Docker container with no network,
a read-only system, no privileges, and only your project folder visible. The rest are checks that
prevent accidents on top of that boundary.

- **Approval gate.** A short list of catastrophic commands (`rm -rf /`, formatting a disk) and your
  own `deny` rules are always blocked; no setting skips them. Your `allow` rules run without asking.
  Everything else asks you.
- **Files.** `read_file` and `write_file` stay inside the project folder and never follow symlinks.
- **Web.** Internal and private addresses are blocked based on what a host name actually resolves
  to, and the connection goes to the address that was checked.
- **Credentials.** A tool receives only the secrets granted to it by name. Things that look like
  keys and passwords are hidden from the model in tool output.
- **Memory.** Notes are plain files with a size limit, each tagged with the session that wrote it.
  `openvici forget --session ID` removes a session's messages and its notes, and checks they are gone.
- **Audit log.** Every approval, command, file write, fetch and settings change is recorded in a
  hash-chained log; `openvici audit verify` detects edits.

What this does not do: the approval gate and the redaction are pattern checks, and a model that is
trying to get around them can. If you approve a harmful command, the container is what limits the
damage. Running with `sandbox.mode = "host-unsafe"` removes that container.

## Your data

Everything is under `~/.openvici`:

| Path | Contents |
| --- | --- |
| `config.toml` | Settings |
| `credentials.json` | API keys (mode 600) |
| `memory/MEMORY.md`, `memory/USER.md` | Long-term notes; you can edit them by hand |
| `sessions.db` | What you and the agent said in earlier sessions |
| `audit.jsonl` | The audit log |

To uninstall: `rm -rf ~/.openvici/venv ~/.local/bin/openvici`. Delete `~/.openvici` as well to remove
your settings, notes and history.

## Development

```sh
git clone https://github.com/alexandru-sacasanu/OpenVici.git
cd OpenVici
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The dashboard interface is TypeScript in `dashboard/`. Its build output is committed under
`src/openvici/dashboard/static/`, so Node is only needed to change it:

```sh
cd dashboard && npm install && npm run build
```
