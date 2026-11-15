#!/bin/sh
# OpenVici installer.
#
#   curl -fsSL https://raw.githubusercontent.com/alexandru-sacasanu/OpenVici/main/install.sh | sh
#
# What it does, and nothing more:
#   1. finds Python 3.11 or newer
#   2. creates a private virtual environment in ~/.openvici/venv
#   3. installs OpenVici into it from GitHub
#   4. links the `openvici` command into ~/.local/bin
#
# It never uses sudo and touches nothing outside those two folders. Running it
# again upgrades to the latest version. To remove OpenVici:
#   rm -rf ~/.openvici/venv ~/.local/bin/openvici     (your settings and notes stay in ~/.openvici)
#
# Overrides: OPENVICI_PREFIX (default ~/.openvici), OPENVICI_BIN (default ~/.local/bin),
#            OPENVICI_SOURCE (default: the GitHub repository; a local path also works).

set -eu

main() {
    prefix="${OPENVICI_PREFIX:-$HOME/.openvici}"
    bindir="${OPENVICI_BIN:-$HOME/.local/bin}"
    source="${OPENVICI_SOURCE:-git+https://github.com/alexandru-sacasanu/OpenVici.git}"

    case "$(uname -s)" in
        Linux|Darwin) ;;
        *) fail "OpenVici runs on Linux and macOS. On Windows, use WSL2 and run this inside it." ;;
    esac

    python=""
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            python="$candidate"
            break
        fi
    done
    [ -n "$python" ] || fail "Python 3.11 or newer is needed and was not found. Install it from https://www.python.org/downloads/ or your package manager, then run this again."

    case "$source" in
        git+*) command -v git >/dev/null 2>&1 || fail "git is needed to download OpenVici. Install git, then run this again." ;;
    esac

    say "Installing OpenVici with $($python --version 2>&1) into $prefix/venv"
    mkdir -p "$prefix"
    chmod 700 "$prefix"
    if ! "$python" -m venv "$prefix/venv" 2>/dev/null; then
        fail "Could not create a virtual environment. On Debian or Ubuntu, run: sudo apt install python3-venv"
    fi
    "$prefix/venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "$source" ||
        fail "The download or installation failed. Check your internet connection and run this again."

    mkdir -p "$bindir"
    ln -sf "$prefix/venv/bin/openvici" "$bindir/openvici"
    say "Installed: $("$prefix/venv/bin/openvici" --version)"

    case ":$PATH:" in
        *":$bindir:"*) command="openvici" ;;
        *)
            command="$bindir/openvici"
            say ""
            say "Note: $bindir is not on your PATH. Add this line to your shell profile (~/.bashrc or ~/.zshrc):"
            say "  export PATH=\"$bindir:\$PATH\""
            ;;
    esac

    if ! command -v docker >/dev/null 2>&1; then
        say ""
        say "Note: Docker was not found. OpenVici runs shell commands only inside a Docker container,"
        say "so that part stays off until Docker is installed: https://docs.docker.com/get-docker/"
    fi

    say ""
    say "Next step:"
    say "  $command setup"
}

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# The whole script is read before anything runs, so a download that is cut
# off halfway cannot execute half an installation.
main "$@"
