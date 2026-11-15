"""The dashboard's HTTP server.

It can start a terminal running the agent and rewrite the security config,
so it is treated as the most sensitive listener in the project:

* It binds to a loopback address and nothing else. There is no option for
  0.0.0.0; to reach it from another machine, tunnel to it (ssh -L, Tailscale).
* Loopback is not authentication. Any web page open in the user's browser
  can send requests to 127.0.0.1, so every API call needs a random token
  created at startup. The token is handed to the page in the URL fragment,
  which browsers never send to a server or put in a Referer, and travels in
  an Authorization header, never in a cookie, so another site cannot make
  the browser attach it.
* The Host header must name this server. That stops DNS rebinding, where a
  hostile domain is re-pointed at 127.0.0.1 to make the browser treat this
  server as its own origin.
* Config writes are validated by the same loader the agent uses before they
  replace the file, and each one is recorded in the audit log.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import mimetypes
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..audit import AuditLog
from ..config import ConfigError, check_raw, home_dir, load_config, read_raw
from ..config_schema import KEYS, SPEC, spec_as_json
from ..sandbox import HOST_EXEC_ENV, SandboxError
from .pty_session import PtySession
from .status import collect_status
from .toml_out import dump_toml

STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY = 1 << 20
MAX_TERMINALS = 4
_PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "OPENVICI_HOME", "PYTHONPATH", "DOCKER_HOST", "DOCKER_CONTEXT",
             "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy",
             "http_proxy", "no_proxy", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", HOST_EXEC_ENV)
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}


class DashboardError(Exception):
    pass


def _loopback(host: str) -> str:
    if host == "localhost":
        return "127.0.0.1"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise DashboardError(
        f"refusing to listen on '{host}': the dashboard only binds to this machine (127.0.0.1). "
        "To use it from elsewhere, tunnel to it, for example: ssh -L 8765:127.0.0.1:8765 this-machine")


class DashboardServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765, *, token: str | None = None,
                 chat_argv: list[str] | None = None, static_dir: Path = STATIC_DIR):
        self.host = _loopback(host)
        self.token = token or secrets.token_urlsafe(32)
        self.chat_argv = chat_argv or [sys.executable, "-m", "openvici", "chat"]
        self.static_dir = static_dir
        self.terminals: dict[str, PtySession] = {}
        self.lock = threading.Lock()
        try:
            self.httpd = ThreadingHTTPServer((self.host, port), _handler_for(self))
        except OSError as exc:
            raise DashboardError(f"cannot listen on {self.host}:{port}: {exc.strerror or exc}") from None
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/#token={self.token}"

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.1)

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        with self.lock:
            terminals, self.terminals = list(self.terminals.values()), {}
        for terminal in terminals:
            terminal.close()

    # -- terminals -------------------------------------------------------------

    def open_terminal(self, cols: int, rows: int) -> str:
        with self.lock:
            for key in [k for k, t in self.terminals.items() if not t.alive]:
                self.terminals.pop(key).close()
            if len(self.terminals) >= MAX_TERMINALS:
                raise DashboardError("too many open terminals; close one first")
        env = {k: os.environ[k] for k in _PASS_ENV if k in os.environ}
        env["TERM"] = "xterm-256color"
        try:
            cwd = str(load_config().sandbox.validated().workspace)
        except (ConfigError, SandboxError):
            cwd = os.getcwd()
        terminal = PtySession(self.chat_argv, env, cwd, cols, rows)
        key = secrets.token_hex(8)
        with self.lock:
            self.terminals[key] = terminal
        return key

    # -- config ----------------------------------------------------------------

    @staticmethod
    def config_path() -> Path:
        return home_dir() / "config.toml"

    def read_config(self) -> dict[str, Any]:
        """Every key with its current value: the file's where set, else the default."""
        raw = read_raw(self.config_path())
        return {s.name: {f.key: raw.get(s.name, {}).get(f.key, f.default) for f in s.fields} for s in SPEC}

    def write_config(self, values: dict[str, Any]) -> list[str]:
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
        path = self.config_path()
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
            actor="human", action="config.write", target="dashboard", decision="allow",
            detail={"changed": changed[:50]})
        if path.exists():
            os.replace(path, path.with_suffix(".toml.bak"))
        os.replace(candidate, path)
        return changed


def _handler_for(server: DashboardServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "openvici"
        sys_version = ""

        def log_message(self, *args: Any) -> None:
            pass

        # -- plumbing ----------------------------------------------------------

        def _send(self, status: int, body: bytes, content_type: str, cache: str = "no-store") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            for name, value in _SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json")

        def _error(self, status: int, message: str) -> None:
            self._json(status, {"error": message})

        def _body(self) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._error(413, "request body too large")
                return None
            return self.rfile.read(length)

        def _json_body(self) -> Any:
            raw = self._body()
            if raw is None:
                return None
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                self._error(400, "body is not valid JSON")
                return None

        def _host_ok(self) -> bool:
            if self.headers.get("Host", "") in server.allowed_hosts:
                return True
            self._error(403, "unexpected Host header")
            return False

        def _authorized(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is not None and origin not in {f"http://{h}" for h in server.allowed_hosts}:
                self._error(403, "cross-origin request refused")
                return False
            scheme, _, supplied = self.headers.get("Authorization", "").partition(" ")
            if scheme != "Bearer" or not hmac.compare_digest(supplied.encode(), server.token.encode()):
                self._error(401, "missing or wrong token; open the link printed by `openvici dashboard`")
                return False
            return True

        # -- routing -----------------------------------------------------------

        def do_GET(self) -> None:
            self._route("GET")

        def do_HEAD(self) -> None:
            self._route("GET")

        def do_POST(self) -> None:
            self._route("POST")

        def do_PUT(self) -> None:
            self._route("PUT")

        def do_DELETE(self) -> None:
            self._route("DELETE")

        def _route(self, method: str) -> None:
            if not self._host_ok():
                return
            parts = urlsplit(self.path)
            path = parts.path
            if not path.startswith("/api/"):
                if method != "GET":
                    return self._error(405, "method not allowed")
                return self._static(path)
            if not self._authorized():
                return
            try:
                self._api(method, path, parse_qs(parts.query))
            except ConfigError as exc:
                self._error(400, str(exc))
            except DashboardError as exc:
                self._error(409, str(exc))
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
            if (method, path) == ("GET", "/api/schema"):
                return self._json(200, spec_as_json())
            if (method, path) == ("GET", "/api/config"):
                return self._json(200, server.read_config())
            if (method, path) == ("PUT", "/api/config"):
                values = self._json_body()
                if values is None:
                    return
                return self._json(200, {"changed": server.write_config(values)})
            if (method, path) == ("GET", "/api/status"):
                return self._json(200, collect_status(load_config()))
            if (method, path) == ("POST", "/api/terminals"):
                size = self._json_body()
                if size is None:
                    return
                cols, rows = _int(size, "cols", 100), _int(size, "rows", 30)
                return self._json(201, {"id": server.open_terminal(cols, rows)})

            if path.startswith("/api/terminals/"):
                key, _, action = path[len("/api/terminals/"):].partition("/")
                with server.lock:
                    terminal = server.terminals.get(key)
                if terminal is None:
                    return self._error(404, "no such terminal")
                if (method, action) == ("GET", "stream"):
                    return self._stream(terminal, _int({"o": (query.get("offset") or ["0"])[0]}, "o", 0))
                if (method, action) == ("POST", "input"):
                    data = self._body()
                    if data is None:
                        return
                    try:
                        terminal.write(data)
                    except (OSError, ValueError):
                        return self._error(409, "terminal is closed")
                    return self._json(200, {})
                if (method, action) == ("POST", "resize"):
                    size = self._json_body()
                    if size is None:
                        return
                    try:
                        terminal.resize(_int(size, "cols", 100), _int(size, "rows", 30))
                    except OSError:
                        return self._error(409, "terminal is closed")
                    return self._json(200, {})
                if (method, action) == ("DELETE", ""):
                    with server.lock:
                        server.terminals.pop(key, None)
                    terminal.close()
                    return self._json(200, {})
            self._error(404, "not found")

        def _stream(self, terminal: PtySession, offset: int) -> None:
            """Newline-delimited JSON: {"d": base64 bytes, "o": next offset},
            {"k": 1} keep-alives, and a final {"exit": code}."""
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Cache-Control", "no-store")
            for name, value in _SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            while True:
                data, offset, finished = terminal.read_from(offset, timeout=10)
                if data:
                    event: dict[str, Any] = {"d": base64.b64encode(data).decode(), "o": offset}
                elif finished:
                    event = {"exit": terminal.process.wait()}
                else:
                    event = {"k": 1}
                self.wfile.write(json.dumps(event).encode() + b"\n")
                self.wfile.flush()
                if "exit" in event:
                    return

        def _static(self, path: str) -> None:
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            root = server.static_dir.resolve()
            target = (root / name).resolve()
            if not target.is_relative_to(root) or not target.is_file():
                if not (root / "index.html").is_file():
                    return self._send(503, b"The dashboard interface has not been built. "
                                           b"Run `npm install && npm run build` in the dashboard/ folder.",
                                      "text/plain; charset=utf-8")
                return self._send(404, b"not found", "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            cache = "public, max-age=31536000, immutable" if name.startswith("assets/") else "no-store"
            self._send(200, target.read_bytes(), ctype, cache)

    return Handler


def _int(source: Any, key: str, default: int) -> int:
    try:
        value = int(source.get(key, default)) if isinstance(source, dict) else default
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default
