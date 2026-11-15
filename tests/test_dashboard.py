"""The dashboard server: binding, authentication, config writes, terminals."""

import base64
import http.client
import json
import sys
import threading
import time
import tomllib

import pytest

from openvici.audit import AuditLog
from openvici.config import ConfigError, load_config
from openvici.config_schema import SPEC, type_problem
from openvici.dashboard import DashboardError, DashboardServer
from openvici.dashboard.status import GIB, build_alerts, read_meminfo
from openvici.toml_out import dump_toml

TOKEN = "test-token-123"
ECHO = [sys.executable, "-u", "-c", "print('ready'); x = input(); print('got:' + x)"]


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path / "home"))
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.chdir(ws)
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>OpenVici</title>")
    (static / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path / "secret.txt").write_text("outside static")
    srv = DashboardServer(port=0, token=TOKEN, chat_argv=ECHO, static_dir=static)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()


def request(server, method, path, body=None, *, token=TOKEN, host=None, origin=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{server.port}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if origin:
        headers["Origin"] = origin
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response, payload


def get_json(server, path, **kw):
    response, payload = request(server, "GET", path, **kw)
    return response.status, json.loads(payload)


# --- binding -----------------------------------------------------------------

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com", ""])
def test_refuses_to_listen_beyond_loopback(host):
    with pytest.raises(DashboardError, match="only binds to this machine"):
        DashboardServer(host=host, port=0)


def test_link_carries_the_token_in_the_fragment(server):
    assert server.url == f"http://127.0.0.1:{server.port}/#token={TOKEN}"
    assert len(DashboardServer(port=0).token) >= 40


# --- authentication ----------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/config", "/api/schema", "/api/status"])
def test_api_needs_the_token(server, path):
    assert request(server, "GET", path, token=None)[0].status == 401
    assert request(server, "GET", path, token="wrong")[0].status == 401
    assert request(server, "GET", path, token=TOKEN + "x")[0].status == 401
    assert request(server, "GET", path)[0].status == 200


def test_token_in_the_query_string_is_not_accepted(server):
    assert request(server, "GET", f"/api/config?token={TOKEN}", token=None)[0].status == 401


def test_writes_and_terminals_need_the_token_too(server):
    assert request(server, "PUT", "/api/config", {}, token=None)[0].status == 401
    assert request(server, "POST", "/api/terminals", {}, token=None)[0].status == 401
    assert server.terminals == {}


@pytest.mark.parametrize("host", ["evil.example", "evil.example:80", "127.0.0.1", "127.0.0.1:1", "localhost.evil.example"])
def test_dns_rebinding_host_header_is_refused_even_with_the_token(server, host):
    assert request(server, "GET", "/api/config", host=host)[0].status == 403
    assert request(server, "GET", "/", host=host)[0].status == 403


def test_localhost_names_for_this_server_are_accepted(server):
    assert request(server, "GET", "/api/config", host=f"localhost:{server.port}")[0].status == 200


def test_cross_origin_requests_are_refused(server):
    assert request(server, "GET", "/api/config", origin="https://evil.example")[0].status == 403
    assert request(server, "PUT", "/api/config", {}, origin="null")[0].status == 403
    assert request(server, "GET", "/api/config", origin=f"http://127.0.0.1:{server.port}")[0].status == 200


def test_no_cors_headers_are_ever_sent(server):
    response, _ = request(server, "GET", "/api/config", origin=f"http://127.0.0.1:{server.port}")
    assert response.getheader("Access-Control-Allow-Origin") is None


def test_security_headers(server):
    response, _ = request(server, "GET", "/", token=None)
    assert response.getheader("X-Frame-Options") == "DENY"
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in response.getheader("Content-Security-Policy")
    assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
    assert "openvici" in response.getheader("Server") and "Python" not in response.getheader("Server")


# --- static files ------------------------------------------------------------

def test_static_files_are_served_without_a_token_and_cannot_escape(server):
    response, body = request(server, "GET", "/", token=None)
    assert response.status == 200 and b"OpenVici" in body
    assert request(server, "GET", "/assets/app.js", token=None)[0].status == 200
    for path in ["/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt", "//etc/passwd", "/nope"]:
        response, body = request(server, "GET", path, token=None)
        assert response.status == 404 and b"outside static" not in body
    assert request(server, "POST", "/", token=None)[0].status == 405


def test_missing_build_is_explained(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENVICI_HOME", str(tmp_path))
    srv = DashboardServer(port=0, token=TOKEN, static_dir=tmp_path / "nothing")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        response, body = request(srv, "GET", "/", token=None)
        assert response.status == 503 and b"npm run build" in body
    finally:
        srv.shutdown()


# --- schema and config -------------------------------------------------------

def test_schema_defaults_match_what_the_loader_does_with_an_empty_file(server):
    """The form's defaults and the loader's defaults come from different code;
    this is the check that they agree."""
    config = load_config()
    values = get_json(server, "/api/config")[1]
    assert values["sandbox"]["mode"] == config.sandbox_mode == "docker"
    assert values["sandbox"]["network"] == config.sandbox.network
    assert values["sandbox"]["image"] == config.sandbox.image
    assert values["sandbox"]["memory"] == config.sandbox.memory and values["sandbox"]["cpus"] == config.sandbox.cpus
    assert values["sandbox"]["pids_limit"] == config.sandbox.pids_limit
    assert values["sandbox"]["timeout_s"] == config.sandbox.timeout_s
    assert values["sandbox"]["workspace_writable"] == config.sandbox.workspace_writable
    assert values["model"] == {"provider": config.model.provider, "name": config.model.name,
                               "base_url": config.model.base_url, "credential": config.model.credential,
                               "max_tokens": config.model.max_tokens}
    assert tuple(values["web"]["allowed_ports"]) == config.web.allowed_ports
    assert values["web"]["max_bytes"] == config.web.max_bytes and values["web"]["timeout_s"] == config.web.timeout_s
    assert values["agent"] == {"max_steps": config.max_steps, "context_chars": config.context_chars}
    assert values["memory"]["write_approval"] == config.memory_write_approval
    assert values["smart_approval"]["enabled"] == config.smart.enabled
    assert values["smart_approval"]["max_chars"] == config.smart.max_chars
    assert values["redaction"]["patterns"] == config.redact_patterns
    assert values["dashboard"]["port"] == config.dashboard_port
    from openvici.memory import DEFAULT_LIMITS
    assert values["memory"]["memory_chars"] == DEFAULT_LIMITS["memory"]
    assert values["memory"]["user_chars"] == DEFAULT_LIMITS["user"]


def test_every_schema_default_passes_its_own_type_check():
    for section in SPEC:
        for field in section.fields:
            assert type_problem(field.default, field) is None, f"{section.name}.{field.key}"
            assert field.help


def test_schema_endpoint_describes_every_field(server):
    status, schema = get_json(server, "/api/schema")
    assert status == 200 and [s["name"] for s in schema] == [s.name for s in SPEC]
    mode = next(f for s in schema if s["name"] == "sandbox" for f in s["fields"] if f["key"] == "mode")
    assert mode["choices"] == ["docker", "host-unsafe"] and "OPENVICI_ALLOW_HOST_EXEC" in mode["caution"]


def test_saving_unchanged_defaults_writes_nothing(server, tmp_path):
    values = get_json(server, "/api/config")[1]
    response, payload = request(server, "PUT", "/api/config", values)
    assert response.status == 200 and json.loads(payload) == {"changed": []}
    assert not (tmp_path / "home" / "config.toml").exists()


def test_save_round_trip_keeps_only_non_defaults_and_is_audited(server, tmp_path):
    values = get_json(server, "/api/config")[1]
    values["approvals"]["allow"] = ["ls*", 'git "status"']
    values["approvals"]["deny"] = ["git push*"]
    values["model"]["name"] = "some-model"
    values["web"]["allowed_ports"] = [443]
    values["credentials"]["grants"] = {"model": ["API_KEY"], "web search": ["SEARCH_KEY"]}
    response, payload = request(server, "PUT", "/api/config", values)
    assert response.status == 200
    assert json.loads(payload)["changed"] == ["approvals.allow", "approvals.deny", "credentials.grants",
                                              "model.name", "web.allowed_ports"]
    path = tmp_path / "home" / "config.toml"
    stored = tomllib.loads(path.read_text())
    assert stored == {"approvals": {"allow": ["ls*", 'git "status"'], "deny": ["git push*"]},
                      "model": {"name": "some-model"}, "web": {"allowed_ports": [443]},
                      "credentials": {"grants": {"model": ["API_KEY"], "web search": ["SEARCH_KEY"]}}}
    assert (path.stat().st_mode & 0o777) == 0o600
    config = load_config()
    assert config.allow == ["ls*", 'git "status"'] and config.grants["web search"] == ["SEARCH_KEY"]
    assert get_json(server, "/api/config")[1] == values
    audit = AuditLog(tmp_path / "home" / "audit.jsonl")
    last = json.loads(audit.path.read_text().splitlines()[-1])
    assert last["action"] == "config.write" and "approvals.allow" in last["detail"]["changed"]
    assert audit.verify().ok

    values["model"]["name"] = "other-model"
    request(server, "PUT", "/api/config", values)
    assert "some-model" in path.with_suffix(".toml.bak").read_text()        # previous version kept


@pytest.mark.parametrize("patch", [
    {"sandbox": {"mode": "yolo"}},
    {"sandbox": {"network": "host"}},
    {"sandbox": {"pids_limit": -1}},
    {"sandbox": {"pids_limit": "many"}},
    {"approvals": {"allow": "ls*"}},
    {"approvals": {"dney": []}},
    {"nonsense": {"x": 1}},
    {"memory": {"write_approval": "sometimes"}},
    {"web": {"allowed_ports": [0]}},
    {"web": {"allowed_ports": [70000]}},
    {"redaction": {"patterns": "no"}},
    {"credentials": {"grants": {"model": "KEY"}}},
    {"model": []},
])
def test_invalid_config_is_rejected_and_nothing_is_written(server, tmp_path, patch):
    response, payload = request(server, "PUT", "/api/config", patch)
    assert response.status == 400 and json.loads(payload)["error"]
    home = tmp_path / "home"
    assert not (home / "config.toml").exists() and not (home / "config.toml.new").exists()


def test_bad_bodies(server):
    assert request(server, "PUT", "/api/config", raw=b"{not json")[0].status == 400
    assert request(server, "PUT", "/api/config", raw=b"[1,2]")[0].status == 400
    # announce an oversized body without sending it: the server must refuse on the header alone
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    conn.putrequest("PUT", "/api/config")
    conn.putheader("Authorization", f"Bearer {TOKEN}")
    conn.putheader("Content-Length", str((1 << 20) + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()


def test_toml_writer_round_trips_awkward_strings():
    data = {"approvals": {"allow": ['a "quoted" \\ back', "tab\there", "ünï", "new\nline"], "deny": []},
            "sandbox": {"workspace_writable": False, "pids_limit": 7, "image": "x:1"},
            "credentials": {"grants": {"my tool": ["A", "B"], "plain": []}}}
    assert tomllib.loads(dump_toml(data)) == data


# --- status ------------------------------------------------------------------

def test_status_endpoint(server):
    status, body = get_json(server, "/api/status")
    assert status == 200 and body["sandbox"]["mode"] == "docker" and body["audit"]["ok"] is True
    assert set(body["notes"]) == {"MEMORY.md", "USER.md"} and isinstance(body["alerts"], list)


def test_alerts_are_ordered_by_what_to_fix_first():
    disks = [{"path": "/data", "free": 50 * GIB, "total": 1000 * GIB}]          # 5% free: warning
    full = [{"path": "/data", "free": GIB // 2, "total": 1000 * GIB}]
    low_mem, no_mem = (16 * GIB, GIB), (16 * GIB, GIB // 4)
    alerts = build_alerts(low_mem, disks, docker_found=False, sandbox_mode="docker", audit_ok=True, audit_error=None)
    assert [(a["level"], a["kind"]) for a in alerts] == [("warning", "sandbox"), ("warning", "disk"), ("warning", "memory")]
    alerts = build_alerts(no_mem, full, True, "docker", False, "line 3: broken link")
    assert [(a["level"], a["kind"]) for a in alerts] == [("critical", "disk"), ("critical", "memory"), ("critical", "audit")]
    assert "nothing runs" in alerts[0]["message"]
    healthy = [{"path": "/", "free": 500 * GIB, "total": 1000 * GIB}]
    assert build_alerts((16 * GIB, 8 * GIB), healthy, True, "docker", True, None) == []
    assert build_alerts(None, healthy, False, "host-unsafe", True, None) == []      # no docker needed there
    assert len(build_alerts(None, full + full, True, "docker", True, None)) == 1    # same disk reported once


def test_meminfo_parsing(tmp_path):
    path = tmp_path / "meminfo"
    path.write_text("MemTotal:       16000000 kB\nMemFree:  100 kB\nMemAvailable:    4000000 kB\n")
    assert read_meminfo(str(path)) == (16000000 * 1024, 4000000 * 1024)
    assert read_meminfo(str(tmp_path / "missing")) is None


# --- terminals ---------------------------------------------------------------

def read_stream(server, key, offset=0, until=b"", timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=timeout)
    conn.request("GET", f"/api/terminals/{key}/stream?offset={offset}",
                 headers={"Authorization": f"Bearer {TOKEN}", "Host": f"127.0.0.1:{server.port}"})
    response = conn.getresponse()
    assert response.status == 200
    data, exit_code, last = b"", None, offset
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = response.readline()
        if not line:
            break
        event = json.loads(line)
        if "d" in event:
            data += base64.b64decode(event["d"])
            last = event["o"]
        if "exit" in event:
            exit_code = event["exit"]
            break
        if until and until in data:
            break
    conn.close()
    return data, exit_code, last


def test_terminal_runs_the_fixed_command_and_carries_input_and_output(server):
    response, payload = request(server, "POST", "/api/terminals", {"cols": 90, "rows": 25, "command": "sh -c id"})
    assert response.status == 201
    key = json.loads(payload)["id"]
    data, _, offset = read_stream(server, key, until=b"ready")
    assert b"ready" in data
    assert request(server, "POST", f"/api/terminals/{key}/resize", {"cols": 120, "rows": 40})[0].status == 200
    assert request(server, "POST", f"/api/terminals/{key}/input", raw="salut ț\n".encode())[0].status == 200
    data, exit_code, _ = read_stream(server, key, offset)
    assert "got:salut ț".encode() in data and exit_code == 0
    assert b"uid=" not in data                               # the "command" in the request was ignored
    replay, _, _ = read_stream(server, key, 0)               # a reconnect gets the history again
    assert b"ready" in replay and b"got:" in replay


def test_terminal_ids_are_unguessable_and_scoped(server):
    key = json.loads(request(server, "POST", "/api/terminals", {})[1])["id"]
    assert len(key) == 16
    assert request(server, "POST", "/api/terminals/nope/input", raw=b"x")[0].status == 404
    assert request(server, "GET", f"/api/terminals/{key}/stream", token=None)[0].status == 401
    assert request(server, "POST", f"/api/terminals/{key}/input", raw=b"x" * 70_000)[0].status == 409
    assert request(server, "DELETE", f"/api/terminals/{key}")[0].status == 200
    assert request(server, "POST", f"/api/terminals/{key}/input", raw=b"x")[0].status == 404


def test_terminal_limit_and_cleanup_on_shutdown(server):
    keys = [json.loads(request(server, "POST", "/api/terminals", {})[1])["id"] for _ in range(4)]
    response, payload = request(server, "POST", "/api/terminals", {})
    assert response.status == 409 and "too many" in json.loads(payload)["error"]
    processes = [server.terminals[k].process for k in keys]
    assert all(p.poll() is None for p in processes)
    server.shutdown()
    assert all(p.poll() is not None for p in processes)
    server.httpd = type("Closed", (), {"shutdown": lambda s: None, "server_close": lambda s: None})()


def test_terminal_environment_is_an_allowlist(server, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    server.chat_argv = [sys.executable, "-u", "-c", "import os; print(sorted(os.environ)); print('TERM=' + os.environ['TERM'])"]
    key = json.loads(request(server, "POST", "/api/terminals", {})[1])["id"]
    data, exit_code, _ = read_stream(server, key)
    assert exit_code == 0 and b"AWS_SECRET_ACCESS_KEY" not in data and b"TERM=xterm-256color" in data


def test_cli_refuses_a_port_in_use(server, capsys):
    from openvici.cli import main
    assert main(["dashboard", "--port", str(server.port), "--no-open"]) == 3
    assert "cannot listen" in capsys.readouterr().err
