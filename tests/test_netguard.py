import pytest

from openvici.audit import AuditLog
from openvici.messages import ToolCall
from openvici.netguard import BlockedURL, Target, check_url, fetch, html_to_text, is_public_address
from openvici.tools import ToolRegistry, WebPolicy, web_fetch_tool

PUBLIC = "93.184.216.34"


def resolver_for(table):
    def resolve(host, port):
        return table.get(host, [PUBLIC])
    return resolve


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.5", "172.16.3.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "fd12::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "::", "not-an-ip",
    "fe80::1%eth0",
])
def test_non_public_addresses(address):
    assert not is_public_address(address)


@pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_addresses(address):
    assert is_public_address(address)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com/",
    "http://user:pw@example.com/",
    "http://example.com:22/",
    "http://example.com:6379/",
    "http:///nohost",
    "http://example.com/a b",
    "http://example.com/\r\nHost: evil",
    "http://[::1/",
])
def test_bad_urls_blocked_before_resolving(url):
    with pytest.raises(BlockedURL):
        check_url(url, resolver=resolver_for({}))


@pytest.mark.parametrize("host,answers", [
    ("metadata.internal", ["169.254.169.254"]),
    ("rebind.example", ["127.0.0.1"]),
    ("mixed.example", [PUBLIC, "10.0.0.1"]),       # one bad record is enough
    ("v6.example", ["::ffff:192.168.0.1"]),
    ("empty.example", []),
])
def test_host_is_judged_by_what_it_resolves_to(host, answers):
    with pytest.raises(BlockedURL):
        check_url(f"https://{host}/", resolver=resolver_for({host: answers}))


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://localhost/",
    "http://[::1]/", "http://169.254.169.254/latest/meta-data/", "http://0/",
])
def test_literal_and_encoded_internal_addresses_blocked_with_real_resolver(url):
    with pytest.raises(BlockedURL):
        check_url(url)


def test_check_url_returns_pinned_target():
    target = check_url("HTTPS://Example.COM./a?b=1", resolver=resolver_for({}))
    assert target == Target("https", "example.com", 443, "/a?b=1", PUBLIC)


def make_opener(responses, seen):
    def opener(target, timeout, max_bytes):
        seen.append(target)
        return responses[target.url]
    return opener


def test_fetch_connects_to_the_address_that_was_checked():
    seen = []
    opener = make_opener({"https://example.com/": (200, {"content-type": "text/html; charset=utf-8"},
                                                    b"<p>Hello</p><script>x()</script>", False)}, seen)
    result = fetch("https://example.com/", resolver=resolver_for({}), opener=opener)
    assert result.text == "Hello" and seen[0].ip == PUBLIC


def test_same_host_redirect_is_rechecked_and_followed():
    seen = []
    opener = make_opener({
        "http://example.com/": (301, {"location": "https://example.com/new"}, b"", False),
        "https://example.com/new": (200, {"content-type": "text/plain"}, b"ok", False)}, seen)
    assert fetch("http://example.com/", resolver=resolver_for({}), opener=opener).text == "ok"
    assert [t.url for t in seen] == ["http://example.com/", "https://example.com/new"]


def test_redirect_to_internal_address_is_blocked():
    opener = make_opener({"https://example.com/": (302, {"location": "http://169.254.169.254/"}, b"", False)}, [])
    with pytest.raises(BlockedURL):
        fetch("https://example.com/", opener=opener,
              resolver=resolver_for({"169.254.169.254": ["169.254.169.254"]}))


def test_redirect_whose_dns_turns_internal_is_blocked():
    answers = {"example.com": [PUBLIC]}
    seen = []

    def opener(target, timeout, max_bytes):
        seen.append(target)
        answers["example.com"] = ["10.0.0.7"]          # DNS changes after the first check
        return 302, {"location": "/again"}, b"", False

    with pytest.raises(BlockedURL):
        fetch("https://example.com/", resolver=lambda h, p: answers[h], opener=opener)
    assert len(seen) == 1


def test_cross_host_redirect_is_reported_not_followed():
    seen = []
    opener = make_opener({"https://example.com/": (302, {"location": "https://other.example/x"}, b"", False)}, seen)
    result = fetch("https://example.com/", resolver=resolver_for({}), opener=opener)
    assert result.redirect_to == "https://other.example/x" and len(seen) == 1


def test_binary_content_refused():
    from openvici.netguard import FetchError
    opener = make_opener({"https://example.com/": (200, {"content-type": "application/zip"}, b"PK", False)}, [])
    with pytest.raises(FetchError):
        fetch("https://example.com/", resolver=resolver_for({}), opener=opener)


def test_html_to_text_drops_scripts_and_styles():
    assert html_to_text("<style>a{}</style><h1>T</h1><p>a &amp; b</p><script>evil()</script>") == "T\na & b"


# --- the tool: approval and audit around the guard ----------------------------

def _tool(tmp_path, policy, confirm, opener=None):
    audit = AuditLog(tmp_path / "audit.jsonl")
    opener = opener or make_opener({"https://docs.python.org/3/": (200, {"content-type": "text/plain"}, b"docs", False),
                                    "https://evil.example/?q=secret": (200, {"content-type": "text/plain"}, b"x", False)}, [])
    registry = ToolRegistry([web_fetch_tool(policy, audit, confirm, resolver=resolver_for(
        {"intranet.corp": ["10.1.2.3"]}), opener=opener)])
    return registry, audit


def call(registry, url):
    return registry.dispatch(ToolCall("1", "web_fetch", {"url": url}))


def test_allowed_domain_needs_no_prompt_and_output_is_marked_untrusted(tmp_path):
    asked = []
    registry, _ = _tool(tmp_path, WebPolicy(allow_domains=["python.org"]), lambda a, r: asked.append(a) or False)
    text, is_error = call(registry, "https://docs.python.org/3/")
    assert not is_error and asked == []
    assert "untrusted content" in text and text.endswith("docs")


def test_unknown_domain_shows_the_full_url_to_the_user(tmp_path):
    asked = []
    registry, audit = _tool(tmp_path, WebPolicy(allow_domains=["python.org"]), lambda a, r: asked.append(a) or False)
    text, is_error = call(registry, "https://evil.example/?q=secret")
    assert is_error and "not approved" in text
    assert asked == ["fetch https://evil.example/?q=secret"]
    assert audit.verify().ok


def test_no_human_means_no_fetch_by_default(tmp_path):
    from openvici.tools import refuse
    registry, _ = _tool(tmp_path, WebPolicy(), refuse)
    assert call(registry, "https://docs.python.org/3/")[1] is True


def test_internal_target_is_blocked_without_asking(tmp_path):
    asked = []
    registry, audit = _tool(tmp_path, WebPolicy(), lambda a, r: asked.append(a) or True)
    text, is_error = call(registry, "http://intranet.corp/")
    assert is_error and "not a public address" in text and asked == []
    assert '"decision":"deny"' in audit.path.read_text()


def test_deny_list_beats_allow_list(tmp_path):
    registry, _ = _tool(tmp_path, WebPolicy(allow_domains=["python.org"], deny_domains=["docs.python.org"]),
                        lambda a, r: True)
    assert "deny list" in call(registry, "https://docs.python.org/3/")[0]


def test_allow_list_does_not_match_lookalike_suffix(tmp_path):
    asked = []
    registry, _ = _tool(tmp_path, WebPolicy(allow_domains=["python.org"]), lambda a, r: asked.append(a) or False,
                        opener=make_opener({}, []))
    call(registry, "https://evilpython.org/")
    assert asked == ["fetch https://evilpython.org/"]


def test_open_pinned_connects_to_the_pinned_ip_not_the_hostname():
    """The host name does not resolve at all; the request still arrives,
    because the socket goes to the address that was checked."""
    import http.server
    import threading
    from openvici.netguard import open_pinned

    hosts = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hosts.append(self.headers["Host"])
            body = b"x" * 50
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        target = Target("http", "does-not-resolve.invalid", port, "/p?q=1", "127.0.0.1")
        status, headers, body, truncated = open_pinned(target, 5, 20)
    finally:
        server.shutdown()
    assert status == 200 and body == b"x" * 20 and truncated
    assert hosts == [f"does-not-resolve.invalid:{port}"]
