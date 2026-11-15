"""SSRF guard and a fetcher that cannot be redirected past it.

The check is made on the addresses a hostname actually resolves to, never on
the text of the URL, so ``http://2130706433/``, ``http://0x7f.1/`` and a
public domain whose DNS points at ``127.0.0.1`` are all seen for what they
are. The connection is then opened to the exact address that was checked.
Resolving a second time at connect time would let a DNS server answer
"public" to the check and "internal" to the request (DNS rebinding).

Every redirect is a new URL and goes through the same check. Redirects to a
different host are not followed at all; the caller is told where the page
points and has to ask again, which puts the new host through approval.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_MAX_REDIRECTS = 5
_TEXT_TYPES = ("text/", "application/json", "application/xml", "application/xhtml+xml",
               "application/javascript", "application/x-ndjson")


class BlockedURL(Exception):
    pass


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    ip: str

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}{'' if self.port == default else f':{self.port}'}{self.path}"


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    content_type: str
    text: str
    truncated: bool = False
    redirect_to: str | None = None  # set when the page points at another host


Resolver = Callable[[str, int], list[str]]
Opener = Callable[[Target, float, int], tuple[int, dict[str, str], bytes, bool]]


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        elif ip in _SIX_TO_FOUR:
            ip = ipaddress.ip_address((int(ip) >> 80) & 0xFFFFFFFF)
    return ip.is_global and not ip.is_multicast


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise BlockedURL(f"cannot resolve {host}: {exc}") from None
    return list(dict.fromkeys(info[4][0] for info in infos))


def check_url(url: str, allowed_ports: tuple[int, ...] = (80, 443),
              resolver: Resolver = system_resolver) -> Target:
    """Validate ``url`` and resolve it. Raises BlockedURL unless every address
    the host resolves to is a public one."""
    if len(url) > 4096 or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise BlockedURL("URL is too long or contains whitespace/control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise BlockedURL(f"malformed URL: {exc}") from None
    if parts.scheme not in ("http", "https"):
        raise BlockedURL(f"only http and https are allowed, not '{parts.scheme}'")
    if parts.username is not None or parts.password is not None:
        raise BlockedURL("URLs with embedded credentials are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise BlockedURL("URL has no host")
    port = port or (443 if parts.scheme == "https" else 80)
    if port not in allowed_ports:
        raise BlockedURL(f"port {port} is not allowed (allowed: {', '.join(map(str, allowed_ports))})")

    addresses = resolver(host, port)
    if not addresses:
        raise BlockedURL(f"{host} did not resolve to any address")
    for address in addresses:
        if not is_public_address(address):
            raise BlockedURL(f"{host} resolves to {address}, which is not a public address")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return Target(parts.scheme, host, port, path, addresses[0])


def fetch(url: str, *, allowed_ports: tuple[int, ...] = (80, 443), timeout: float = 20,
          max_bytes: int = 1_000_000, resolver: Resolver = system_resolver,
          opener: Opener | None = None) -> FetchResult:
    opener = opener or open_pinned
    target = check_url(url, allowed_ports, resolver)
    for _ in range(_MAX_REDIRECTS + 1):
        try:
            status, headers, body, truncated = opener(target, timeout, max_bytes)
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"request to {target.host} failed: {exc}") from None
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            nxt = check_url(urljoin(target.url, location), allowed_ports, resolver)
            if nxt.host != target.host:
                return FetchResult(target.url, status, "", "", redirect_to=nxt.url)
            target = nxt
            continue
        ctype = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if body and not ctype.startswith(_TEXT_TYPES):
            raise FetchError(f"{target.url} is '{ctype or 'unknown type'}', not text")
        text = body.decode(_charset(headers.get("content-type", "")), errors="replace")
        if "html" in ctype:
            text = html_to_text(text)
        return FetchResult(target.url, status, ctype, text, truncated)
    raise FetchError("too many redirects")


def open_pinned(target: Target, timeout: float, max_bytes: int) -> tuple[int, dict[str, str], bytes, bool]:
    """One GET to ``target.ip``, with TLS verified against ``target.host``."""
    if target.scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPS(target, timeout)
    else:
        conn = _PinnedHTTP(target, timeout)
    try:
        conn.request("GET", target.path, headers={
            "User-Agent": "openvici/0.0.1", "Accept": "text/html, text/*, application/json",
            "Accept-Encoding": "identity"})
        response = conn.getresponse()
        body = response.read(max_bytes + 1)
        headers = {k.lower(): v for k, v in response.getheaders()}
        return response.status, headers, body[:max_bytes], len(body) > max_bytes
    finally:
        conn.close()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, target: Target, timeout: float):
        super().__init__(target.host, target.port, timeout=timeout)
        self._pinned_ip = target.ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, target: Target, timeout: float):
        self._tls = ssl.create_default_context()
        super().__init__(target.host, target.port, timeout=timeout, context=self._tls)
        self._pinned_ip = target.ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)


def _charset(content_type: str) -> str:
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            try:
                "".encode(value.strip("\"'"))
                return value.strip("\"'")
            except LookupError:
                break
    return "utf-8"


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "template", "svg"}
    _BREAK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skipping = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skipping += 1
        elif tag in self._BREAK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skipping:
            self._skipping -= 1

    def handle_data(self, data):
        if not self._skipping:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line)
