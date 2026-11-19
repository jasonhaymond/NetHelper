"""
HTTP(S) fetch with a timing breakdown, like a browser's network waterfall.

Rather than one opaque "page took 3 seconds", each phase is measured
separately, which points straight at the cause:
  dns_ms      name lookup          slow -> DNS server problem
  connect_ms  TCP handshake        slow -> network latency / congestion / firewall
  tls_ms      TLS handshake        slow -> TLS inspection device, overloaded server
  ttfb_ms     request -> headers   slow -> the server/application itself
  total_ms    everything incl. body download

Redirects (301/302/...) are followed up to 5 times. Only the first 256 KB of
each body is read - this is a reachability test, not a download.

The connection is built by hand (socket -> TLS -> raw HTTP/1.1 request) so
each phase can be timed; certificate verification is always ON here.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from nethelper import __version__
from nethelper.core import validate

MAX_BODY = 256 * 1024
MAX_REDIRECTS = 5


@dataclass
class HttpHop:
    """One request in a redirect chain."""

    url: str
    status: int | None = None
    reason: str = ""
    ip: str | None = None
    dns_ms: float | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    server: str | None = None
    location: str | None = None
    bytes_read: int = 0
    error: str | None = None


@dataclass
class HttpResult:
    """Final outcome plus every hop of the redirect chain."""

    url: str
    final_url: str | None = None
    status: int | None = None
    hops: list[HttpHop] = field(default_factory=list)
    error: str | None = None
    body_sample: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400


def _one_request(url: str, timeout: float) -> tuple[HttpHop, bytes]:
    """Perform a single GET (no redirect following) with per-phase timings."""
    hop = HttpHop(url=url)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        hop.error = f"DNS lookup failed: {exc}"
        return hop, b""
    t1 = time.perf_counter()
    hop.dns_ms = round((t1 - t0) * 1000, 1)
    sock = None
    last_err: OSError | None = None
    for fam, stype, proto, _, addr in infos:  # try each address (IPv4/IPv6) in turn
        try:
            sock = socket.socket(fam, stype, proto)
            sock.settimeout(timeout)
            sock.connect(addr)
            hop.ip = addr[0]
            break
        except OSError as exc:
            last_err = exc
            if sock:
                sock.close()
            sock = None
    if sock is None:
        hop.error = f"TCP connect failed: {last_err}"
        return hop, b""
    t2 = time.perf_counter()
    hop.connect_ms = round((t2 - t1) * 1000, 1)
    try:
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            hop.tls_ms = round((time.perf_counter() - t2) * 1000, 1)
        t3 = time.perf_counter()
        host_header = host if port in (80, 443) else f"{host}:{port}"
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                   f"User-Agent: NetHelper/{__version__} (network diagnostics)\r\n"
                   "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode("ascii"))
        # HTTPResponse parses the status line and headers from the socket.
        resp = http.client.HTTPResponse(sock, method="GET")
        resp.begin()
        hop.ttfb_ms = round((time.perf_counter() - t3) * 1000, 1)
        hop.status = resp.status
        hop.reason = validate.safe_text(resp.reason, 80)
        hop.server = validate.safe_text(resp.getheader("Server") or "", 80) or None
        hop.location = resp.getheader("Location")
        body = resp.read(MAX_BODY)
        hop.bytes_read = len(body)
        hop.total_ms = round((time.perf_counter() - t0) * 1000, 1)
        return hop, body
    except ssl.SSLCertVerificationError as exc:
        hop.error = f"certificate not trusted: {exc.verify_message}"
    except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
        hop.error = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return hop, b""


def fetch(url: str, timeout: float = 10.0) -> HttpResult:
    """
    GET a URL, following redirects, and return the timing breakdown.
    Never raises for network/HTTP problems; see HttpResult.error.
    """
    url = validate.url(url)
    result = HttpResult(url=url)
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        hop, body = _one_request(current, timeout)
        result.hops.append(hop)
        if hop.error:
            result.error = hop.error
            return result
        result.status = hop.status
        result.final_url = current
        if hop.status in (301, 302, 303, 307, 308) and hop.location:
            nxt = urljoin(current, hop.location)
            try:
                current = validate.url(nxt)
            except validate.ValidationError:
                result.error = f"redirect to unsupported location: {validate.safe_text(nxt, 120)}"
                return result
            continue
        result.body_sample = body[:200].decode("utf-8", errors="replace")
        return result
    result.error = "too many redirects"
    return result
