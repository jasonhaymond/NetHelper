"""
TCP reachability tests and service banner grabbing.

A TCP "connect test" opens a connection to host:port and immediately closes
it - the same thing `Test-NetConnection -Port` or `telnet host port` does. It
distinguishes three situations that matter for firewall troubleshooting:
  open      - something accepted the connection
  refused   - the host answered "nothing listening here" (host is up, port closed)
  timeout   - no answer at all (filtered by a firewall, or host down)

Banner grabbing reads the greeting some services send on connect (SMTP
"220 mail.example.com ESMTP", IMAP "* OK", SSH "SSH-2.0-...") - proof that the
right service, not just *something*, is listening. Banners are untrusted
network data and are sanitised before display.
"""

from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from nethelper.core import validate

# Well-known ports for service kinds used by profiles.
SERVICE_PORTS = {
    "smtp": 25, "submission": 587, "smtps": 465, "imap": 143, "imaps": 993, "pop3": 110,
    "ldap": 389, "ldaps": 636, "kerberos": 88,
}
# Kinds that are wrapped in TLS from the first byte.
TLS_KINDS = {"smtps", "imaps", "ldaps"}
# Kinds that send a text greeting as soon as you connect.
BANNER_KINDS = {"smtp", "submission", "smtps", "imap", "imaps", "pop3"}


@dataclass
class PortResult:
    """Outcome of one TCP connect test."""

    host: str
    port: int
    state: str              # open / refused / timeout / error
    ip: str | None = None
    connect_ms: float | None = None
    banner: str | None = None
    error: str | None = None


def connect(host: str, port: int, timeout: float = 3.0, family: int = 0, source: str | None = None,
            device: str | None = None) -> PortResult:
    """
    Try to open a TCP connection to host:port and report what happened.
    `source`/`device` send it from a specific local interface (see icmp.bind_source).
    """
    from nethelper.net.icmp import bind_source

    started = time.perf_counter()
    if source and not family:
        family = socket.AF_INET6 if ":" in source else socket.AF_INET  # match the source's address family
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except OSError as exc:
        return PortResult(host, port, "error", error=f"could not resolve: {exc}")
    last = PortResult(host, port, "error", error="no addresses")
    for fam, stype, proto, _, addr in infos:
        sock = socket.socket(fam, stype, proto)
        sock.settimeout(timeout)
        try:
            bind_source(sock, source, device)
            sock.connect(addr)
            return PortResult(host, port, "open", addr[0], round((time.perf_counter() - started) * 1000, 1))
        except ConnectionRefusedError:
            last = PortResult(host, port, "refused", addr[0], error="connection refused (host up, nothing listening)")
        except socket.timeout:
            last = PortResult(host, port, "timeout", addr[0], error="no response (filtered by a firewall or host down)")
        except OSError as exc:
            last = PortResult(host, port, "error", addr[0], error=str(exc))
        finally:
            sock.close()
    return last


def connect_many(pairs: list[tuple[str, int]], timeout: float = 3.0, workers: int = 32,
                 source: str | None = None) -> list[PortResult]:
    """Run many connect tests concurrently; results keep the input order."""
    if not pairs:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        return list(pool.map(lambda p: connect(p[0], p[1], timeout, source=source), pairs))


def banner(host: str, port: int, kind: str = "tcp", timeout: float = 5.0) -> PortResult:
    """
    Connect and, for services that greet first, read the first line they send.
    TLS-wrapped kinds (smtps/imaps/ldaps) perform a verified TLS handshake first.
    """
    res = connect(host, port, timeout)
    if res.state != "open":
        return res
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if kind in TLS_KINDS:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                if kind == "ldaps":
                    res.banner = f"TLS OK ({sock.version()})"
            if kind in BANNER_KINDS:
                data = sock.recv(512)
                first = data.decode("utf-8", errors="replace").splitlines()[0] if data else ""
                res.banner = validate.safe_text(first, 200) or None
        finally:
            sock.close()
    except ssl.SSLCertVerificationError as exc:
        res.error = f"TLS certificate not trusted: {exc.verify_message}"
    except (OSError, ssl.SSLError) as exc:
        res.error = f"connected but could not read banner: {exc}"
    return res
