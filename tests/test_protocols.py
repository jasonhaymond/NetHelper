"""
Protocol tests against REAL local servers (no mocks): a DNS server, HTTP
server, TLS server, NTP server and TCP listeners run on 127.0.0.1 inside the
test, and NetHelper's clients talk to them over actual sockets.
"""

from __future__ import annotations

import http.server
import socket
import struct
import threading
import time

import pytest

from nethelper.net import dnswire, httpcheck, icmp, ntp, tcp, tlscheck, x509


def _dns_answer(query: bytes, ip: str = "10.9.8.7", truncated: bool = False) -> bytes:
    """Build a DNS response to `query` with one A record (optionally with the TC flag)."""
    qid = query[:2]
    flags = 0x8380 if truncated else 0x8180
    qsection = query[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return qid + struct.pack("!HHHHH", flags, 1, 0 if truncated else 1, 0, 0) + qsection + (b"" if truncated else answer)


@pytest.fixture
def dns_server():
    """UDP + TCP DNS server on the same local port. UDP answers 'truncated' for big.test."""
    # Windows reserves (different) port ranges for Hyper-V/WSL per protocol,
    # mostly inside the ephemeral range; try random ports below it until one
    # number is free for BOTH TCP and UDP.
    import random

    rng = random.Random()
    for _ in range(100):
        port = rng.randint(20000, 45000)
        tcp_srv, udp = socket.socket(), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp_srv.bind(("127.0.0.1", port))
            udp.bind(("127.0.0.1", port))
            break
        except OSError:
            tcp_srv.close()
            udp.close()
    else:
        pytest.skip("no port free for both TCP and UDP")
    tcp_srv.listen(4)
    stop = threading.Event()

    def serve_udp():
        udp.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = udp.recvfrom(4096)
            except OSError:
                continue
            udp.sendto(_dns_answer(data, truncated=b"\x03big" in data), addr)

    def serve_tcp():
        tcp_srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = tcp_srv.accept()
            except OSError:
                continue
            with conn:
                n = struct.unpack("!H", conn.recv(2))[0]
                q = conn.recv(n)
                resp = _dns_answer(q, ip="10.1.1.1")
                conn.sendall(struct.pack("!H", len(resp)) + resp)

    threads = [threading.Thread(target=f, daemon=True) for f in (serve_udp, serve_tcp)]
    for t in threads:
        t.start()
    yield port
    stop.set()
    udp.close()
    tcp_srv.close()


def test_dns_query_over_udp(dns_server):
    """A real UDP query/response round trip parses the A record."""
    r = dnswire.query("www.example.test", "A", server="127.0.0.1", port=dns_server, timeout=2)
    assert r.rcode == "NOERROR" and r.values("A") == ["10.9.8.7"] and r.transport == "udp"


def test_dns_truncated_udp_retries_over_tcp(dns_server):
    """A truncated (TC) UDP answer is automatically retried over TCP, as RFC 1035 requires."""
    r = dnswire.query("big.example.test", "A", server="127.0.0.1", port=dns_server, timeout=2)
    assert r.transport == "tcp" and r.values("A") == ["10.1.1.1"]


def test_dns_query_build_parse_roundtrip_with_dnssec():
    """The EDNS0 DO bit is encoded correctly (OPT record present in the additional section)."""
    _, packet = dnswire.build_query("example.com", "MX", dnssec=True)
    assert struct.unpack("!H", packet[10:12])[0] == 1  # ARCOUNT
    assert packet.endswith(b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0))


class _Handler(http.server.BaseHTTPRequestHandler):
    """Tiny HTTP handler: /redirect -> 302 to /ok; /ok -> 200 'hello'."""

    def do_GET(self):  # noqa: N802 - name required by BaseHTTPRequestHandler
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture
def http_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_http_fetch_follows_redirect_with_timings(http_server):
    """Redirects are followed and every phase is timed."""
    res = httpcheck.fetch(f"http://127.0.0.1:{http_server}/redirect", timeout=5)
    assert res.ok and res.status == 200 and len(res.hops) == 2
    assert res.hops[0].status == 302
    assert res.hops[-1].connect_ms is not None and res.hops[-1].ttfb_ms is not None
    assert res.body_sample == "hello"


def test_tcp_connect_open_and_refused(http_server):
    """Open vs refused ports are distinguished (host up, nothing listening)."""
    assert tcp.connect("127.0.0.1", http_server).state == "open"
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    # Windows retries a refused SYN for ~2 s before reporting it, so allow 5 s.
    assert tcp.connect("127.0.0.1", free, timeout=5).state == "refused"


def test_tcp_banner_is_read_and_sanitised():
    """An SMTP-style greeting is captured, with control characters stripped."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):  # connect test + banner read
            conn, _ = srv.accept()
            conn.sendall(b"220 mail.test ESMTP\x1b[31m ready\r\n")
            time.sleep(0.1)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    res = tcp.banner("127.0.0.1", port, "smtp", timeout=3)
    srv.close()
    assert res.banner and res.banner.startswith("220 mail.test") and "\x1b" not in res.banner


def test_tls_untrusted_cert_is_diagnosed(tls_server):
    """A self-signed certificate is reported as untrusted AND still read for diagnosis."""
    r = tlscheck.inspect("localhost", tls_server, timeout=5)
    assert r.connected and not r.trusted
    assert r.verify_error
    assert r.cert["subject"].get("CN") == "localhost"
    assert r.cert["self_signed"] is True
    assert "localhost" in r.cert["san"] and "127.0.0.1" in r.cert["san"]
    assert 0 <= r.cert["days_left"] <= 2


def test_x509_name_matching_rules():
    """Wildcards cover exactly one label, per RFC 6125."""
    assert x509.name_matches("www.example.com", ["*.example.com"])
    assert not x509.name_matches("example.com", ["*.example.com"])
    assert not x509.name_matches("a.b.example.com", ["*.example.com"])
    assert x509.name_matches("Example.COM.", ["example.com"])


def test_ntp_offset_against_local_server():
    """Clock offset is computed correctly against a local NTP server running 10 s fast."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def serve():
        data, addr = srv.recvfrom(512)
        now = time.time() + 10  # server clock is 10 s ahead
        ts = ntp._to_ntp(now)
        reply = b"\x24\x02" + b"\0" * 22 + data[40:48] + ts + ts
        srv.sendto(reply, addr)

    threading.Thread(target=serve, daemon=True).start()
    orig = socket.getaddrinfo
    try:
        socket.getaddrinfo = lambda *a, **k: [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", port))]
        r = ntp.query("fake-ntp", timeout=3)
    finally:
        socket.getaddrinfo = orig
        srv.close()
    assert r.error is None and r.stratum == 2
    assert 9.5 < r.offset_s < 10.5


def test_icmp_checksum_and_loopback_ping():
    """The Internet checksum is correct, and pinging loopback works without admin rights."""
    pkt = icmp.build_echo(0x1234, 1, b"abcd")
    assert icmp._checksum(pkt) == 0  # a packet including its checksum sums to zero
    stats = icmp.ping("127.0.0.1", count=2, timeout=2, interval=0.05)
    assert stats.received >= 1, stats.error
