"""
LAN/WAN throughput testing between two machines - a built-in, dependency-free
alternative to iperf3.

    Machine A:  nethelper serve                  (listens on TCP/UDP 5202)
    Machine B:  nethelper throughput <A's IP>    (upload, download, or both)

Tests:
  TCP upload    client sends as fast as it can for N seconds; the SERVER
                measures what it received (the truthful number)
  TCP download  server sends for N seconds; the client measures
  parallel      -P N runs N TCP streams at once (fills fast links that one
                stream can't, e.g. high-latency WAN or 10 GbE)
  UDP           client sends at a chosen rate; the server reports loss,
                out-of-order packets and jitter (RFC 3550) - the numbers that
                matter for VoIP/video

Protocol (one TCP connection per stream, newline-terminated JSON lines):
  server -> {"proto": "nethelper-tp/1", "nonce": "<random>", "auth": true|false}
  client -> {"mode": "upload|download|udp", "seconds": N, ..., "mac": "<HMAC>"}
  server -> {"ok": true, ...}  or  {"error": "..."}
  ...data phase...
  server -> {"bytes": ..., "seconds": ...}   (upload / udp statistics)

SECURITY (the server is a network-facing service, so it is locked down):
  - runs only when explicitly started with `nethelper serve`, in the
    foreground, and stops on Ctrl+C (or after one test with --once)
  - optional shared key (NETHELPER_THROUGHPUT_KEY / --key): the client must
    prove knowledge of it with HMAC-SHA256 over a random per-connection nonce,
    so the key never crosses the network and replies can't be replayed;
    compared in constant time (hmac.compare_digest)
  - strict limits: request line <= 2 KB of JSON, test length <= 60 s, UDP
    rate <= 10 Gb/s, packet size 64-1472, <= 8 concurrent sessions, 10 s idle
    timeout - so it can't be used to tie the machine up indefinitely
  - it only ever sends zero-filled test data or statistics back; it never
    reads files, runs commands, or forwards traffic anywhere
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from nethelper.net.icmp import bind_source

log = logging.getLogger("nethelper.throughput")

PROTO = "nethelper-tp/1"
DEFAULT_PORT = 5202
MAX_LINE = 2048
MAX_SECONDS = 60
MAX_STREAMS = 8
MAX_SESSIONS = 8
MAX_RATE_BPS = 10_000_000_000
IDLE_TIMEOUT = 10.0
CHUNK = 128 * 1024
_ZEROS = bytes(CHUNK)
_UDP_HDR = struct.Struct("!Id")  # sequence number (uint32) + sender timestamp (double, seconds)

# Security note (B104): listening on all interfaces is the purpose of a LAN
# test server; it runs only when the user starts `nethelper serve`, --bind
# narrows it to one address, and the auth/limits above apply to every client.
ANY_ADDRESS = "0.0.0.0"  # nosec B104


class ThroughputError(Exception):
    """A test couldn't run (no server, auth failed, refused by limits...). Message is user-readable."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _mac(key: str, nonce: str, request: dict) -> str:
    """HMAC-SHA256 over the nonce and the request fields, keyed by the shared secret."""
    fields = "|".join(f"{k}={request[k]}" for k in sorted(request) if k != "mac")
    return hmac.new(key.encode("utf-8"), f"{nonce}|{fields}".encode("utf-8"), hashlib.sha256).hexdigest()


def _send_line(sock: socket.socket, obj: dict) -> None:
    """Send one JSON object as a single line (the protocol's message format)."""
    sock.sendall(json.dumps(obj).encode("utf-8") + b"\n")


def _close_gracefully(sock: socket.socket, max_bytes: int = 65536, max_seconds: float = 1.0) -> None:
    """
    Finish a rejected session so the client actually receives the error line.

    Closing a socket while the client's data is still unread makes the OS send
    a TCP reset, which can destroy the error reply before the client reads it
    (the client then sees "connection reset" instead of the reason). So we
    signal "no more data from us" (shutdown for writing), then read and discard
    whatever the client already sent. Both limits are small and fixed, so a
    misbehaving client can't use this to hold the session open.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(0.2)
        deadline = time.monotonic() + max_seconds
        drained = 0
        while drained < max_bytes and time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            drained += len(chunk)
    except OSError:
        pass  # timeout or the client already closed: nothing more to do


def _recv_line(sock: socket.socket, limit: int = MAX_LINE) -> dict:
    """Read one JSON line (bounded). Raises ThroughputError on overflow/garbage/close."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ThroughputError("connection closed during handshake")
        buf += chunk
        if len(buf) > limit:
            raise ThroughputError("handshake line too long")
    try:
        obj = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ThroughputError("malformed handshake") from exc
    if not isinstance(obj, dict):
        raise ThroughputError("malformed handshake")
    return obj


def _int_field(req: dict, name: str, lo: int, hi: int, default: int | None = None) -> int:
    """Validate an integer request field within [lo, hi]."""
    value = req.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise ThroughputError(f"{name} must be an integer between {lo} and {hi}")
    return value


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class Server:
    """
    The `nethelper serve` endpoint. Create, then call serve_forever() (blocks)
    or start() (background thread, used by tests). stop() shuts it down.
    """

    def __init__(self, bind: str | None = None, port: int = DEFAULT_PORT, key: str = "",
                 once: bool = False, on_event: Callable[[str], None] | None = None):
        self.bind, self.port, self.key, self.once = bind or ANY_ADDRESS, port, key, once
        self.on_event = on_event or (lambda msg: None)
        self._sessions = threading.BoundedSemaphore(MAX_SESSIONS)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._active = 0              # sessions currently running
        self._last_done = 0.0         # monotonic time the last session ended
        self.completed = 0

    # With --once: after a test completes, wait this long with no sessions
    # running before exiting, so all parallel streams of one test can finish.
    ONCE_GRACE = 2.0

    def _event(self, msg: str) -> None:
        log.info("serve: %s", msg)
        self.on_event(msg)

    def listen(self) -> int:
        """Open the listening socket; returns the actual port (useful with port 0)."""
        fam = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        self._sock = socket.socket(fam, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.port))
        self._sock.listen(MAX_SESSIONS * 2)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        return self.port

    def serve_forever(self) -> None:
        """
        Accept clients until stop() / Ctrl+C. With once=True, exit after a test
        has completed AND no session (e.g. another parallel stream) is still
        running for ONCE_GRACE seconds.
        """
        if self._sock is None:
            self.listen()
        while not self._stop.is_set():
            if self.once and self.completed:
                with self._lock:
                    idle = self._active == 0 and time.monotonic() - self._last_done > self.ONCE_GRACE
                if idle:
                    break
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._sessions.acquire(blocking=False):
                try:
                    _send_line(conn, {"error": "server busy (too many concurrent tests)"})
                finally:
                    conn.close()
                continue
            with self._lock:
                self._active += 1
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        self.close()

    def start(self) -> int:
        """Run serve_forever in a background thread; returns the port."""
        port = self.listen()
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return port

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _handle(self, conn: socket.socket, addr) -> None:
        """One client session: handshake, validate, run the requested test."""
        peer = f"{addr[0]}:{addr[1]}"
        try:
            conn.settimeout(IDLE_TIMEOUT)
            nonce = secrets.token_hex(16)
            _send_line(conn, {"proto": PROTO, "nonce": nonce, "auth": bool(self.key)})
            req = _recv_line(conn)
            if self.key:
                given = req.get("mac")
                if not isinstance(given, str) or not hmac.compare_digest(given, _mac(self.key, nonce, req)):
                    _send_line(conn, {"error": "authentication failed (wrong or missing key)"})
                    self._event(f"{peer} rejected: authentication failed")
                    return
            mode = req.get("mode")
            if mode not in ("upload", "download", "udp"):
                raise ThroughputError("mode must be upload, download or udp")
            seconds = _int_field(req, "seconds", 1, MAX_SECONDS)
            if mode == "upload":
                self._upload(conn, seconds, peer)
            elif mode == "download":
                self._download(conn, seconds, peer)
            else:
                rate = _int_field(req, "rate_bps", 1000, MAX_RATE_BPS)
                size = _int_field(req, "size", 64, 1472)
                self._udp(conn, seconds, rate, size, addr[0], peer)
            with self._lock:
                self.completed += 1
        except ThroughputError as exc:
            if "closed during handshake" in str(exc):
                # A reachability probe (server_available) or a port scanner - not worth a console line.
                log.debug("serve: %s disconnected before sending a test request", peer)
                return
            try:
                _send_line(conn, {"error": str(exc)})
                _close_gracefully(conn)
            except OSError:
                pass
            self._event(f"{peer} rejected: {exc}")
        except OSError as exc:
            self._event(f"{peer} connection error: {exc}")
        finally:
            conn.close()
            with self._lock:
                self._active -= 1
                self._last_done = time.monotonic()
            self._sessions.release()

    def _upload(self, conn: socket.socket, seconds: int, peer: str) -> None:
        """Receive until the client closes its side (or the time limit), then report bytes/time."""
        _send_line(conn, {"ok": True})
        received, first, last = 0, None, None
        deadline = time.monotonic() + seconds + 5
        conn.settimeout(IDLE_TIMEOUT)
        while time.monotonic() < deadline:
            data = conn.recv(CHUNK)
            if not data:
                break
            now = time.perf_counter()
            first = first or now
            last = now
            received += len(data)
        elapsed = (last - first) if first and last and last > first else 1e-6
        _send_line(conn, {"bytes": received, "seconds": round(elapsed, 4)})
        self._event(f"{peer} upload: {received * 8 / elapsed / 1e6:.1f} Mb/s over {elapsed:.1f}s")

    def _download(self, conn: socket.socket, seconds: int, peer: str) -> None:
        """Send zero-filled data for `seconds`, then close our side."""
        _send_line(conn, {"ok": True})
        sent, end = 0, time.monotonic() + seconds
        while time.monotonic() < end:
            conn.sendall(_ZEROS)
            sent += CHUNK
        conn.shutdown(socket.SHUT_WR)
        self._event(f"{peer} download: sent {sent * 8 / seconds / 1e6:.1f} Mb/s for {seconds}s")

    def _udp(self, conn: socket.socket, seconds: int, rate: int, size: int, client_ip: str, peer: str) -> None:
        """Receive a paced UDP stream on a fresh port and report loss/jitter/reordering."""
        fam = socket.AF_INET6 if ":" in client_ip else socket.AF_INET
        udp = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            udp.bind((self.bind if ":" in self.bind or fam == socket.AF_INET else "::", 0))
            udp.settimeout(0.2)
            _send_line(conn, {"ok": True, "udp_port": udp.getsockname()[1]})
            stats = {"received": 0, "bytes": 0, "max_seq": -1, "out_of_order": 0, "duplicates": 0}
            seen: set[int] = set()
            jitter, prev_transit, last_seq = 0.0, None, -1
            first = last = None
            done = threading.Event()

            def watch_control() -> None:
                try:
                    conn.settimeout(seconds + 10)
                    if conn.recv(16).startswith(b"done"):
                        done.set()
                except OSError:
                    done.set()

            threading.Thread(target=watch_control, daemon=True).start()
            deadline = time.monotonic() + seconds + 5
            while time.monotonic() < deadline:
                try:
                    data, src = udp.recvfrom(2048)
                except socket.timeout:
                    if done.is_set():
                        break
                    continue
                if src[0] != client_ip or len(data) < _UDP_HDR.size:
                    continue  # only count the client that set up this test
                seq, sent_ts = _UDP_HDR.unpack_from(data)
                now = time.time()
                first = first or time.perf_counter()
                last = time.perf_counter()
                if seq in seen:
                    stats["duplicates"] += 1
                    continue
                if len(seen) < 5_000_000:
                    seen.add(seq)
                stats["received"] += 1
                stats["bytes"] += len(data)
                if seq < last_seq:
                    stats["out_of_order"] += 1
                last_seq = max(last_seq, seq)
                stats["max_seq"] = max(stats["max_seq"], seq)
                # RFC 3550 jitter: smoothed variation in transit time. The unknown
                # clock offset between the two machines cancels out in the difference.
                transit = now - sent_ts
                if prev_transit is not None:
                    jitter += (abs(transit - prev_transit) - jitter) / 16
                prev_transit = transit
            expected = stats["max_seq"] + 1
            elapsed = (last - first) if first and last and last > first else 1e-6
            result = {**stats, "expected": expected,
                      "lost": max(0, expected - stats["received"]),
                      "loss_pct": round(100 * max(0, expected - stats["received"]) / expected, 2) if expected else 100.0,
                      "jitter_ms": round(jitter * 1000, 3), "seconds": round(elapsed, 3)}
            _send_line(conn, result)
            self._event(f"{peer} udp: {result['loss_pct']}% loss, jitter {result['jitter_ms']} ms")
        finally:
            udp.close()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

@dataclass
class Result:
    """Outcome of one test direction."""

    mode: str
    target: str
    port: int
    mbps: float | None = None
    bytes: int = 0
    seconds: float = 0.0
    streams: int = 1
    per_stream_mbps: list[float] = field(default_factory=list)
    udp: dict | None = None
    method: str = "nethelper"
    error: str | None = None


def _open(host: str, port: int, key: str, request: dict, timeout: float, source: str | None) -> tuple[socket.socket, dict]:
    """Connect, complete the handshake (with HMAC if the server wants a key); return (socket, server reply)."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET6 if source and ":" in source else
                                   (socket.AF_INET if source else 0), socket.SOCK_STREAM)
    except OSError as exc:
        raise ThroughputError(f"cannot resolve {host}: {exc}") from exc
    last_exc: Exception | None = None
    for fam, stype, proto, _, addr in infos:
        sock = socket.socket(fam, stype, proto)
        sock.settimeout(timeout)
        try:
            bind_source(sock, source)
            sock.connect(addr)
            break
        except OSError as exc:
            last_exc = exc
            sock.close()
    else:
        if isinstance(last_exc, ConnectionRefusedError):
            raise ThroughputError(f"no NetHelper throughput server at {host}:{port} (connection refused)")
        raise ThroughputError(f"cannot connect to {host}:{port}: {last_exc}")
    try:
        hello = _recv_line(sock)
        if hello.get("proto") != PROTO:
            raise ThroughputError(f"{host}:{port} is not a NetHelper throughput server")
        if hello.get("auth"):
            if not key:
                raise ThroughputError("server requires a key - pass --key or set NETHELPER_THROUGHPUT_KEY")
            request = {**request, "mac": _mac(key, str(hello.get("nonce", "")), request)}
        _send_line(sock, request)
        reply = _recv_line(sock)
        if reply.get("error"):
            raise ThroughputError(f"server refused: {reply['error']}")
        return sock, reply
    except socket.timeout as exc:
        sock.close()
        raise ThroughputError(f"{host}:{port} accepted the connection but didn't answer (not a NetHelper server?)") from exc
    except ThroughputError:
        sock.close()
        raise


def _tcp_stream(host: str, port: int, key: str, mode: str, seconds: int, source: str | None,
                timeout: float) -> tuple[int, float]:
    """Run one TCP stream; returns (bytes, seconds) as measured by the receiving side."""
    sock, _ = _open(host, port, key, {"mode": mode, "seconds": seconds}, timeout, source)
    try:
        if mode == "upload":
            sock.settimeout(IDLE_TIMEOUT)
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                sock.sendall(_ZEROS)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(seconds + 15)
            res = _recv_line(sock)
            return int(res.get("bytes", 0)), float(res.get("seconds", seconds))
        # download: count what arrives until the server closes
        sock.settimeout(IDLE_TIMEOUT)
        received, first, last = 0, None, None
        while True:
            data = sock.recv(CHUNK)
            if not data:
                break
            now = time.perf_counter()
            first = first or now
            last = now
            received += len(data)
        return received, (last - first) if first and last and last > first else 1e-6
    finally:
        sock.close()


def tcp_test(host: str, port: int = DEFAULT_PORT, mode: str = "upload", seconds: int = 10, streams: int = 1,
             key: str = "", source: str | None = None, timeout: float = 5.0) -> Result:
    """Run a TCP upload or download test with `streams` parallel connections."""
    seconds = max(1, min(int(seconds), MAX_SECONDS))
    streams = max(1, min(int(streams), MAX_STREAMS))
    result = Result(mode=mode, target=host, port=port, streams=streams)
    with ThreadPoolExecutor(max_workers=streams) as pool:
        futures = [pool.submit(_tcp_stream, host, port, key, mode, seconds, source, timeout) for _ in range(streams)]
        outcomes = []
        for f in futures:
            try:
                outcomes.append(f.result())
            except ThroughputError as exc:
                result.error = str(exc)
            except OSError as exc:
                result.error = f"{type(exc).__name__}: {exc}"
    if not outcomes:
        return result
    result.bytes = sum(b for b, _ in outcomes)
    result.seconds = round(max(s for _, s in outcomes), 3)
    result.per_stream_mbps = [round(b * 8 / s / 1e6, 2) for b, s in outcomes]
    result.mbps = round(sum(result.per_stream_mbps), 2)
    log.info("throughput %s to %s:%s: %s Mb/s (%d streams)", mode, host, port, result.mbps, streams)
    return result


def udp_test(host: str, port: int = DEFAULT_PORT, rate_mbps: float = 10.0, seconds: int = 10, size: int = 1200,
             key: str = "", source: str | None = None, timeout: float = 5.0) -> Result:
    """Send a paced UDP stream; the server reports loss, jitter and reordering."""
    seconds = max(1, min(int(seconds), MAX_SECONDS))
    size = max(64, min(int(size), 1472))
    rate_bps = int(max(0.001, min(rate_mbps, MAX_RATE_BPS / 1e6)) * 1e6)
    result = Result(mode="udp", target=host, port=port)
    try:
        ctl, reply = _open(host, port, key, {"mode": "udp", "seconds": seconds, "rate_bps": rate_bps, "size": size},
                    timeout, source)
    except ThroughputError as exc:
        result.error = str(exc)
        return result
    try:
        udp_port = int(reply["udp_port"])
        peer = ctl.getpeername()[0]
        udp = socket.socket(socket.AF_INET6 if ":" in peer else socket.AF_INET, socket.SOCK_DGRAM)
        try:
            bind_source(udp, source)
            interval = size * 8 / rate_bps  # seconds between packets at the target rate
            pad = bytes(size - _UDP_HDR.size)
            seq, start = 0, time.perf_counter()
            end = start + seconds
            while True:
                now = time.perf_counter()
                if now >= end:
                    break
                due = start + seq * interval
                if due > now:
                    time.sleep(min(due - now, 0.01))
                    continue
                try:
                    udp.sendto(_UDP_HDR.pack(seq, time.time()) + pad, (peer, udp_port))
                except OSError:
                    pass  # e.g. local buffer full at extreme rates - counted as loss by the server
                seq += 1
        finally:
            udp.close()
        time.sleep(0.5)  # let in-flight packets land before signalling the end
        ctl.sendall(b"done\n")
        ctl.settimeout(15)
        stats = _recv_line(ctl, limit=8192)
        stats["sent"] = seq
        result.udp = stats
        result.bytes = int(stats.get("bytes", 0))
        result.seconds = float(stats.get("seconds", seconds)) or seconds
        result.mbps = round(result.bytes * 8 / max(result.seconds, 1e-6) / 1e6, 2)
    except (ThroughputError, OSError, KeyError, ValueError) as exc:
        result.error = str(exc)
    finally:
        ctl.close()
    return result


def server_available(host: str, port: int = DEFAULT_PORT, timeout: float = 2.0) -> bool:
    """True if something at host:port speaks the NetHelper throughput protocol."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return _recv_line(s).get("proto") == PROTO
    except (OSError, ThroughputError):
        return False


def auto_test(host: str, port: int = DEFAULT_PORT, seconds: int = 10, streams: int = 1, key: str = "",
              source: str | None = None, directions: tuple[str, ...] = ("upload", "download"),
              iperf_port: int = 5201, allow_icmp: bool = True) -> dict:
    """
    Measure throughput to `host` with the best method it supports:
      1. a NetHelper throughput server (nethelper serve) on `port`
      2. an iperf3 server on `iperf_port` (if the iperf3 tool is installed here)
      3. ICMP load (approximate lower bound) - works against any pingable host,
         including routers that run nothing else
    Returns {"method", "results": {direction: {...}}, "notes": [...], "error"}.
    """
    from nethelper.core import cmd as _cmd
    from nethelper.net import bandwidth, tcp

    out: dict = {"target": host, "method": None, "results": {}, "notes": [], "error": None}
    if server_available(host, port):
        out["method"] = "nethelper"
        for d in directions:
            r = tcp_test(host, port, d, seconds, streams, key, source)
            out["results"][d] = {"mbps": r.mbps, "bytes": r.bytes, "seconds": r.seconds,
                                 "streams": r.streams, "per_stream_mbps": r.per_stream_mbps, "error": r.error}
        return out
    out["notes"].append(f"no NetHelper server on {host}:{port}")
    if _cmd.which("iperf3"):
        if tcp.connect(host, iperf_port, timeout=2.0, source=source).state == "open":
            out["method"] = "iperf3"
            for d in directions:
                out["results"][d] = bandwidth.iperf3(host, seconds, reverse=(d == "download"), port=iperf_port,
                                                     source=source, streams=streams)
            return out
        out["notes"].append(f"no iperf3 server on {host}:{iperf_port}")
    else:
        out["notes"].append("iperf3 not installed here (fallback skipped)")
    if allow_icmp:
        out["method"] = "icmp-load"
        out["results"]["icmp"] = icmp_load(host, seconds=min(seconds, 10), source=source)
        out["notes"].append("ICMP load gives an approximate LOWER BOUND - for real numbers run 'nethelper serve' "
                            "on the far end, or install the iperf3 package on the router (e.g. pfSense: "
                            "System > Package Manager > iperf)")
        return out
    out["error"] = "no throughput server found on the target"
    return out


def icmp_load(ip: str, seconds: int = 10, threads: int = 8, size: int = 1472, source: str | None = None) -> dict:
    """
    APPROXIMATE path capacity using ICMP only - for when the target (e.g. a
    router) runs no throughput server. Several threads send large pings back
    to back; echoed bytes per second gives a LOWER BOUND (routers rate-limit
    ICMP to themselves, so real TCP throughput is usually higher). Also
    reports latency under that load, which exposes bufferbloat/congestion.
    """
    from nethelper.net import icmp

    seconds = max(1, min(int(seconds), MAX_SECONDS))
    threads = max(1, min(int(threads), 16))
    end = time.monotonic() + seconds
    lock = threading.Lock()
    agg = {"sent": 0, "ok": 0, "rtts": []}

    def worker() -> None:
        seq = 0
        while time.monotonic() < end:
            seq += 1
            r = icmp.echo(ip, seq=seq, timeout=1.0, size=size, source=source)
            with lock:
                agg["sent"] += 1
                if r.status == icmp.OK and r.rtt_ms is not None:
                    agg["ok"] += 1
                    agg["rtts"].append(r.rtt_ms)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for _ in range(threads):
            pool.submit(worker)
    elapsed = max(time.monotonic() - started, 1e-6)
    rtts = agg["rtts"]
    echoed_bits = agg["ok"] * (size + 28) * 8 * 2  # request + reply, incl. IP/ICMP headers
    return {
        "method": "icmp-load (approximate lower bound)",
        "target": ip, "seconds": round(elapsed, 2), "threads": threads, "size": size,
        "sent": agg["sent"], "replies": agg["ok"],
        "loss_pct": round(100 * (agg["sent"] - agg["ok"]) / agg["sent"], 2) if agg["sent"] else 100.0,
        "mbps_echoed": round(echoed_bits / elapsed / 1e6, 2),
        "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "max_ms": round(max(rtts), 2) if rtts else None,
    }
