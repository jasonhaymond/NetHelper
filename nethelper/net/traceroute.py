"""
Traceroute: discover each router ("hop") between this machine and a target,
and how long each takes to answer.

How it works: every IP packet carries a TTL ("time to live") counter that each
router decrements; when it hits zero the router discards the packet and sends
back an ICMP "TTL exceeded" message - revealing its address. Sending pings with
TTL 1, 2, 3, ... therefore maps the path hop by hop.

Method by OS / privilege:
  Windows (any)     - Windows ICMP API with TTL (icmp.py); probes for all hops
                      are sent in parallel, so a full trace takes seconds.
  Linux/macOS root  - raw ICMP socket with TTL, same parallel approach.
  Linux/macOS user  - system `traceroute -n`, else `tracepath -n` (Linux),
                      else the system ping with a TTL option, hop by hop.

A "*" hop (no reply) is normal - many routers don't answer probes. Only
consistent loss from some hop onward *to the destination* indicates a problem.
"""

from __future__ import annotations

import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

from nethelper.core import cmd
from nethelper.net import icmp


@dataclass
class Hop:
    """One hop: its TTL number, who answered, and response times (ms)."""

    ttl: int
    address: str | None = None
    rtts: list[float] = field(default_factory=list)
    hostname: str | None = None
    reached: bool = False  # True when this hop IS the destination

    @property
    def avg_ms(self) -> float | None:
        return round(sum(self.rtts) / len(self.rtts), 1) if self.rtts else None


@dataclass
class TraceResult:
    """Full trace: target, its IP, hops in order, whether we got there, method used."""

    target: str
    address: str | None
    hops: list[Hop] = field(default_factory=list)
    reached: bool = False
    method: str = ""
    error: str | None = None
    raw: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        for hop, src in zip(data["hops"], self.hops, strict=True):
            hop["avg_ms"] = src.avg_ms
        data.pop("raw", None)
        return data


def _reverse(ip: str | None) -> str | None:
    """Reverse-DNS lookup (IP -> name) with a short timeout; None if none."""
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def _probe_hop(ip: str, ttl: int, probes: int, timeout: float, method: str) -> Hop:
    """Send `probes` echo requests with the given TTL and collect the answers."""
    hop = Hop(ttl=ttl)
    for n in range(probes):
        reply = icmp.echo(ip, seq=ttl * 10 + n, timeout=timeout, ttl=ttl, method=method)
        if reply.status in (icmp.OK, icmp.TTL_EXPIRED) and reply.from_ip:
            hop.address = hop.address or reply.from_ip
            if reply.rtt_ms is not None:
                hop.rtts.append(reply.rtt_ms)
            if reply.status == icmp.OK:
                hop.reached = True
    return hop


def _trace_parallel(ip: str, max_hops: int, probes: int, timeout: float, method: str) -> list[Hop]:
    """
    Probe every TTL at once in worker threads, then cut the list off at the
    first hop that is the destination itself.
    """
    with ThreadPoolExecutor(max_workers=min(max_hops, 16)) as pool:
        hops = list(pool.map(lambda t: _probe_hop(ip, t, probes, timeout, method), range(1, max_hops + 1)))
    for i, hop in enumerate(hops):
        if hop.reached or hop.address == ip:
            hop.reached = True
            return hops[: i + 1]
    # Trim the long tail of silent hops after the last one that answered.
    last = max((i for i, h in enumerate(hops) if h.address), default=-1)
    return hops[: min(last + 3, len(hops))]


# Regex: one line of `traceroute -n` output, e.g.
#   " 3  10.20.0.1  4.123 ms  3.9 ms"   or   " 7  * * *"
_TR_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
# Regex: an IPv4 or IPv6 address token inside such a line.
_IP_TOKEN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\b")
# Regex: a time value like "4.123 ms" or "4.1ms".
_MS_TOKEN = re.compile(r"([\d.]+)\s*ms")
# Regex: one line of `tracepath -n` output, e.g. " 2:  10.0.0.1    1.234ms"
_TP_LINE = re.compile(r"^\s*(\d+)\??:\s+(\S+)\s+(?:([\d.]+)ms)?")


def parse_traceroute(output: str, target_ip: str) -> list[Hop]:
    """Parse `traceroute -n` (Linux/macOS) or `tracert -d` (Windows) text."""
    hops: dict[int, Hop] = {}
    for line in output.splitlines():
        m = _TR_LINE.match(line)
        if not m:
            continue
        ttl = int(m.group(1))
        rest = m.group(2)
        hop = hops.setdefault(ttl, Hop(ttl=ttl))
        ipm = _IP_TOKEN.search(rest.replace("<1 ms", "0.5 ms"))
        if ipm and not hop.address:
            hop.address = ipm.group(1)
        hop.rtts.extend(float(x) for x in _MS_TOKEN.findall(rest.replace("<1 ms", "0.5 ms")))
        if hop.address == target_ip:
            hop.reached = True
    return [hops[k] for k in sorted(hops)]


def parse_tracepath(output: str, target_ip: str) -> list[Hop]:
    """Parse `tracepath -n` output (Linux, no root required)."""
    hops: dict[int, Hop] = {}
    for line in output.splitlines():
        m = _TP_LINE.match(line)
        if not m or m.group(2) in ("[LOCALHOST]", "no"):
            continue
        ttl = int(m.group(1))
        hop = hops.setdefault(ttl, Hop(ttl=ttl))
        hop.address = hop.address or m.group(2)
        if m.group(3):
            hop.rtts.append(float(m.group(3)))
        if hop.address == target_ip:
            hop.reached = True
    return [hops[k] for k in sorted(hops)]


def trace(host: str, max_hops: int = 30, probes: int = 2, timeout: float = 1.5,
          resolve_names: bool = True) -> TraceResult:
    """
    Trace the route to `host`. See module docstring for the method chosen.
    Returns a TraceResult; network problems are reported, never raised.
    """
    try:
        ip, fam = icmp.resolve(host)
    except (OSError, ValueError) as exc:
        return TraceResult(target=host, address=None, error=f"could not resolve: {exc}")
    v6 = fam == socket.AF_INET6
    result = TraceResult(target=host, address=ip)
    method = icmp.best_method(v6)

    if method in ("winapi", "raw"):
        result.method = method
        result.hops = _trace_parallel(ip, max_hops, probes, timeout, method)
    else:
        res = None
        if cmd.which("traceroute"):
            argv = ["traceroute", "-n", "-q", str(probes), "-w", str(max(int(timeout), 1)), "-m", str(max_hops)]
            if v6:
                argv.insert(1, "-6")
            res = cmd.run(argv + [ip], timeout=max_hops * probes * timeout + 15)
            result.method = "traceroute"
            result.hops = parse_traceroute(res.stdout, ip)
        elif cmd.which("tracepath") and sys.platform.startswith("linux"):
            res = cmd.run(["tracepath", "-n", "-m", str(max_hops), ip], timeout=max_hops * 3 + 15)
            result.method = "tracepath"
            result.hops = parse_tracepath(res.stdout, ip)
        else:
            # Hop-by-hop via the system ping command's TTL option.
            result.method = "system-ping"
            result.hops = []
            for ttl in range(1, max_hops + 1):
                hop = _probe_hop(ip, ttl, 1, timeout, "system")
                result.hops.append(hop)
                if hop.reached:
                    break
        if res is not None:
            result.raw = res.transcript()
            if res.error and not result.hops:
                result.error = res.error

    result.reached = any(h.reached for h in result.hops)
    if resolve_names and result.hops:
        # Reverse lookups in parallel; slow DNS shouldn't make the trace crawl.
        with ThreadPoolExecutor(max_workers=8) as pool:
            for hop, name in zip(result.hops, pool.map(lambda h: _reverse(h.address), result.hops), strict=True):
                hop.hostname = name
    return result
