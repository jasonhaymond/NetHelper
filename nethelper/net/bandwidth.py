"""
Internet speed tests and iperf3, plus "latency under load" (bufferbloat).

  HTTP download/upload - transfers a known number of bytes over HTTPS to a
      speed-test endpoint (Cloudflare's by default; configurable in .env or a
      profile) and times it. Measures real-world speed to the internet,
      including any proxy/TLS inspection in the way.
  Latency under load - while the download/upload runs, the gateway and a
      public IP are pinged continuously. A big jump compared with idle latency
      is "bufferbloat": the router's queues fill up, so calls/games stutter
      whenever someone downloads, even though raw speed looks fine.
  iperf3 - if the iperf3 tool is installed and an iperf3 server exists (e.g.
      the iperf package on pfSense/OPNsense), raw TCP throughput both ways.

Speed tests use real bandwidth (25 MB down / 5 MB up by default), so they're
only part of full runs and the `speed` command, never quick checks.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Any, Callable

from nethelper import __version__
from nethelper.core import cmd, validate

CHUNK = 64 * 1024


def download(url_template: str, size: int, timeout: float = 30.0) -> dict:
    """
    Download `size` bytes and return {"mbps", "bytes", "seconds", "url"}.
    `url_template` may contain "{bytes}", replaced with the size.
    """
    url = validate.url(url_template.replace("{bytes}", str(size)))
    req = urllib.request.Request(url, headers={"User-Agent": f"NetHelper/{__version__}"})
    started = time.perf_counter()
    received = 0
    # Security note (B310): validated https URL
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        first_byte = time.perf_counter()
        while received < size * 2:  # hard cap in case the server sends more than asked
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            received += len(chunk)
            if time.perf_counter() - started > timeout:
                break
    elapsed = max(time.perf_counter() - first_byte, 1e-6)
    return {"mbps": round(received * 8 / elapsed / 1_000_000, 2), "bytes": received,
            "seconds": round(elapsed, 2), "url": url}


def upload(url: str, size: int, timeout: float = 30.0) -> dict:
    """POST `size` bytes and return {"mbps", "bytes", "seconds", "url"}."""
    url = validate.url(url)
    body = b"\0" * size
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "User-Agent": f"NetHelper/{__version__}", "Content-Type": "application/octet-stream"})
    started = time.perf_counter()
    # Security note (B310): validated https URL
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        resp.read(4096)
    elapsed = max(time.perf_counter() - started, 1e-6)
    return {"mbps": round(size * 8 / elapsed / 1_000_000, 2), "bytes": size,
            "seconds": round(elapsed, 2), "url": url}


def _ping_series(ip: str, stop: threading.Event, out: list[float], interval: float = 0.2) -> None:
    """Ping `ip` every `interval` seconds until `stop` is set, appending RTTs (ms)."""
    from nethelper.net import icmp

    seq = 0
    while not stop.is_set():
        seq += 1
        r = icmp.echo(ip, seq=seq, timeout=1.0)
        if r.status == icmp.OK and r.rtt_ms is not None:
            out.append(r.rtt_ms)
        stop.wait(interval)


def _summ(values: list[float]) -> dict:
    """Average / 95th-percentile / max of a list of latencies."""
    if not values:
        return {"samples": 0, "avg_ms": None, "p95_ms": None, "max_ms": None}
    s = sorted(values)
    return {"samples": len(s), "avg_ms": round(sum(s) / len(s), 1), "p95_ms": round(s[int(0.95 * (len(s) - 1))], 1),
            "max_ms": round(s[-1], 1)}


def with_latency(targets: list[str], work: Callable[[], Any]) -> tuple[Any, dict]:
    """
    Measure idle latency to each target (3 s), then run `work()` while pinging
    the targets, and return (work result, {target: {"idle": ..., "loaded": ...,
    "increase_ms": ...}}).
    """
    from nethelper.net import icmp

    idle: dict[str, list[float]] = {t: [] for t in targets}
    for t in targets:
        for seq in range(1, 11):
            r = icmp.echo(t, seq=seq, timeout=1.0)
            if r.status == icmp.OK and r.rtt_ms is not None:
                idle[t].append(r.rtt_ms)
            time.sleep(0.2)
    loaded: dict[str, list[float]] = {t: [] for t in targets}
    stop = threading.Event()
    threads = [threading.Thread(target=_ping_series, args=(t, stop, loaded[t]), daemon=True) for t in targets]
    for th in threads:
        th.start()
    try:
        result = work()
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=3)
    report = {}
    for t in targets:
        i, lo = _summ(idle[t]), _summ(loaded[t])
        inc = round(lo["avg_ms"] - i["avg_ms"], 1) if i["avg_ms"] is not None and lo["avg_ms"] is not None else None
        report[t] = {"idle": i, "loaded": lo, "increase_ms": inc}
    return result, report


def bufferbloat_grade(increase_ms: float | None) -> str:
    """Letter grade for latency increase under load (in the spirit of common bufferbloat tests)."""
    if increase_ms is None:
        return "?"
    for limit, grade in ((5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")):
        if increase_ms < limit:
            return grade
    return "F"


def iperf3(server: str, seconds: int = 5, reverse: bool = False, port: int = 5201,
           source: str | None = None, streams: int = 1) -> dict:
    """
    Run `iperf3 -c server -t N -J` (JSON output); reverse=True measures the
    download direction (server -> us). Returns {"mbps", "retransmits"} or {"error"}.
    """
    server = validate.hostname(server)
    argv = ["iperf3", "-c", server, "-p", str(validate.port(port)), "-t", str(int(seconds)),
            "-P", str(max(1, min(int(streams), 8))), "-J"]
    if reverse:
        argv.append("-R")
    if source:
        argv += ["-B", validate.hostname(source)]  # bind to a local interface address
    res = cmd.run(argv, timeout=seconds + 25)
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return {"error": res.error or res.stderr.strip()[:200] or "iperf3 produced no output"}
    if data.get("error"):
        return {"error": validate.safe_text(data["error"], 200)}
    end = data.get("end", {})
    recv = end.get("sum_received", {})
    sent = end.get("sum_sent", {})
    return {"mbps": round(recv.get("bits_per_second", 0) / 1_000_000, 2),
            "retransmits": sent.get("retransmits"), "method": "iperf3"}
