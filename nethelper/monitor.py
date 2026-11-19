"""
Continuous monitoring modes - for intermittent problems a one-off test misses.

`nethelper monitor` - every N seconds pings the gateway, public test IPs and
extra hosts (optionally through specific interfaces) and times a DNS lookup,
printing one compact line per round:

    14:02:05  gateway 2ms   1.1.1.1 8ms   8.8.8.8 9ms   dns 14ms

`nethelper wifi monitor` - samples the Wi-Fi connection: signal (dBm),
access point (BSSID), channel and link rate. A BSSID change is a ROAM (moved
to another AP); losing the SSID is a DROP. Ideal for walk-around checks
("signal dies by the conference room") and roaming complaints.

Both: state changes are highlighted and written to the run log with
timestamps; --csv appends every sample for graphing; Ctrl+C (or --duration)
ends with a summary.
"""

from __future__ import annotations

import csv
import datetime as dt
import logging
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from nethelper.core.console import Console
from nethelper.core.result import Status
from nethelper.net import icmp

log = logging.getLogger("nethelper.monitor")


@dataclass
class Track:
    """Running statistics and outage history for one monitored target."""

    name: str
    sent: int = 0
    lost: int = 0
    rtts: list[float] = field(default_factory=list)
    down_since: float | None = None
    outages: list[tuple[float, float]] = field(default_factory=list)

    def record(self, ok: bool, rtt: float | None, now: float) -> str | None:
        """Add one sample; return "down"/"up" on a state change, else None."""
        self.sent += 1
        if ok:
            if rtt is not None:
                self.rtts.append(rtt)
            if self.down_since is not None:
                self.outages.append((self.down_since, now))
                self.down_since = None
                return "up"
            return None
        self.lost += 1
        if self.down_since is None:
            self.down_since = now
            return "down"
        return None


def _dns_probe(name: str) -> tuple[bool, float | None]:
    """Time one OS-resolver lookup (what applications experience)."""
    started = time.perf_counter()
    try:
        socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
        return True, (time.perf_counter() - started) * 1000
    except OSError:
        return False, None


class _CsvLog:
    """Optional CSV writer (header written once for new files)."""

    def __init__(self, path: Path | None, header: list[str]):
        self.fh = None
        if path:
            new = not path.exists()
            self.fh = path.open("a", newline="", encoding="utf-8")
            self.writer = csv.writer(self.fh)
            if new:
                self.writer.writerow(header)

    def row(self, values: list) -> None:
        if self.fh:
            self.writer.writerow(values)
            self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def run(con: Console, targets: list[tuple[str, str, str | None]], dns_name: str | None, interval: float,
        duration: float | None, csv_path: Path | None, timeout: float = 2.0) -> int:
    """
    Monitor until Ctrl+C or `duration` seconds. `targets` is a list of
    (label, host, source IP or None). Returns 0 if no outages, 1 otherwise.
    """
    tracks = {label: Track(label) for label, _, _ in targets}
    if dns_name:
        tracks["dns"] = Track("dns")
    resolved: dict[str, str | None] = {}
    for _, host, _ in targets:
        if host not in resolved:
            try:
                resolved[host] = icmp.resolve(host)[0]  # resolve once: DNS problems are measured separately
            except (OSError, ValueError):
                resolved[host] = None
    out = _CsvLog(csv_path, ["timestamp", *[f"{t}_ms" for t in tracks]])
    con.print(con.c(f"Monitoring {', '.join(tracks)} every {interval:g}s - press Ctrl+C to stop", "bold"))
    log.info("monitor started: %s every %ss", list(tracks), interval)
    started = time.monotonic()
    try:
        while duration is None or time.monotonic() - started < duration:
            round_start = time.monotonic()
            now = time.time()
            cells, row = [], [dt.datetime.now().isoformat(timespec="seconds")]
            for label, host, src in targets:
                ip = resolved.get(host)
                reply = icmp.echo(ip, timeout=timeout, source=src) if ip else None
                ok = bool(reply and reply.status == icmp.OK)
                rtt = reply.rtt_ms if ok and reply else None
                cells.append(_cell(con, label, ok, rtt, tracks[label].record(ok, rtt, now)))
                row.append(f"{rtt:.1f}" if rtt else "")
            if dns_name:
                ok, took = _dns_probe(dns_name)
                cells.append(_cell(con, "dns", ok, took, tracks["dns"].record(ok, took, now)))
                row.append(f"{took:.1f}" if ok and took else "")
            con.print(con.c(time.strftime("%H:%M:%S"), "grey") + "  " + "   ".join(cells))
            out.row(row)
            time.sleep(max(0.0, interval - (time.monotonic() - round_start)))
    except KeyboardInterrupt:
        con.print("")
    finally:
        out.close()
    return _summary(con, tracks)


def _cell(con: Console, label: str, ok: bool, rtt: float | None, change: str | None) -> str:
    """Format one target's result for the live line, logging state changes."""
    if change == "down":
        log.warning("monitor: %s DOWN", label)
        return con.c(f"{label} DOWN", "red", "bold")
    if change == "up":
        log.warning("monitor: %s back UP", label)
        return con.c(f"{label} UP {rtt or 0:.0f}ms", "green", "bold")
    if not ok:
        return con.c(f"{label} --", "red")
    return f"{label} {rtt:.0f}ms" if rtt is not None else f"{label} ok"


def _summary(con: Console, tracks: dict[str, Track]) -> int:
    """Print the end-of-run summary table and return the exit code."""
    end = time.time()
    con.heading("Monitor summary")
    rows = []
    any_outage = False
    for t in tracks.values():
        if t.down_since is not None:
            t.outages.append((t.down_since, end))
        loss = 100 * t.lost / t.sent if t.sent else 0
        avg = sum(t.rtts) / len(t.rtts) if t.rtts else None
        rows.append([t.name, t.sent, f"{loss:.1f}%", f"{avg:.1f}" if avg else "-",
                     f"{max(t.rtts):.1f}" if t.rtts else "-", len(t.outages)])
        any_outage = any_outage or bool(t.outages)
        log.info("monitor summary %s: %d samples, %.1f%% loss, %d outage(s)", t.name, t.sent, loss, len(t.outages))
    con.table(["target", "samples", "loss", "avg ms", "max ms", "outages"], rows)
    for t in tracks.values():
        for start, stop in t.outages:
            con.print(f"  {con.badge(Status.FAIL)} {t.name} down at {dt.datetime.fromtimestamp(start):%H:%M:%S} "
                      f"for {stop - start:.0f}s")
    return 1 if any_outage else 0


def wifi_monitor(con: Console, interval: float, duration: float | None, csv_path: Path | None) -> int:
    """
    Sample the Wi-Fi connection until Ctrl+C / duration. Prints signal, AP,
    channel and rate each sample; flags roams (BSSID change) and drops (no
    association). Returns 0 if no drops, 1 otherwise.
    """
    from nethelper.net import wifi

    out = _CsvLog(csv_path, ["timestamp", "ssid", "bssid", "rssi_dbm", "signal_pct", "channel", "rx_mbps", "tx_mbps"])
    con.print(con.c(f"Wi-Fi monitor every {interval:g}s - walk around if surveying; Ctrl+C to stop", "bold"))
    rssis: list[int] = []
    roams: list[tuple[str, str, str]] = []
    drops: list[str] = []
    last_bssid, connected = None, None
    started = time.monotonic()
    try:
        while duration is None or time.monotonic() - started < duration:
            t0 = time.monotonic()
            stamp = time.strftime("%H:%M:%S")
            infos = [w for w in wifi.current() if w.ssid or w.bssid]
            w = infos[0] if infos else None
            if w is None:
                if connected is True:  # only a drop if we were connected before
                    drops.append(stamp)
                    log.warning("wifi monitor: disconnected at %s", stamp)
                con.print(con.c(stamp, "grey") + "  " + con.c("NOT CONNECTED", "red", "bold"))
                connected = False
                out.row([dt.datetime.now().isoformat(timespec="seconds"), "", "", "", "", "", "", ""])
            else:
                note = ""
                if connected is False:
                    note = con.c("  RECONNECTED", "green", "bold")
                elif last_bssid and w.bssid and w.bssid != last_bssid:
                    roams.append((stamp, last_bssid, w.bssid))
                    note = con.c(f"  ROAMED from {last_bssid}", "yellow", "bold")
                    log.warning("wifi monitor: roamed %s -> %s at %s", last_bssid, w.bssid, stamp)
                connected, last_bssid = True, w.bssid or last_bssid
                if w.rssi_dbm is not None:
                    rssis.append(w.rssi_dbm)
                color = "green" if (w.rssi_dbm or -100) >= -67 else "yellow" if (w.rssi_dbm or -100) >= -75 else "red"
                sig = con.c(f"{w.rssi_dbm} dBm", color) if w.rssi_dbm is not None else "? dBm"
                con.print(f"{con.c(stamp, 'grey')}  {w.ssid}  {sig} ({w.signal_pct}%)  ch {w.channel}  "
                          f"{w.rx_mbps or '-'}/{w.tx_mbps or '-'} Mb/s  AP {w.bssid}{note}")
                out.row([dt.datetime.now().isoformat(timespec="seconds"), w.ssid, w.bssid, w.rssi_dbm, w.signal_pct,
                         w.channel, w.rx_mbps, w.tx_mbps])
            time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    except KeyboardInterrupt:
        con.print("")
    finally:
        out.close()
    con.heading("Wi-Fi monitor summary")
    if rssis:
        con.kv("signal", f"min {min(rssis)} / avg {sum(rssis) / len(rssis):.0f} / max {max(rssis)} dBm over {len(rssis)} samples")
    con.kv("roams", len(roams))
    for stamp, a, b in roams:
        con.print(f"    {stamp}: {a} -> {b}")
    con.kv("drop-outs", len(drops))
    for stamp in drops:
        con.print(f"    {con.badge(Status.FAIL)} disconnected at {stamp}")
    if rssis and min(rssis) < -75:
        con.print(con.c("  Signal fell below -75 dBm: expect slowness/drops there. Add or move an access point.", "yellow"))
    return 1 if drops else 0
