"""
Packet capture through whichever method is available on this machine.

Capturing raw traffic always needs special permission, because it can see
other people's traffic. Supported backends, tried in this order:

  dumpcap / tshark  Wireshark's capture engine (any OS). Non-admin works if
                    Npcap was installed without "restrict to Administrators"
                    (Windows), the user is in the `wireshark` group (Linux), or
                    ChmodBPF is installed (macOS).
  tcpdump           Linux/macOS; root (or readable /dev/bpf* on macOS).
  pktmon            Built into Windows 10 2004+/11; Administrator only.
                    NOTE: pktmon's packet filters are machine-wide state. We
                    refuse to run if someone else has filters configured, so we
                    never clobber another person's capture setup.
  rawsocket         Linux only, built into Python (AF_PACKET); root only.

Filters are chosen from simple presets (dns, dhcp, arp, icmp, lldp, cdp,
l2discovery, vlan, host:IP, port:N, tcp, udp, all) and translated for each
backend. A raw BPF expression (tcpdump syntax) can be passed for the
dumpcap/tcpdump backends. All inputs are validated (validate.py) and passed
as separate arguments - never through a shell.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from nethelper.core import cmd, validate
from nethelper.core.paths import sub_dir
from nethelper.core.privileges import Capabilities
from nethelper.net import pcap

log = logging.getLogger("nethelper.capture")

# Preset -> BPF filter expression (tcpdump/dumpcap syntax).
BPF_PRESETS = {
    "all": "",
    "dns": "port 53",
    "dhcp": "udp port 67 or udp port 68",
    "arp": "arp",
    "icmp": "icmp or icmp6",
    "lldp": "ether proto 0x88cc",
    "cdp": "ether dst 01:00:0c:cc:cc:cc",
    "l2discovery": "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc",
    "vlan": "vlan",
    "tcp": "tcp",
    "udp": "udp",
}
# Preset -> list of pktmon filter definitions (multiple filters are OR'ed).
PKTMON_PRESETS: dict[str, list[list[str]]] = {
    "all": [],
    "dns": [["-t", "UDP", "-p", "53"], ["-t", "TCP", "-p", "53"]],
    "dhcp": [["-t", "UDP", "-p", "67"], ["-t", "UDP", "-p", "68"]],
    "arp": [["-d", "ARP"]],
    "icmp": [["-t", "ICMP"], ["-t", "ICMPv6"]],
    "lldp": [["-d", str(pcap.LLDP_ETHERTYPE)]],
    "cdp": [["-m", "01-00-0C-CC-CC-CC"]],
    "l2discovery": [["-d", str(pcap.LLDP_ETHERTYPE)], ["-m", "01-00-0C-CC-CC-CC"]],
    "vlan": [],
    "tcp": [["-t", "TCP"]],
    "udp": [["-t", "UDP"]],
}


@dataclass
class CaptureSpec:
    """
    What to capture.
      interface - adapter name (None = the default-route adapter / all)
      duration  - seconds to capture
      count     - stop after this many matching packets (0 = no limit)
      preset    - filter preset name, or "host:<ip>" / "port:<n>"
      bpf       - optional raw BPF expression (dumpcap/tcpdump only)
      outfile   - where to write the capture (temp file if None)
      backend   - force a specific backend (None = best available)
    """

    interface: str | None = None
    duration: float = 30
    count: int = 0
    preset: str = "all"
    bpf: str | None = None
    outfile: Path | None = None
    backend: str | None = None
    outdir: Path | None = None  # folder for auto-named files (NETHELPER_CAPTURE_DIR)


@dataclass
class CaptureResult:
    """Outcome: success flag, backend used, capture file, packets read back, notes."""

    ok: bool
    backend: str | None = None
    file: Path | None = None
    packets: list[pcap.Packet] = field(default_factory=list)
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    transcript: str = ""


def bpf_for(spec: CaptureSpec) -> str:
    """Translate the spec's preset (or raw BPF) into one BPF expression."""
    if spec.bpf:
        return validate.bpf_filter(spec.bpf)
    preset = spec.preset
    if preset.startswith("host:"):
        return f"host {validate.hostname(preset[5:])}"
    if preset.startswith("port:"):
        return f"port {validate.port(preset[5:])}"
    if preset not in BPF_PRESETS:
        raise validate.ValidationError(f"unknown capture preset {preset!r}; choose from "
                                       f"{', '.join(BPF_PRESETS)}, host:<ip>, port:<n>")
    return BPF_PRESETS[preset]


def predicate_for(preset: str) -> Callable[[pcap.Decoded], bool]:
    """
    Python-side version of each preset, used by the raw-socket backend (which
    has no kernel filter) and to post-filter pktmon captures.
    """
    if preset.startswith("host:"):
        target = validate.hostname(preset[5:])
        return lambda d: target in (d.src_ip, d.dst_ip)
    if preset.startswith("port:"):
        num = validate.port(preset[5:])
        return lambda d: num in (d.sport, d.dport)
    table: dict[str, Callable[[pcap.Decoded], bool]] = {
        "all": lambda d: True,
        "dns": lambda d: 53 in (d.sport, d.dport),
        "dhcp": lambda d: d.proto == "udp" and bool({d.sport, d.dport} & {67, 68}),
        "arp": lambda d: d.l3 == "arp",
        "icmp": lambda d: d.proto in ("icmp", "icmpv6"),
        "lldp": lambda d: d.l3 == "lldp",
        "cdp": lambda d: d.l3 == "cdp",
        "l2discovery": lambda d: d.l3 in ("lldp", "cdp"),
        "vlan": lambda d: bool(d.vlans),
        "tcp": lambda d: d.proto == "tcp",
        "udp": lambda d: d.proto == "udp",
    }
    return table.get(preset, table["all"])


def available_backends(caps: Capabilities) -> list[str]:
    """Names of backends that should work right now, best first."""
    return [name for name, usable, _ in caps.capture_backends() if usable]


# --------------------------------------------------------------------------
# dumpcap / tshark
# --------------------------------------------------------------------------

# Regex: one line of `dumpcap -D`, e.g. "3. \Device\NPF_{GUID} (Wi-Fi)" or "1. eth0".
_DUMPCAP_IF = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?")


def _dumpcap_index(tool: str, interface: str | None) -> str | None:
    """Map a friendly adapter name to dumpcap's interface number."""
    if not interface:
        return None
    res = cmd.run([tool, "-D"], timeout=20)
    for line in res.stdout.splitlines():
        m = _DUMPCAP_IF.match(line)
        if m and interface.lower() in {m.group(2).lower(), (m.group(3) or "").lower()}:
            return m.group(1)
    return interface


def _capture_dumpcap(tool: str, spec: CaptureSpec, out: Path) -> CaptureResult:
    argv = [tool, "-q", "-w", str(out), "-a", f"duration:{int(spec.duration)}"]
    idx = _dumpcap_index(tool, spec.interface)
    if idx:
        argv += ["-i", idx]
    if spec.count:
        argv += ["-c", str(spec.count)]
    expr = bpf_for(spec)
    if expr:
        argv += ["-f", expr]
    res = cmd.run(argv, timeout=spec.duration + 30)
    ok = out.exists() and out.stat().st_size > 0
    err = None if ok else (res.error or res.stderr.strip()[:300] or "capture produced no file")
    if err and "permission" in err.lower():
        err += " - run elevated, or allow non-admin capture in Npcap/wireshark group"
    return CaptureResult(ok, tool, out if ok else None, error=err, transcript=res.transcript())


# --------------------------------------------------------------------------
# tcpdump
# --------------------------------------------------------------------------

def _capture_tcpdump(spec: CaptureSpec, out: Path) -> CaptureResult:
    argv = ["tcpdump", "-n", "-U", "-s", "0", "-w", str(out), "-i",
            validate.interface(spec.interface) if spec.interface else "any"]
    if spec.count:
        argv += ["-c", str(spec.count)]
    expr = bpf_for(spec)
    if expr:
        argv.append(expr)  # one argument; tcpdump reads it as the filter expression
    try:
        proc = cmd.Background(argv)
    except (FileNotFoundError, OSError) as exc:
        return CaptureResult(False, "tcpdump", error=str(exc))
    try:
        proc.wait(spec.duration)  # returns early if -c count was reached
    finally:
        res = proc.stop()  # always stop tcpdump - even on Ctrl+C
    ok = out.exists() and out.stat().st_size > 24
    err = None if ok else (res.stderr.strip()[:300] or "no packets captured")
    if err and ("permission" in err.lower() or "operation not permitted" in err.lower()):
        err += " - run with sudo"
    result = CaptureResult(ok or out.exists(), "tcpdump", out if out.exists() else None, error=err,
                           transcript=res.transcript())
    if result.ok and not ok:
        result.notes.append("no matching packets were seen during the capture window")
        result.error = None
    return result


# --------------------------------------------------------------------------
# pktmon (Windows)
# --------------------------------------------------------------------------

def _pktmon_has_foreign_filters() -> tuple[bool, str]:
    """True if pktmon already has filters that someone else configured."""
    res = cmd.run(["pktmon", "filter", "list"], timeout=15)
    # Regex: a numbered filter row, e.g. " 1 MyFilter  0x0800 ..." (header rows don't start with a digit).
    rows = [ln for ln in res.stdout.splitlines() if re.match(r"^\s*\d+\s+\S", ln)]
    foreign = [r for r in rows if "NetHelper" not in r]
    return bool(foreign), res.stdout


def _capture_pktmon(spec: CaptureSpec, out: Path) -> CaptureResult:
    transcript: list[str] = []
    foreign, listing = _pktmon_has_foreign_filters()
    if foreign:
        return CaptureResult(False, "pktmon", error="pktmon already has packet filters configured by someone "
                             "else; not touching them. Run 'pktmon filter list' to review, "
                             "'pktmon filter remove' to clear, then retry.", transcript=listing)
    status = cmd.run(["pktmon", "status"], timeout=15)
    if "not running" not in status.stdout.lower() and "running" in status.stdout.lower():
        return CaptureResult(False, "pktmon", error="pktmon is already capturing (another session?). "
                             "Run 'pktmon stop' first.", transcript=status.transcript())
    etl = out.with_suffix(".etl")
    preset = spec.preset if spec.preset in PKTMON_PRESETS else "all"
    filters = list(PKTMON_PRESETS[preset])
    if spec.preset.startswith("host:"):
        filters = [["-i", validate.hostname(spec.preset[5:])]]
    elif spec.preset.startswith("port:"):
        filters = [["-p", str(validate.port(spec.preset[5:]))]]
    def cleanup() -> None:
        """Stop the pktmon session and remove our filters (also used on Ctrl+C)."""
        transcript.append(cmd.run(["pktmon", "stop"], timeout=60).transcript())
        cmd.run(["pktmon", "filter", "remove"], timeout=15)

    cmd.register_cleanup(cleanup)  # stop_all() runs it if we're interrupted
    try:
        cmd.run(["pktmon", "filter", "remove"], timeout=15)
        for n, flt in enumerate(filters):
            r = cmd.run(["pktmon", "filter", "add", f"NetHelper{n}", *flt], timeout=15)
            transcript.append(r.transcript())
        start = cmd.run(["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                         "--file-name", str(etl)], timeout=30)
        transcript.append(start.transcript())
        if not start.ok:
            return CaptureResult(False, "pktmon", error=f"pktmon start failed: {(start.stdout or start.error or '').strip()[:300]}",
                                 transcript="\n".join(transcript))
        time.sleep(spec.duration)
    finally:
        cmd.unregister_cleanup(cleanup)
        cleanup()
    conv = cmd.run(["pktmon", "etl2pcap", str(etl), "--out", str(out)], timeout=120)
    transcript.append(conv.transcript())
    try:
        etl.unlink(missing_ok=True)
    except OSError:
        pass
    ok = out.exists()
    result = CaptureResult(ok, "pktmon", out if ok else None,
                           error=None if ok else "pktmon did not produce a capture file",
                           transcript="\n".join(transcript))
    if spec.preset == "vlan":
        result.notes.append("Windows NIC drivers usually strip 802.1Q tags before pktmon sees them")
    return result


# --------------------------------------------------------------------------
# Linux raw socket
# --------------------------------------------------------------------------

def _capture_rawsocket(spec: CaptureSpec, out: Path, stop_when: Callable[[pcap.Packet], bool] | None) -> CaptureResult:
    """
    Capture with an AF_PACKET socket (Linux, root). Every frame on the
    interface arrives here; the preset predicate filters in Python.
    """
    eth_p_all = 0x0003  # ETH_P_ALL: receive every protocol
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_p_all))  # type: ignore[attr-defined]
    except (PermissionError, AttributeError, OSError) as exc:
        return CaptureResult(False, "rawsocket", error=f"raw socket unavailable: {exc} (needs root on Linux)")
    match = predicate_for(spec.preset)
    writer = pcap.PcapWriter(out)
    packets: list[pcap.Packet] = []
    try:
        if spec.interface:
            sock.bind((validate.interface(spec.interface), 0))
        deadline = time.monotonic() + spec.duration
        while time.monotonic() < deadline:
            sock.settimeout(max(deadline - time.monotonic(), 0.05))
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                break
            pkt = pcap.Packet(time.time(), pcap.LINK_ETHERNET, frame)
            if not match(pcap.decode(pkt)):
                continue
            writer.write(pkt.ts, frame)
            packets.append(pkt)
            if (spec.count and len(packets) >= spec.count) or (stop_when and stop_when(pkt)):
                break
    finally:
        writer.close()
        sock.close()
    result = CaptureResult(True, "rawsocket", out, packets=packets)
    if spec.preset == "vlan":
        result.notes.append("many NICs strip 802.1Q tags in hardware (VLAN offload); "
                            "try 'ethtool -K <if> rxvlan off' if no tags appear")
    return result


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

# Only one capture at a time: pktmon is a single machine-wide session, and
# parallel checks (switchport + tagged-frame probe) must not collide.
_capture_lock = threading.Lock()


def run_capture(spec: CaptureSpec, caps: Capabilities,
                stop_when: Callable[[pcap.Packet], bool] | None = None) -> CaptureResult:
    """
    Capture packets according to `spec` with the best available backend and
    read the resulting file back. `stop_when` lets the raw-socket backend end
    early (e.g. as soon as an LLDP frame arrives). Captures are serialised.
    """
    with _capture_lock:
        return _run_capture(spec, caps, stop_when)


def _run_capture(spec: CaptureSpec, caps: Capabilities,
                 stop_when: Callable[[pcap.Packet], bool] | None) -> CaptureResult:
    """Implementation of run_capture (called with the capture lock held)."""
    if spec.interface:
        spec.interface = validate.interface(spec.interface)
    bpf_for(spec)  # validates the preset / BPF before anything runs
    backends = [spec.backend] if spec.backend else available_backends(caps)
    if not backends:
        hint = ("install Wireshark (with Npcap on Windows) or run elevated"
                if caps.os == "windows" else "install tcpdump, or run with sudo")
        return CaptureResult(False, error=f"no packet-capture method is usable at this privilege level - {hint}")
    if spec.bpf and backends[0] in ("pktmon", "rawsocket"):
        return CaptureResult(False, backends[0], error="raw BPF filters need dumpcap/tshark/tcpdump; use a --filter preset instead")

    if spec.outfile:
        out = Path(spec.outfile)
    else:
        # Default location: <data dir>/captures/capture-YYYYmmdd-HHMMSS.pcap(ng)
        ext = ".pcapng" if backends[0] in ("dumpcap", "tshark", "pktmon") else ".pcap"
        folder = Path(spec.outdir) if spec.outdir else sub_dir("captures")
        folder.mkdir(parents=True, exist_ok=True)
        out = folder / f"capture-{time.strftime('%Y%m%d-%H%M%S')}-{spec.preset.split(':')[0]}{ext}"
    log.info("capture: backends %s, preset %s, interface %s, %ss -> %s", backends, spec.preset,
             spec.interface or "default", spec.duration, out)
    errors: list[str] = []
    for backend in backends:
        if backend in ("dumpcap", "tshark"):
            result = _capture_dumpcap(backend, spec, out)
        elif backend == "tcpdump":
            result = _capture_tcpdump(spec, out)
        elif backend == "pktmon":
            result = _capture_pktmon(spec, out)
        elif backend == "rawsocket" and sys.platform.startswith("linux"):
            result = _capture_rawsocket(spec, out, stop_when)
        else:
            continue
        if result.ok:
            if not result.packets and result.file:
                try:
                    result.packets = pcap.read(result.file)
                except (OSError, ValueError) as exc:
                    result.notes.append(f"could not read capture back: {exc}")
                if backend == "pktmon" and spec.preset not in ("all",):
                    pred = predicate_for(spec.preset)
                    result.packets = [p for p in result.packets if pred(pcap.decode(p))]
            return result
        errors.append(f"{backend}: {result.error}")
    return CaptureResult(False, error="; ".join(errors))


def is_private(ip: str) -> bool:
    """True for RFC1918/ULA/link-local addresses (used by redaction and summaries)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
