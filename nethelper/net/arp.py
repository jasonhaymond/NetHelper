"""
ARP: find the hardware (MAC) address behind a local IP, and sweep a subnet
to list the devices on it.

ARP ("Address Resolution Protocol") is how a computer on an Ethernet/Wi-Fi
LAN asks "who has 192.168.1.1? tell me your MAC". Every device must answer
ARP to communicate, even ones whose firewall ignores ping - so an ARP answer
is the most reliable "this device exists on my LAN" signal.

Non-admin methods:
  Windows      SendARP() from iphlpapi.dll via ctypes (no elevation needed).
  Linux/macOS  send a harmless UDP packet to the IP (port 9 = "discard"),
               which makes the OS perform ARP, then read the neighbour table.

The LAN sweep combines ARP, ping and TCP connects to common ports, so devices
that block one method are still found. It is "intrusive" (it touches every
address in the range, which security tools may flag) and therefore only runs
when explicitly requested.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from nethelper.core import cmd
from nethelper.net import icmp, oui
from nethelper.system.model import normalize_mac

SWEEP_PORTS = [22, 80, 443, 445, 3389, 8080, 9100]  # SSH, web, SMB, RDP, alt-web, printers


@dataclass
class Host:
    """A device found on the LAN and how it was detected."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    ping_ms: float | None = None
    open_ports: list[int] | None = None
    methods: list[str] | None = None


def _sendarp_windows(ip: str) -> str | None:
    """Windows: resolve a MAC with SendARP (blocks up to ~3 s if no answer)."""
    import ctypes

    dest = int.from_bytes(socket.inet_aton(ip), "little")
    mac_buf = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(8)
    ret = ctypes.WinDLL("iphlpapi.dll").SendARP(ctypes.c_uint32(dest), ctypes.c_uint32(0),
                                                ctypes.byref(mac_buf), ctypes.byref(length))
    if ret != 0 or length.value < 6:
        return None
    return normalize_mac(":".join(f"{b:02x}" for b in bytes(mac_buf)[: length.value]))


def _neighbor_lookup_posix(ip: str) -> str | None:
    """Read one IP's MAC from the OS neighbour table (Linux `ip neigh`, macOS `arp -n`)."""
    if sys.platform.startswith("linux") and cmd.which("ip"):
        res = cmd.run(["ip", "neigh", "show", ip], timeout=5)
        # Regex: "lladdr aa:bb:cc:dd:ee:ff" in `ip neigh` output.
        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", res.stdout)
        if m and "FAILED" not in res.stdout:
            return normalize_mac(m.group(1))
        return None
    res = cmd.run(["arp", "-n", ip], timeout=5)
    # Regex: a MAC like a:b:c:d:e:f (macOS prints without leading zeros) after " at ".
    m = re.search(r" at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", res.stdout)
    if not m:
        return None
    return normalize_mac(":".join(p.zfill(2) for p in m.group(1).split(":")))


def resolve_mac(ip: str, timeout: float = 1.0) -> str | None:
    """Return the MAC address for a same-subnet IPv4 address, or None."""
    if sys.platform == "win32":
        try:
            return _sendarp_windows(ip)
        except OSError:
            return None
    try:
        # Any packet to the IP forces ARP resolution; port 9 is the "discard" service.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (ip, 9))
    except OSError:
        pass
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        mac = _neighbor_lookup_posix(ip)
        if mac:
            return mac
        time.sleep(0.2)
    return None


def _probe(ip: str, timeout: float, ports: list[int]) -> Host | None:
    """Try ARP (same subnet), ping, then common TCP ports on one address."""
    host = Host(ip=ip, methods=[], open_ports=[])
    reply = icmp.echo(ip, timeout=timeout)
    if reply.status == icmp.OK:
        host.ping_ms = reply.rtt_ms
        host.methods.append("icmp")
    mac = resolve_mac(ip, timeout=min(timeout, 1.0))
    if mac:
        host.mac = mac
        host.vendor = oui.vendor(mac)
        host.methods.append("arp")
    if not host.methods:
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=min(timeout, 0.6)):
                    host.open_ports.append(port)
            except ConnectionRefusedError:
                host.methods.append("tcp-rst")  # a refusal still proves the host exists
                break
            except OSError:
                continue
        if host.open_ports:
            host.methods.append("tcp")
    if not host.methods:
        return None
    try:
        host.hostname = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        pass
    return host


def sweep(network: ipaddress.IPv4Network, timeout: float = 1.0, workers: int = 64,
          ports: list[int] | None = None) -> list[Host]:
    """
    Probe every host address in `network` (already size-checked by
    validate.cidr) concurrently. Returns live hosts sorted by IP.
    """
    ports = SWEEP_PORTS if ports is None else ports
    addrs = [str(a) for a in network.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [h for h in pool.map(lambda a: _probe(a, timeout, ports), addrs) if h]
    return sorted(found, key=lambda h: ipaddress.ip_address(h.ip))
