"""
Passive-style LAN service discovery with mDNS/Bonjour and SSDP/UPnP.

Printers, NAS boxes, smart TVs, Chromecasts, Sonos speakers, IP cameras and
Macs announce themselves with these protocols. Asking "who's out there?" lists
them by name and service type without scanning anything.

  mDNS (multicast DNS, a.k.a. Bonjour/Zeroconf): DNS-format queries sent to
        224.0.0.251 port 5353. We ask for "_services._dns-sd._udp.local"
        (the list of all service types), then for instances of each type.
        The "QU" bit asks devices to reply directly to us, so no special port
        binding (and no admin rights) are needed.
  SSDP (UPnP discovery): an HTTP-like "M-SEARCH" sent to 239.255.255.250
        port 1900; devices reply with SERVER / LOCATION / ST headers.

Replies are untrusted network data and are sanitised before display.
Multicast stays on the local network segment (it doesn't cross routers).
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field

from nethelper.core.validate import safe_text
from nethelper.net import dnswire

MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)


@dataclass
class MdnsDevice:
    """One device answering mDNS: its IP, the names it uses, the services it offers."""

    ip: str
    names: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)


def _mdns_round(sock: socket.socket, name: str, timeout: float, found: dict[str, MdnsDevice]) -> set[str]:
    """Send one mDNS PTR query and collect replies until timeout. Returns PTR targets seen."""
    _, packet = dnswire.build_query(name, "PTR", qid=0, recursion=False, unicast_response=True)
    sock.sendto(packet, MDNS_ADDR)
    targets: set[str] = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock.settimeout(max(deadline - time.monotonic(), 0.05))
        try:
            data, addr = sock.recvfrom(9000)
        except socket.timeout:
            break
        except OSError:
            continue
        try:
            resp = dnswire.parse_response(data)
        except dnswire.DnsError:
            continue
        dev = found.setdefault(addr[0], MdnsDevice(ip=addr[0]))
        for rec in resp.answers + resp.authority:
            if rec.rtype == "PTR":
                targets.add(rec.value)
                if rec.name != "_services._dns-sd._udp.local":
                    dev.services.add(safe_text(rec.name.replace(".local", ""), 80))
                    dev.names.add(safe_text(rec.value.split("._")[0], 80))
            elif rec.rtype in ("A", "AAAA", "SRV"):
                dev.names.add(safe_text(rec.name.replace(".local", ""), 80))
    return targets


def mdns_browse(timeout: float = 3.0, max_types: int = 25) -> list[MdnsDevice]:
    """Discover mDNS service types, then their instances. Returns devices by IP."""
    found: dict[str, MdnsDevice] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)  # mDNS spec requires TTL 255
        sock.bind(("", 0))
        types = _mdns_round(sock, "_services._dns-sd._udp.local", timeout, found)
        for stype in sorted(types)[:max_types]:
            if stype.endswith(".local"):
                _mdns_round(sock, stype, min(timeout, 1.0), found)
    return sorted(found.values(), key=lambda d: socket.inet_aton(d.ip) if d.ip.count(".") == 3 else b"\xff")


def parse_ssdp(data: bytes) -> dict[str, str]:
    """Parse an SSDP reply (HTTP-style headers) into a lower-cased header dict."""
    headers: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = safe_text(value.strip(), 200)
    return headers


def ssdp_search(timeout: float = 3.0) -> list[dict]:
    """Broadcast an SSDP M-SEARCH and return one entry per responding device."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode("ascii")
    devices: dict[str, dict] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))
        sock.bind(("", 0))
        sock.sendto(msg, SSDP_ADDR)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(deadline - time.monotonic(), 0.05))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                continue
            h = parse_ssdp(data)
            dev = devices.setdefault(addr[0], {"ip": addr[0], "server": h.get("server"),
                                               "location": h.get("location"), "types": set()})
            if h.get("st"):
                dev["types"].add(h["st"])
    out = []
    for dev in devices.values():
        dev["types"] = sorted(dev["types"])[:10]
        out.append(dev)
    return sorted(out, key=lambda d: socket.inet_aton(d["ip"]))
