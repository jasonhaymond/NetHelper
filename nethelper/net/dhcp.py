"""
DHCP server discovery: find every DHCP server answering on this network
segment, to catch a *rogue* one.

A rogue DHCP server (a home router plugged in backwards, a misconfigured VM,
or an attacker) hands out wrong gateways/DNS and causes intermittent,
maddening outages for whoever's lease it grabs. Detection: broadcast a DHCP
DISCOVER and list every server that sends an OFFER.

Safety: we send only DISCOVER and never the follow-up REQUEST, so no lease is
taken and the machine's real address is untouched. Servers may briefly
earmark an address for us; it's released when we don't follow up.

Privileges: DHCP clients listen on UDP port 68. Binding it needs root on
Linux, and on Windows the DHCP Client service usually holds it. When we can't
bind, the check reports that clearly instead of guessing.
"""

from __future__ import annotations

import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

from nethelper.net.pcap import DHCP_TYPES


@dataclass
class Offer:
    """One DHCP OFFER: who sent it and what it proposed."""

    server_id: str | None
    from_ip: str
    offered_ip: str
    subnet_mask: str | None = None
    routers: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    domain: str | None = None
    lease_s: int | None = None


def build_discover(mac: bytes, xid: int) -> bytes:
    """
    Build a DHCPDISCOVER packet (RFC 2131 layout):
    op=1 (request), htype=1 (Ethernet), hlen=6, hops=0, transaction id,
    secs=0, flags=0x8000 (ask servers to *broadcast* the reply, since we have
    no address yet), four zeroed address fields, client MAC padded to 16
    bytes, 192 zero bytes (sname/file), magic cookie, then options.
    """
    header = struct.pack("!BBBBIHH4s4s4s4s16s192s", 1, 1, 6, 0, xid, 0, 0x8000,
                         b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, mac + b"\0" * 10, b"\0" * 192)
    options = (b"\x63\x82\x53\x63"                 # magic cookie
               + b"\x35\x01\x01"                   # option 53: message type = DISCOVER
               + b"\x37\x06\x01\x03\x06\x0f\x33\x36"  # option 55: request mask, router, DNS, domain, lease, server id
               + b"\x3d\x07\x01" + mac             # option 61: client identifier
               + b"\xff")                          # end
    return header + options


def parse_offer(data: bytes, xid: int, from_ip: str) -> Offer | None:
    """Decode a DHCP reply; return an Offer only for an OFFER matching our transaction id."""
    if len(data) < 240 or data[0] != 2 or struct.unpack("!I", data[4:8])[0] != xid:
        return None
    if data[236:240] != b"\x63\x82\x53\x63":
        return None
    offer = Offer(server_id=None, from_ip=from_ip, offered_ip=socket.inet_ntoa(data[16:20]))
    msg_type = None
    pos = 240
    while pos < len(data):
        code = data[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        length = data[pos + 1]
        value = data[pos + 2: pos + 2 + length]
        pos += 2 + length
        if code == 53 and value:
            msg_type = DHCP_TYPES.get(value[0])
        elif code == 54 and len(value) == 4:
            offer.server_id = socket.inet_ntoa(value)
        elif code == 1 and len(value) == 4:
            offer.subnet_mask = socket.inet_ntoa(value)
        elif code == 3:
            offer.routers = [socket.inet_ntoa(value[i:i + 4]) for i in range(0, len(value) - 3, 4)]
        elif code == 6:
            offer.dns = [socket.inet_ntoa(value[i:i + 4]) for i in range(0, len(value) - 3, 4)]
        elif code == 15:
            offer.domain = value.decode("ascii", errors="replace").strip("\0")[:100]
        elif code == 51 and len(value) == 4:
            offer.lease_s = struct.unpack("!I", value)[0]
    return offer if msg_type == "OFFER" else None


# Security note (B104): a DHCP client MUST listen on all interfaces - offers
# arrive as broadcasts addressed to 255.255.255.255:68, which a socket bound
# to one specific IP never receives. The socket only exists for `timeout`
# seconds and only accepts replies matching our random transaction id.
ANY_ADDRESS = "0.0.0.0"  # nosec B104


def discover(mac: str, timeout: float = 5.0, bind_ip: str = ANY_ADDRESS) -> list[Offer]:
    """
    Broadcast a DISCOVER from `mac` and collect OFFERs for `timeout` seconds.
    Raises PermissionError/OSError if UDP port 68 can't be bound.
    """
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    xid = secrets.randbits(32)
    offers: list[Offer] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((bind_ip, 68))
        sock.sendto(build_discover(mac_bytes, xid), ("255.255.255.255", 67))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(deadline - time.monotonic(), 0.05))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            offer = parse_offer(data, xid, addr[0])
            if offer and not any(o.server_id == offer.server_id and o.from_ip == offer.from_ip for o in offers):
                offers.append(offer)
    return offers
