"""
Packet capture files: read/write pcap and pcapng, decode packets, summarise.

Capture files are what Wireshark, tcpdump, dumpcap and Windows pktmon produce.
NetHelper reads them itself (no Wireshark needed) so it can:
  - find LLDP/CDP frames from the switch (switchport/VLAN discovery)
  - summarise any capture: protocols, top talkers, DNS names queried, DHCP
    exchanges, ARP conflicts, TCP resets, VLAN tags seen

Formats:
  pcap    (classic) 24-byte file header, then [16-byte record header + packet]...
  pcapng  (newer)   a sequence of typed "blocks"; we read Section Header (SHB),
                    Interface Description (IDB), Enhanced Packet (EPB) and
                    Simple Packet (SPB) blocks and skip everything else.
Link types handled: Ethernet (1), Linux "cooked" capture SLL (113) and SLL2
(276), raw IP (101), BSD loopback (0).

SECURITY: capture files and packets are untrusted input (a crafted packet on
the wire could target a parser). Every length is bounds-checked; malformed
data is skipped, never trusted, and reading stops at a packet-count cap.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2 = 0, 1, 101, 113, 276
CDP_MAC = "01:00:0c:cc:cc:cc"
LLDP_ETHERTYPE = 0x88CC
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)  # 802.1Q, 802.1ad (QinQ), legacy QinQ
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
MAX_PACKETS = 500_000


@dataclass
class Packet:
    """One captured frame: timestamp (Unix seconds), link type, raw bytes."""

    ts: float
    linktype: int
    data: bytes


@dataclass
class Decoded:
    """
    The interesting fields of a decoded frame. Anything not present is None.
      l3     - ipv4 / ipv6 / arp / lldp / cdp / other
      proto  - tcp / udp / icmp / icmpv6 / other (for IP packets)
      vlans  - 802.1Q VLAN ids in the frame's tag(s), outermost first
      payload- bytes after the TCP/UDP header (or the L2 payload for LLDP/CDP)
    """

    src_mac: str | None = None
    dst_mac: str | None = None
    vlans: list[int] = field(default_factory=list)
    ethertype: int | None = None
    l3: str = "other"
    src_ip: str | None = None
    dst_ip: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None
    length: int = 0
    payload: bytes = b""
    arp: dict | None = None


def _mac(b: bytes) -> str:
    """Format 6 raw bytes as aa:bb:cc:dd:ee:ff."""
    return ":".join(f"{x:02x}" for x in b)


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

def read(path: str | Path, limit: int = MAX_PACKETS) -> list[Packet]:
    """Read a pcap or pcapng file (auto-detected). Raises ValueError if neither."""
    data = Path(path).read_bytes()
    if len(data) < 4:
        return []
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(data, limit)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _read_pcap(data, limit)
    raise ValueError("not a pcap or pcapng file")


def _read_pcap(data: bytes, limit: int) -> list[Packet]:
    """Classic pcap: detect byte order and micro/nanosecond timestamps from the magic."""
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24:
        return []
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    out, pos = [], 24
    while pos + 16 <= len(data) and len(out) < limit:
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[pos: pos + 16])
        pos += 16
        if incl > 262144 or pos + incl > len(data):  # corrupt or truncated record
            break
        out.append(Packet(sec + frac / (1e9 if nano else 1e6), linktype, data[pos: pos + incl]))
        pos += incl
    return out


def _read_pcapng(data: bytes, limit: int) -> list[Packet]:
    """pcapng: walk blocks, tracking each interface's link type and timestamp units."""
    out: list[Packet] = []
    pos, endian = 0, "<"
    ifaces: list[tuple[int, float]] = []  # (linktype, seconds per timestamp tick)
    while pos + 12 <= len(data) and len(out) < limit:
        btype_raw = data[pos: pos + 4]
        if btype_raw == b"\x0a\x0d\x0d\x0a":  # Section Header: byte-order magic follows
            bom = data[pos + 8: pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        btype, blen = struct.unpack(endian + "II", data[pos: pos + 8])
        if blen < 12 or blen % 4 or pos + blen > len(data):
            break
        body = data[pos + 8: pos + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            resolution = 1e-6
            opt = 8
            while opt + 4 <= len(body):  # look for the if_tsresol option (code 9)
                code, olen = struct.unpack(endian + "HH", body[opt: opt + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[opt + 4]
                    resolution = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opt += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, resolution))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, _ = struct.unpack(endian + "IIIII", body[:20])
            if if_id < len(ifaces) and 20 + cap_len <= len(body):
                linktype, res = ifaces[if_id]
                out.append(Packet(((ts_hi << 32) | ts_lo) * res, linktype, body[20: 20 + cap_len]))
        elif btype == 3 and len(body) >= 4 and ifaces:  # Simple Packet Block (no timestamp)
            orig = struct.unpack(endian + "I", body[:4])[0]
            out.append(Packet(0.0, ifaces[0][0], body[4: 4 + min(orig, len(body) - 4)]))
        pos += blen
    return out


# --------------------------------------------------------------------------
# Writing (used by the raw-socket capture backend)
# --------------------------------------------------------------------------

class PcapWriter:
    """Write a classic little-endian pcap file, one packet at a time."""

    def __init__(self, path: str | Path, linktype: int = LINK_ETHERNET, snaplen: int = 262144):
        self._fh = open(path, "wb")  # noqa: SIM115 - closed in close()
        # Magic, version 2.4, timezone 0, sigfigs 0, snaplen, link type.
        self._fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.count = 0

    def write(self, ts: float, frame: bytes) -> None:
        """Append one frame with its capture timestamp."""
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        self.count += 1

    def close(self) -> None:
        self._fh.close()


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------

def decode(pkt: Packet) -> Decoded:
    """Decode a frame's headers into a Decoded record (never raises)."""
    d = Decoded(length=len(pkt.data))
    try:
        _decode(pkt, d)
    except (struct.error, IndexError, ValueError):
        pass
    return d


def _decode(pkt: Packet, d: Decoded) -> None:
    data = pkt.data
    if pkt.linktype == LINK_ETHERNET:
        if len(data) < 14:
            return
        d.dst_mac, d.src_mac = _mac(data[0:6]), _mac(data[6:12])
        etype = struct.unpack("!H", data[12:14])[0]
        pos = 14
        while etype in VLAN_ETHERTYPES and pos + 4 <= len(data):  # peel off VLAN tags
            tci = struct.unpack("!H", data[pos: pos + 2])[0]
            d.vlans.append(tci & 0x0FFF)  # low 12 bits of the tag = VLAN id
            etype = struct.unpack("!H", data[pos + 2: pos + 4])[0]
            pos += 4
        payload = data[pos:]
    elif pkt.linktype == LINK_SLL:
        if len(data) < 16:
            return
        alen = struct.unpack("!H", data[4:6])[0]
        if alen == 6:
            d.src_mac = _mac(data[6:12])
        etype = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
        if etype == 0x0004:  # ETH_P_802_2: LLC frame (e.g. CDP)
            etype = len(payload)
    elif pkt.linktype == LINK_SLL2:
        if len(data) < 20:
            return
        etype = struct.unpack("!H", data[0:2])[0]
        if data[11] == 6:
            d.src_mac = _mac(data[12:18])
        payload = data[20:]
        if etype == 0x0004:
            etype = len(payload)
    elif pkt.linktype == LINK_RAW:
        etype = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
        payload = data
    elif pkt.linktype == LINK_NULL:
        family = struct.unpack("<I", data[:4])[0]
        etype = 0x0800 if family == 2 else 0x86DD
        payload = data[4:]
    else:
        return
    d.ethertype = etype

    if etype <= 1500:  # 802.3 length field: LLC/SNAP frame
        if payload[:8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" or d.dst_mac == CDP_MAC:
            d.l3 = "cdp"
            d.payload = payload[8:] if payload[:3] == b"\xaa\xaa\x03" else payload
        return
    if etype == LLDP_ETHERTYPE:
        d.l3, d.payload = "lldp", payload
        return
    if etype == 0x0806 and len(payload) >= 28:
        d.l3 = "arp"
        op = struct.unpack("!H", payload[6:8])[0]
        d.arp = {"op": "request" if op == 1 else "reply" if op == 2 else str(op),
                 "sender_mac": _mac(payload[8:14]), "sender_ip": socket.inet_ntoa(payload[14:18]),
                 "target_mac": _mac(payload[18:24]), "target_ip": socket.inet_ntoa(payload[24:28])}
        d.src_ip, d.dst_ip = d.arp["sender_ip"], d.arp["target_ip"]
        return
    if etype == 0x0800 and len(payload) >= 20:
        d.l3 = "ipv4"
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        d.src_ip, d.dst_ip = socket.inet_ntoa(payload[12:16]), socket.inet_ntoa(payload[16:20])
        l4 = payload[ihl:]
    elif etype == 0x86DD and len(payload) >= 40:
        d.l3 = "ipv6"
        proto = payload[6]
        d.src_ip = str(ipaddress.IPv6Address(payload[8:24]))
        d.dst_ip = str(ipaddress.IPv6Address(payload[24:40]))
        l4 = payload[40:]
    else:
        return
    if proto == 6 and len(l4) >= 20:
        d.proto = "tcp"
        d.sport, d.dport = struct.unpack("!HH", l4[:4])
        d.tcp_flags = l4[13]
        d.payload = l4[(l4[12] >> 4) * 4:]
    elif proto == 17 and len(l4) >= 8:
        d.proto = "udp"
        d.sport, d.dport = struct.unpack("!HH", l4[:4])
        d.payload = l4[8:]
    elif proto in (1, 58) and l4:
        d.proto = "icmp" if proto == 1 else "icmpv6"
        d.icmp_type = l4[0]
    else:
        d.proto = str(proto)


def dns_query_name(payload: bytes) -> str | None:
    """Return the question name of a DNS *query* payload, else None."""
    from nethelper.net.dnswire import DnsError, _read_name

    if len(payload) < 17 or payload[2] & 0x80:  # QR bit set = response, skip
        return None
    try:
        return _read_name(payload, 12)[0]
    except DnsError:
        return None


def dhcp_info(payload: bytes) -> dict | None:
    """Decode a DHCP message type, client MAC and server identifier from a UDP payload."""
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":  # DHCP "magic cookie"
        return None
    info = {"client_mac": _mac(payload[28:34]), "your_ip": socket.inet_ntoa(payload[16:20])}
    pos = 240
    while pos < len(payload):
        code = payload[pos]
        if code == 255:  # end
            break
        if code == 0:    # pad
            pos += 1
            continue
        if pos + 1 >= len(payload):
            break
        length = payload[pos + 1]
        value = payload[pos + 2: pos + 2 + length]
        if code == 53 and value:
            info["type"] = DHCP_TYPES.get(value[0], str(value[0]))
        elif code == 54 and len(value) == 4:
            info["server_id"] = socket.inet_ntoa(value)
        pos += 2 + length
    return info


def summarize(packets: list[Packet], top: int = 10) -> dict:
    """
    Produce a troubleshooting-oriented summary of a capture: protocol mix,
    busiest hosts/conversations/ports, VLANs seen, DNS names asked for, DHCP
    exchanges, ARP conflicts (one IP claimed by several MACs) and TCP resets.
    """
    proto_counts: Counter[str] = Counter()
    talkers: Counter[str] = Counter()
    convs: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    vlans: Counter[int] = Counter()
    dns_names: Counter[str] = Counter()
    dhcp: list[dict] = []
    arp_claims: dict[str, set[str]] = {}
    resets = 0
    icmp_unreach = 0
    total_bytes = 0
    for pkt in packets:
        d = decode(pkt)
        total_bytes += d.length
        label = d.proto if d.l3 in ("ipv4", "ipv6") and d.proto else d.l3
        proto_counts[label] += 1
        for v in d.vlans:
            vlans[v] += 1
        if d.src_ip:
            talkers[d.src_ip] += d.length
        if d.src_ip and d.dst_ip and d.l3 in ("ipv4", "ipv6"):
            a, b = sorted([d.src_ip, d.dst_ip])
            convs[f"{a} <-> {b}"] += d.length
        if d.dport is not None and d.proto in ("tcp", "udp"):
            ports[f"{d.proto}/{min(d.sport or 0, d.dport)}"] += 1
        if d.proto == "udp" and 53 in (d.sport, d.dport):
            name = dns_query_name(d.payload)
            if name:
                dns_names[name] += 1
        if d.proto == "udp" and {d.sport, d.dport} & {67, 68}:
            info = dhcp_info(d.payload)
            if info:
                info["src_ip"] = d.src_ip
                dhcp.append(info)
        if d.arp and d.arp["op"] == "reply" or (d.arp and d.arp["sender_ip"] == d.arp["target_ip"]):
            arp_claims.setdefault(d.arp["sender_ip"], set()).add(d.arp["sender_mac"])
        if d.proto == "tcp" and d.tcp_flags is not None and d.tcp_flags & 0x04:  # RST flag
            resets += 1
        if (d.proto == "icmp" and d.icmp_type == 3) or (d.proto == "icmpv6" and d.icmp_type == 1):
            icmp_unreach += 1
    times = [p.ts for p in packets if p.ts]
    return {
        "packets": len(packets),
        "bytes": total_bytes,
        "duration_s": round(max(times) - min(times), 2) if len(times) > 1 else 0,
        "protocols": dict(proto_counts.most_common()),
        "top_talkers": talkers.most_common(top),
        "top_conversations": convs.most_common(top),
        "top_ports": ports.most_common(top),
        "vlans_seen": dict(vlans.most_common()),
        "dns_queries": dns_names.most_common(top * 2),
        "dhcp": dhcp[:50],
        "arp_conflicts": {ip: sorted(macs) for ip, macs in arp_claims.items() if len(macs) > 1},
        "tcp_resets": resets,
        "icmp_unreachable": icmp_unreach,
    }
