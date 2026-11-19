"""
Parsers for the switch "discovery" protocols LLDP and CDP.

Managed switches periodically send a small frame out of every port announcing
who they are: the switch's name, which port this is, the port's VLAN, the
voice VLAN, PoE budget, speed/duplex, and a management IP. Capturing one of
these frames on a PC answers the classic field questions -
"which switch and port is this wall jack patched to?" and "what VLAN is it in?"
- without access to the switch or tracing cables.

  LLDP (IEEE 802.1AB) - vendor-neutral; Ethernet type 0x88CC, sent to
                        01:80:c2:00:00:0e every 30 s by default. Extensions:
                        IEEE 802.1 (VLANs), IEEE 802.3 (speed/duplex, PoE,
                        frame size), LLDP-MED (voice VLAN / network policy).
  CDP                 - Cisco's protocol (also on some other vendors); an
                        802.3 + SNAP frame to 01:00:0c:cc:cc:cc every 60 s.

Both use a TLV ("type-length-value") layout. All input is untrusted network
data: lengths are bounds-checked and strings sanitised for display.
"""

from __future__ import annotations

import ipaddress
import socket
import struct

from nethelper.core.validate import safe_text
from nethelper.net.pcap import Packet, decode

# LLDP system-capability bits -> names.
LLDP_CAPS = {0x01: "other", 0x02: "repeater", 0x04: "bridge/switch", 0x08: "wlan-ap", 0x10: "router",
             0x20: "telephone", 0x40: "docsis", 0x80: "station", 0x100: "c-vlan", 0x200: "s-vlan"}
# CDP capability bits -> names.
CDP_CAPS = {0x01: "router", 0x02: "tb-bridge", 0x04: "sr-bridge", 0x08: "switch", 0x10: "host",
            0x20: "igmp", 0x40: "repeater", 0x80: "phone", 0x100: "remote", 0x200: "cvta", 0x400: "mac-relay"}
# IEEE 802.3 operational MAU types (RFC 4836) for copper/fibre links seen in practice.
MAU_TYPES = {
    10: ("10BASE-T", "half"), 11: ("10BASE-T", "full"), 15: ("100BASE-TX", "half"),
    16: ("100BASE-TX", "full"), 17: ("100BASE-FX", "half"), 18: ("100BASE-FX", "full"),
    21: ("1000BASE-X", "half"), 22: ("1000BASE-X", "full"), 23: ("1000BASE-LX", "half"),
    24: ("1000BASE-LX", "full"), 25: ("1000BASE-SX", "half"), 26: ("1000BASE-SX", "full"),
    29: ("1000BASE-T", "half"), 30: ("1000BASE-T", "full"),
}
MED_APPS = {1: "voice", 2: "voice-signaling", 3: "guest-voice", 4: "guest-voice-signaling",
            5: "softphone-voice", 6: "video-conferencing", 7: "streaming-video", 8: "video-signaling"}


def _caps(value: int, table: dict[int, str]) -> list[str]:
    """Expand a capability bit field into a list of names."""
    return [name for bit, name in table.items() if value & bit]


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _addr(family: int, raw: bytes) -> str | None:
    """IANA address family 1 = IPv4, 2 = IPv6."""
    try:
        if family == 1 and len(raw) == 4:
            return socket.inet_ntoa(raw)
        if family == 2 and len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
    except (OSError, ValueError):
        pass
    return None


def parse_lldp(payload: bytes) -> dict:
    """
    Decode an LLDP frame body (everything after the Ethernet header) into a
    dict of neighbour information. Unknown TLVs are ignored.
    """
    info: dict = {"protocol": "LLDP", "vlan_names": {}, "mgmt_addresses": [], "network_policies": []}
    pos = 0
    while pos + 2 <= len(payload):
        header = struct.unpack("!H", payload[pos: pos + 2])[0]
        ttype, tlen = header >> 9, header & 0x01FF  # 7-bit type, 9-bit length
        value = payload[pos + 2: pos + 2 + tlen]
        pos += 2 + tlen
        if len(value) < tlen or ttype == 0:  # truncated, or End-of-LLDPDU
            break
        if ttype == 1 and value:  # Chassis ID: subtype then value
            sub, rest = value[0], value[1:]
            info["chassis_id"] = _fmt_mac(rest) if sub == 4 and len(rest) == 6 else (
                _addr(rest[0], rest[1:]) if sub == 5 and rest else safe_text(rest.decode("utf-8", "replace"), 100))
        elif ttype == 2 and value:  # Port ID
            sub, rest = value[0], value[1:]
            info["port_id"] = _fmt_mac(rest) if sub == 3 and len(rest) == 6 else safe_text(
                rest.decode("utf-8", "replace"), 100)
        elif ttype == 3 and len(value) >= 2:
            info["ttl"] = struct.unpack("!H", value[:2])[0]
        elif ttype == 4:
            info["port_description"] = safe_text(value.decode("utf-8", "replace"), 200)
        elif ttype == 5:
            info["system_name"] = safe_text(value.decode("utf-8", "replace"), 200)
        elif ttype == 6:
            info["system_description"] = safe_text(value.decode("utf-8", "replace"), 300)
        elif ttype == 7 and len(value) >= 4:
            system, enabled = struct.unpack("!HH", value[:4])
            info["capabilities"] = _caps(system, LLDP_CAPS)
            info["capabilities_enabled"] = _caps(enabled, LLDP_CAPS)
        elif ttype == 8 and value:  # Management address
            alen = value[0]
            if alen >= 2 and len(value) >= 1 + alen:
                addr = _addr(value[1], value[2: 1 + alen])
                if addr:
                    info["mgmt_addresses"].append(addr)
        elif ttype == 127 and len(value) >= 4:  # Organisationally-specific
            _org_tlv(value[:3], value[3], value[4:], info)
    return info


def _org_tlv(oui: bytes, sub: int, body: bytes, info: dict) -> None:
    """Decode the IEEE 802.1, IEEE 802.3 and LLDP-MED extension TLVs."""
    if oui == b"\x00\x80\xc2":  # IEEE 802.1
        if sub == 1 and len(body) >= 2:
            pvid = struct.unpack("!H", body[:2])[0]
            if pvid:
                info["native_vlan"] = pvid  # Port VLAN ID = untagged/access VLAN
        elif sub == 3 and len(body) >= 3:
            vid, nlen = struct.unpack("!H", body[:2])[0], body[2]
            info["vlan_names"][vid] = safe_text(body[3: 3 + nlen].decode("utf-8", "replace"), 64)
    elif oui == b"\x00\x12\x0f":  # IEEE 802.3
        if sub == 1 and len(body) >= 5:
            autoneg = body[0]
            mau = struct.unpack("!H", body[3:5])[0]
            info["autoneg_supported"] = bool(autoneg & 0x01)
            info["autoneg_enabled"] = bool(autoneg & 0x02)
            name, duplex = MAU_TYPES.get(mau, (f"MAU type {mau}", None))
            info["link_type"] = name
            if duplex:
                info["duplex"] = duplex
        elif sub == 2 and len(body) >= 3:
            poe = {"class": max(body[2] - 1, 0)}  # field stores class+1
            if len(body) >= 7:
                poe["requested_w"] = struct.unpack("!H", body[4:6])[0] / 10 if len(body) >= 6 else None
                poe["allocated_w"] = struct.unpack("!H", body[6:8])[0] / 10 if len(body) >= 8 else None
            info["poe"] = poe
        elif sub == 4 and len(body) >= 2:
            info["max_frame_size"] = struct.unpack("!H", body[:2])[0]
    elif oui == b"\x00\x12\xbb":  # LLDP-MED (phones, voice VLAN)
        if sub == 2 and len(body) >= 4:
            app = body[0]
            bits = int.from_bytes(body[1:4], "big")
            # 24 bits: Unknown(1) Tagged(1) reserved(1) VLAN(12) L2-priority(3) DSCP(6)
            policy = {"application": MED_APPS.get(app, str(app)), "unknown": bool(bits >> 23 & 1),
                      "tagged": bool(bits >> 22 & 1), "vlan": (bits >> 9) & 0xFFF,
                      "priority": (bits >> 6) & 0x7, "dscp": bits & 0x3F}
            info["network_policies"].append(policy)
            if app == 1 and not policy["unknown"] and policy["vlan"]:
                info["voice_vlan"] = policy["vlan"]
        elif sub == 4 and len(body) >= 3:
            info.setdefault("poe", {})["med_power_w"] = struct.unpack("!H", body[1:3])[0] / 10


def _cdp_addresses(value: bytes) -> list[str]:
    """Decode a CDP address list: count(4) then entries of type/len/proto/addrlen/addr."""
    out: list[str] = []
    if len(value) < 4:
        return out
    count = struct.unpack("!I", value[:4])[0]
    pos = 4
    for _ in range(min(count, 16)):
        if pos + 2 > len(value):
            break
        plen = value[pos + 1]
        proto = value[pos + 2: pos + 2 + plen]
        pos += 2 + plen
        if pos + 2 > len(value):
            break
        alen = struct.unpack("!H", value[pos: pos + 2])[0]
        raw = value[pos + 2: pos + 2 + alen]
        pos += 2 + alen
        if proto == b"\xcc" and len(raw) == 4:  # NLPID 0xCC = IPv4
            out.append(socket.inet_ntoa(raw))
        elif len(raw) == 16:
            out.append(str(ipaddress.IPv6Address(raw)))
    return out


def parse_cdp(payload: bytes) -> dict:
    """Decode a CDP packet (starting at the CDP version byte, after LLC/SNAP)."""
    info: dict = {"protocol": "CDP", "mgmt_addresses": []}
    if len(payload) < 4:
        return info
    info["cdp_version"], info["ttl"] = payload[0], payload[1]
    pos = 4
    while pos + 4 <= len(payload):
        ttype, tlen = struct.unpack("!HH", payload[pos: pos + 4])
        if tlen < 4 or pos + tlen > len(payload):
            break
        value = payload[pos + 4: pos + tlen]
        pos += tlen

        def text(raw: bytes = value) -> str:
            """This TLV's value as sanitised text (bound now, not at loop end)."""
            return safe_text(raw.decode("utf-8", "replace").strip("\x00"), 300)

        if ttype == 0x0001:
            info["system_name"] = text()          # Device ID (usually hostname)
            info["chassis_id"] = info["system_name"]
        elif ttype == 0x0002:
            info["addresses"] = _cdp_addresses(value)
        elif ttype == 0x0003:
            info["port_id"] = text()
        elif ttype == 0x0004 and len(value) >= 4:
            info["capabilities"] = _caps(struct.unpack("!I", value[:4])[0], CDP_CAPS)
        elif ttype == 0x0005:
            info["system_description"] = text()   # software version
        elif ttype == 0x0006:
            info["platform"] = text()
        elif ttype == 0x0009:
            info["vtp_domain"] = text()
        elif ttype == 0x000A and len(value) >= 2:
            info["native_vlan"] = struct.unpack("!H", value[:2])[0]
        elif ttype == 0x000B and value:
            info["duplex"] = "full" if value[0] else "half"
        elif ttype == 0x000E and len(value) >= 3:
            info["voice_vlan"] = struct.unpack("!H", value[1:3])[0]
        elif ttype == 0x0011 and len(value) >= 4:
            info["mtu"] = struct.unpack("!I", value[:4])[0]
        elif ttype == 0x0014:
            info["system_name_full"] = text()
        elif ttype == 0x0016:
            info["mgmt_addresses"] = _cdp_addresses(value)
    if not info["mgmt_addresses"] and info.get("addresses"):
        info["mgmt_addresses"] = info["addresses"]
    return info


def find_neighbors(packets: list[Packet]) -> list[dict]:
    """
    Pull every LLDP/CDP announcement out of captured packets and return one
    entry per distinct (protocol, sending switch port), newest data winning.
    Each entry also records the sender's MAC and any 802.1Q tag on the frame.
    """
    found: dict[tuple, dict] = {}
    for pkt in packets:
        d = decode(pkt)
        if d.l3 == "lldp":
            info = parse_lldp(d.payload)
        elif d.l3 == "cdp":
            info = parse_cdp(d.payload)
        else:
            continue
        info["src_mac"] = d.src_mac
        if d.vlans:
            info["frame_vlan_tag"] = d.vlans[0]
        info["seen_at"] = pkt.ts
        key = (info["protocol"], info.get("chassis_id"), info.get("port_id"), d.src_mac)
        found[key] = info
    return list(found.values())
