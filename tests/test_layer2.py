"""
Layer 2 tests: LLDP/CDP decoding (switch name, port, VLANs, PoE, duplex),
pcap/pcapng round trips, packet summaries, DHCP packet handling, and the
switchport/VLAN validation checks using synthetic frames.
"""

from __future__ import annotations

import socket
import struct

from nethelper.core.config import parse_profile
from nethelper.core.result import Status
from nethelper.net import dhcp, l2proto, pcap

SWITCH_MAC = bytes.fromhex("001122334455")


def _tlv(t: int, value: bytes) -> bytes:
    """Encode one LLDP TLV (7-bit type, 9-bit length)."""
    return struct.pack("!H", (t << 9) | len(value)) + value


def lldp_frame(vlan: int = 20, voice: int = 30) -> bytes:
    """Build a realistic LLDP frame like a Cisco/Aruba access switch sends."""
    body = (
        _tlv(1, b"\x04" + SWITCH_MAC)                                   # chassis id (MAC)
        + _tlv(2, b"\x05" + b"Gi1/0/12")                                # port id (ifname)
        + _tlv(3, struct.pack("!H", 120))                               # TTL
        + _tlv(4, b"Office 2.14 desk")                                  # port description
        + _tlv(5, b"core-sw-01")                                        # system name
        + _tlv(6, b"Cisco IOS Software")                                # system description
        + _tlv(7, struct.pack("!HH", 0x14, 0x04))                       # caps: bridge+router, bridge enabled
        + _tlv(8, b"\x05\x01" + socket.inet_aton("10.0.0.2") + b"\x02\x00\x00\x00\x01\x00")  # mgmt IPv4
        + _tlv(127, b"\x00\x80\xc2\x01" + struct.pack("!H", vlan))      # 802.1 PVID
        + _tlv(127, b"\x00\x80\xc2\x03" + struct.pack("!H", vlan) + b"\x04DATA")  # VLAN name
        + _tlv(127, b"\x00\x12\x0f\x01\x03\x6c\x01" + struct.pack("!H", 30))       # MAC/PHY: 1000BASE-T FD
        + _tlv(127, b"\x00\x12\x0f\x02\x07\x01\x04\x51" + struct.pack("!HH", 154, 154))  # PoE class 3, 15.4 W
        + _tlv(127, b"\x00\x12\xbb\x02\x01" + ((1 << 22) | (voice << 9) | (5 << 6) | 46).to_bytes(3, "big"))  # MED voice policy
        + _tlv(0, b"")
    )
    return b"\x01\x80\xc2\x00\x00\x0e" + SWITCH_MAC + b"\x88\xcc" + body


def cdp_frame() -> bytes:
    """Build a CDP frame (802.3 + LLC/SNAP) with native and voice VLANs."""
    def t(tt: int, v: bytes) -> bytes:
        return struct.pack("!HH", tt, len(v) + 4) + v

    addr = struct.pack("!I", 1) + b"\x01\x01\xcc" + struct.pack("!H", 4) + socket.inet_aton("10.0.0.3")
    cdp = (b"\x02\xb4\x00\x00" + t(1, b"access-sw-07") + t(3, b"FastEthernet0/5") + t(4, struct.pack("!I", 0x28))
           + t(6, b"cisco WS-C2960") + t(10, struct.pack("!H", 40)) + t(11, b"\x00") + t(14, b"\x01" + struct.pack("!H", 41))
           + t(0x16, addr))
    payload = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
    return b"\x01\x00\x0c\xcc\xcc\xcc" + SWITCH_MAC + struct.pack("!H", len(payload)) + payload


def test_lldp_full_decode():
    """Every field a field tech needs is decoded from LLDP: switch, port, VLAN, voice VLAN, PoE, duplex, mgmt IP."""
    d = pcap.decode(pcap.Packet(0, pcap.LINK_ETHERNET, lldp_frame()))
    assert d.l3 == "lldp"
    info = l2proto.parse_lldp(d.payload)
    assert info["system_name"] == "core-sw-01"
    assert info["port_id"] == "Gi1/0/12" and info["port_description"] == "Office 2.14 desk"
    assert info["chassis_id"] == "00:11:22:33:44:55"
    assert info["native_vlan"] == 20 and info["vlan_names"] == {20: "DATA"}
    assert info["voice_vlan"] == 30
    assert info["link_type"] == "1000BASE-T" and info["duplex"] == "full"
    assert info["poe"]["class"] == 3 and info["poe"]["allocated_w"] == 15.4
    assert info["mgmt_addresses"] == ["10.0.0.2"]
    assert "bridge/switch" in info["capabilities"]


def test_cdp_full_decode():
    """CDP: device id, port, platform, native VLAN, voice VLAN, duplex and management address."""
    d = pcap.decode(pcap.Packet(0, pcap.LINK_ETHERNET, cdp_frame()))
    assert d.l3 == "cdp"
    info = l2proto.parse_cdp(d.payload)
    assert info["system_name"] == "access-sw-07" and info["port_id"] == "FastEthernet0/5"
    assert info["native_vlan"] == 40 and info["voice_vlan"] == 41
    assert info["duplex"] == "half" and info["platform"] == "cisco WS-C2960"
    assert info["mgmt_addresses"] == ["10.0.0.3"] and "switch" in info["capabilities"]


def test_pcap_roundtrip_and_find_neighbors(tmp_path):
    """Frames written to a pcap file read back identically and both discovery protocols are found."""
    path = tmp_path / "l2.pcap"
    w = pcap.PcapWriter(path)
    w.write(100.5, lldp_frame())
    w.write(101.0, cdp_frame())
    w.close()
    packets = pcap.read(path)
    assert len(packets) == 2 and packets[0].data == lldp_frame()
    found = l2proto.find_neighbors(packets)
    assert {n["protocol"] for n in found} == {"LLDP", "CDP"}


def test_pcapng_reader(tmp_path):
    """A minimal pcapng file (SHB + IDB + EPB) is parsed with the right timestamp."""
    def block(btype: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", btype, length) + body + struct.pack("<I", length)

    frame = lldp_frame()
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    ts = 1_700_000_000_000_000  # microseconds
    epb = block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    path = tmp_path / "x.pcapng"
    path.write_bytes(shb + idb + epb)
    pkts = pcap.read(path)
    assert len(pkts) == 1 and pkts[0].data == frame and abs(pkts[0].ts - 1_700_000_000) < 1


def test_vlan_tag_decoding_and_summary():
    """802.1Q tags are decoded and counted; DNS query names and ARP conflicts are summarised."""
    eth = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01"
    tagged = eth + b"\x81\x00" + struct.pack("!H", 0x0064) + b"\x08\x06" + b"\x00" * 28
    def arp(mac: bytes) -> bytes:
        body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac + socket.inet_aton("10.0.0.9") + b"\0" * 6 + socket.inet_aton("10.0.0.1")
        return b"\xff" * 6 + mac + b"\x08\x06" + body
    s = pcap.summarize([pcap.Packet(1, 1, tagged), pcap.Packet(2, 1, arp(b"\x02" * 6)), pcap.Packet(3, 1, arp(b"\x04" * 6))])
    assert s["vlans_seen"] == {100: 1}
    assert "10.0.0.9" in s["arp_conflicts"]


def test_dhcp_discover_and_offer_roundtrip():
    """Our DISCOVER is well-formed and a server's OFFER is decoded (server, IP, router, DNS, lease)."""
    xid = 0xDEADBEEF
    mac = bytes.fromhex("aabbccddeeff")
    disc = dhcp.build_discover(mac, xid)
    assert disc[0] == 1 and disc[236:240] == b"\x63\x82\x53\x63" and b"\x35\x01\x01" in disc
    offer = bytearray(disc)
    offer[0] = 2
    offer[16:20] = socket.inet_aton("192.168.1.77")
    opts = (b"\x63\x82\x53\x63\x35\x01\x02\x36\x04" + socket.inet_aton("192.168.1.1") + b"\x03\x04"
            + socket.inet_aton("192.168.1.1") + b"\x06\x08" + socket.inet_aton("1.1.1.1") + socket.inet_aton("8.8.8.8")
            + b"\x33\x04" + struct.pack("!I", 86400) + b"\xff")
    offer = bytes(offer[:236]) + opts
    o = dhcp.parse_offer(offer, xid, "192.168.1.1")
    assert o and o.server_id == "192.168.1.1" and o.offered_ip == "192.168.1.77"
    assert o.dns == ["1.1.1.1", "8.8.8.8"] and o.lease_s == 86400
    assert dhcp.parse_offer(offer, xid + 1, "x") is None  # wrong transaction id ignored


def test_vlan_validation_detects_wrong_vlan_and_subnet(ctx):
    """With switch data saying VLAN 30 but the profile expecting 20, validation FAILs with a clear reason."""
    from nethelper.checks.layer2 import vlan_validation

    ctx.profile = parse_profile({"expected": {"vlan": 20},
                                 "vlans": {"20": {"subnet": "192.168.1.0/24"}, "30": {"subnet": "10.30.0.0/24"}}})
    ctx._memo["l2discovery"] = ("ok", {"interface": "eth0", "neighbors": [{"protocol": "LLDP", "native_vlan": 30}],
                                       "error": None, "limited": False, "waited": 1})
    out = vlan_validation(ctx)
    assert out.status is Status.FAIL
    assert "VLAN 30" in out.summary and "expected 20" in out.summary
    assert any(c["check"] == "subnet" and c["ok"] is False for c in out.details["checks"])


def test_vlan_validation_passes_when_consistent(ctx):
    """Matching VLAN, subnet and duplex PASS."""
    from nethelper.checks.layer2 import vlan_validation

    ctx.profile = parse_profile({"expected": {"vlan": 20}, "vlans": {"20": {"subnet": "192.168.1.0/24", "gateway": "192.168.1.1"}}})
    ctx._memo["l2discovery"] = ("ok", {"interface": "eth0", "neighbors": [{"protocol": "LLDP", "native_vlan": 20, "duplex": "full"}],
                                       "error": None, "limited": False, "waited": 1})
    assert vlan_validation(ctx).status is Status.PASS


def test_switchport_reports_privilege_limit_when_capture_unavailable(ctx):
    """Non-elevated with no capture tools: the switchport check SKIPs and is marked privilege-limited."""
    from nethelper.core.registry import load_all, REGISTRY
    from nethelper.core.runner import run_one

    load_all()
    res = run_one(REGISTRY["l2.switchport"], ctx)
    assert res.status is Status.SKIP and res.limited
    assert "elevat" in res.summary.lower() or "sudo" in res.summary.lower() or "administrator" in res.summary.lower()
