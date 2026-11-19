"""
Security tests: hostile network data.

DNS responses, certificates, capture files and LLDP/CDP frames all come from
the network, where an attacker (or a broken device) controls every byte. These
tests feed malformed, truncated, looping and random data to every parser and
prove it is rejected cleanly - no crash, hang, or out-of-range read.
"""

from __future__ import annotations

import os
import random
import struct

import pytest

from nethelper.net import dhcp, dnswire, l2proto, pcap, x509


def test_dns_compression_pointer_loop_is_rejected():
    """Blocks a denial-of-service: a name pointer that points at itself forever."""
    header = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0)
    # Answer name = pointer to offset 12 (itself) -> infinite loop in a naive parser.
    msg = header + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    with pytest.raises(dnswire.DnsError):
        dnswire.parse_response(msg)


def test_dns_response_id_mismatch_is_rejected():
    """Blocks accepting a spoofed or stray reply whose id doesn't match our query."""
    qid, query = dnswire.build_query("example.com")
    reply = struct.pack("!H", (qid + 1) % 65536) + b"\x81\x80" + query[4:]
    with pytest.raises(dnswire.DnsError):
        dnswire.parse_response(reply, expected_id=qid)


def test_dns_truncated_record_is_rejected():
    """Blocks out-of-bounds reads when record data claims to be longer than the packet."""
    header = struct.pack("!HHHHHH", 7, 0x8180, 0, 1, 0, 0)
    msg = header + b"\x00" + struct.pack("!HHIH", 1, 1, 60, 200) + b"\x01"
    with pytest.raises(dnswire.DnsError):
        dnswire.parse_response(msg)


def test_parsers_survive_random_garbage():
    """Fuzz: thousands of random byte strings never crash any parser with an unexpected exception."""
    rng = random.Random(1234)
    for _ in range(3000):
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
        try:
            dnswire.parse_response(blob)
        except dnswire.DnsError:
            pass
        l2proto.parse_lldp(blob)
        l2proto.parse_cdp(blob)
        pcap.decode(pcap.Packet(0, pcap.LINK_ETHERNET, blob))
        pcap.dhcp_info(blob)
        dhcp.parse_offer(blob, 1, "1.2.3.4")
        try:
            x509.parse_certificate(blob)
        except (ValueError, IndexError):
            pass


def test_pcap_reader_handles_truncated_and_bogus_files(tmp_path):
    """A corrupt capture file is read up to the damage, never trusted beyond it."""
    good = tmp_path / "ok.pcap"
    w = pcap.PcapWriter(good)
    w.write(1.0, b"\x00" * 60)
    w.close()
    data = good.read_bytes()
    trunc = tmp_path / "trunc.pcap"
    trunc.write_bytes(data + struct.pack("<IIII", 1, 0, 999999, 999999) + b"xx")  # record claims ~1 MB
    assert len(pcap.read(trunc)) == 1
    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(os.urandom(64))
    with pytest.raises(ValueError):
        pcap.read(bogus)


def test_lldp_strings_are_sanitised():
    """Blocks terminal-escape injection via a switch's LLDP system name."""
    name = b"sw\x1b[2Jitch"
    tlv = struct.pack("!H", (5 << 9) | len(name)) + name + b"\x00\x00"
    info = l2proto.parse_lldp(tlv)
    assert "\x1b" not in info["system_name"]


def test_x509_rejects_oversized_length():
    """Blocks a DER length field that points past the end of the buffer."""
    with pytest.raises(ValueError):
        x509.parse_certificate(b"\x30\x84\x7f\xff\xff\xff\x00")
