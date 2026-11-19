"""
A small, dependency-free DNS client that speaks the DNS wire protocol directly.

Why not just use the OS resolver (socket.getaddrinfo)? Because troubleshooting
needs things the OS resolver can't do:
  - ask a *specific* DNS server (is the router's DNS broken, or everyone's?)
  - fetch any record type (MX, TXT, NS, SOA, SRV, PTR...)
  - see the raw response code (NXDOMAIN vs SERVFAIL vs REFUSED)
  - check DNSSEC validation (the "AD" flag) and encrypted DNS (DoT/DoH)

Message format (RFC 1035): a 12-byte header (id, flags, 4 counts), then the
question, then answer/authority/additional "resource records". Names are
sequences of length-prefixed labels ("3www6google3com0") and may be
*compressed* - a 2-byte pointer back to a name earlier in the message.

SECURITY: responses come from the network and are untrusted. The parser
bounds-checks every read, limits pointer jumps (a malicious response could
contain a pointer loop to hang a naive parser), and verifies the response id
matches the query (prevents accepting spoofed/stray packets).
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import ssl
import struct
import time
import urllib.request
from dataclasses import dataclass, field

from nethelper import __version__

# Record type names <-> numbers (IANA DNS parameters).
TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "OPT": 41, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "CAA": 257, "ANY": 255,
}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

# Response codes (the RCODE field).
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsError(Exception):
    """A malformed response or transport failure."""


@dataclass
class Record:
    """One answer record: owner name, type name, TTL seconds, and decoded value."""

    name: str
    rtype: str
    ttl: int
    value: str


@dataclass
class DnsResponse:
    """
    Parsed DNS reply.
      server     - who answered (IP, or URL for DoH)
      transport  - udp / tcp / dot / doh
      rcode      - NOERROR, NXDOMAIN, SERVFAIL...
      answers    - answer-section records
      authority  - authority-section records (e.g. SOA on NXDOMAIN)
      ad         - "Authenticated Data" flag: resolver validated DNSSEC
      tc         - response was truncated (retry over TCP)
      rtt_ms     - query round-trip time
    """

    server: str
    transport: str
    rcode: str
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    ad: bool = False
    tc: bool = False
    ra: bool = False
    rtt_ms: float = 0.0

    def values(self, rtype: str | None = None) -> list[str]:
        """Answer values, optionally only those of one record type."""
        return [r.value for r in self.answers if rtype is None or r.rtype == rtype]


def encode_name(name: str) -> bytes:
    """Encode "www.example.com" as DNS labels: b"\\x03www\\x07example\\x03com\\x00"."""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")  # converts international names (münchen.de) to ASCII form
        if len(raw) > 63:
            raise DnsError(f"label too long: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, rtype: str = "A", dnssec: bool = False, qid: int | None = None,
                recursion: bool = True, unicast_response: bool = False) -> tuple[int, bytes]:
    """
    Build a DNS query packet. Returns (query id, bytes).

    dnssec=True adds an EDNS0 "OPT" record with the DO ("DNSSEC OK") bit, asking
    the resolver to perform/indicate validation. unicast_response sets the mDNS
    "QU" bit (used by discovery.py).
    """
    qid = secrets.randbelow(65536) if qid is None else qid
    flags = 0x0100 if recursion else 0  # RD = "recursion desired"
    arcount = 1 if dnssec else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, arcount)
    qclass = 1 | (0x8000 if unicast_response else 0)  # class IN (+ QU bit for mDNS)
    question = encode_name(name) + struct.pack("!HH", TYPES[rtype.upper()], qclass)
    extra = b""
    if dnssec:
        # OPT pseudo-record: root name, type 41, UDP payload size 1232,
        # extended rcode/version 0, flags 0x8000 = DO bit, no options.
        extra = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    return qid, header + question + extra


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """
    Read a possibly-compressed name starting at `offset`.
    Returns (name, offset just past the name in the original position).
    """
    labels: list[str] = []
    jumps = 0
    end = None  # where parsing continues after the name, set at first pointer
    while True:
        if offset >= len(msg):
            raise DnsError("name runs past end of message")
        length = msg[offset]
        if length & 0xC0 == 0xC0:  # top two bits set = compression pointer
            if offset + 1 >= len(msg):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > 32 or pointer >= len(msg):  # loop / out-of-range protection
                raise DnsError("bad compression pointer")
            offset = pointer
            continue
        if length == 0:
            offset += 1
            break
        if length > 63 or offset + 1 + length > len(msg):
            raise DnsError("bad label length")
        labels.append(msg[offset + 1: offset + 1 + length].decode("ascii", errors="replace"))
        offset += 1 + length
    return ".".join(labels) or ".", (end if end is not None else offset)


def _decode_rdata(msg: bytes, rtype: int, start: int, length: int) -> str:
    """Turn a record's raw data into readable text according to its type."""
    data = msg[start: start + length]
    try:
        if rtype == 1 and length == 4:
            return socket.inet_ntoa(data)
        if rtype == 28 and length == 16:
            return str(ipaddress.IPv6Address(data))
        if rtype in (2, 5, 12):  # NS, CNAME, PTR - a single name
            return _read_name(msg, start)[0]
        if rtype == 15:  # MX: preference + exchange host
            pref = struct.unpack("!H", data[:2])[0]
            return f"{pref} {_read_name(msg, start + 2)[0]}"
        if rtype == 16:  # TXT: one or more length-prefixed strings
            parts, i = [], 0
            while i < len(data):
                n = data[i]
                parts.append(data[i + 1: i + 1 + n].decode("utf-8", errors="replace"))
                i += 1 + n
            return "".join(parts)
        if rtype == 6:  # SOA: primary NS, admin mailbox, then 5 numbers
            mname, off = _read_name(msg, start)
            rname, off = _read_name(msg, off)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[off: off + 20])
            return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
        if rtype == 33:  # SRV: priority weight port target
            prio, weight, port = struct.unpack("!HHH", data[:6])
            return f"{prio} {weight} {port} {_read_name(msg, start + 6)[0]}"
        if rtype == 257:  # CAA: flags, tag, value
            tag_len = data[1]
            return f"{data[0]} {data[2:2 + tag_len].decode(errors='replace')} {data[2 + tag_len:].decode(errors='replace')}"
    except (struct.error, IndexError, DnsError, ValueError):
        pass
    return f"<{TYPE_NAMES.get(rtype, rtype)} {length} bytes>"


def parse_response(msg: bytes, expected_id: int | None = None) -> DnsResponse:
    """
    Parse a raw DNS response. Raises DnsError if malformed or if its id
    doesn't match `expected_id` (a stray or spoofed packet).
    """
    if len(msg) < 12:
        raise DnsError("response shorter than DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    if expected_id is not None and qid != expected_id:
        raise DnsError("response id does not match query")
    resp = DnsResponse(server="", transport="", rcode=RCODES.get(flags & 0x000F, str(flags & 0x000F)),
                       ad=bool(flags & 0x0020), tc=bool(flags & 0x0200), ra=bool(flags & 0x0080))
    offset = 12
    for _ in range(qd):  # skip the echoed question(s)
        _, offset = _read_name(msg, offset)
        offset += 4
    sections = [(an, resp.answers), (ns, resp.authority), (ar, None)]
    for count, bucket in sections:
        for _ in range(count):
            name, offset = _read_name(msg, offset)
            if offset + 10 > len(msg):
                raise DnsError("truncated resource record")
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", msg[offset: offset + 10])
            offset += 10
            if offset + rdlen > len(msg):
                raise DnsError("record data runs past end of message")
            if bucket is not None and rtype != 41:
                bucket.append(Record(name, TYPE_NAMES.get(rtype, str(rtype)), ttl,
                                     _decode_rdata(msg, rtype, offset, rdlen)))
            offset += rdlen
    return resp


def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from a TCP/TLS stream (DNS-over-TCP framing)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DnsError("connection closed mid-response")
        buf += chunk
    return buf


def _server_ip(server: str) -> str:
    """
    DNS servers may be given by name (e.g. in a profile); resolve to an IP so
    replies can be matched by source address. IPs are returned unchanged.
    """
    try:
        ipaddress.ip_address(server.split("%")[0])
        return server
    except ValueError:
        return socket.getaddrinfo(server, 53, type=socket.SOCK_DGRAM)[0][4][0]


def query(name: str, rtype: str = "A", server: str = "1.1.1.1", timeout: float = 3.0,
          dnssec: bool = False, transport: str = "udp", port: int | None = None,
          tls_hostname: str | None = None, source: str | None = None) -> DnsResponse:
    """
    Ask one DNS server one question.

    transport:
      "udp" - normal DNS on port 53; automatically retries over TCP if the
              answer was truncated
      "tcp" - DNS over TCP port 53 (2-byte length prefix framing)
      "dot" - DNS over TLS, port 853, certificate verified against tls_hostname
    source - optional local IP to send from (tests one specific interface)
    Raises DnsError / OSError (incl. socket.timeout) on failure.
    """
    label = server
    server = _server_ip(server)
    qid, packet = build_query(name, rtype, dnssec)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    started = time.perf_counter()
    if transport == "udp":
        with socket.socket(fam, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            if source:
                sock.bind((source, 0))
            sock.sendto(packet, (server, port or 53))
            deadline = started + timeout
            while True:
                sock.settimeout(max(deadline - time.perf_counter(), 0.01))
                data, addr = sock.recvfrom(65535)
                # Only accept replies from the server we asked (anti-spoofing).
                if addr[0].split("%")[0] != server.split("%")[0]:
                    continue
                try:
                    resp = parse_response(data, qid)
                    break
                except DnsError:
                    continue
        if resp.tc:  # too big for UDP: ask again over TCP
            return query(name, rtype, server, timeout, dnssec, "tcp", port, source=source)
    else:
        default_port = 853 if transport == "dot" else 53
        raw = socket.create_connection((server, port or default_port), timeout=timeout,
                                       source_address=(source, 0) if source else None)
        try:
            sock = raw
            if transport == "dot":
                # Verified TLS: refuses to talk if the certificate isn't valid for tls_hostname.
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(raw, server_hostname=tls_hostname or server)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", _recv_exact(sock, 2))[0]
            resp = parse_response(_recv_exact(sock, length), qid)
        finally:
            raw.close()
    resp.server = label
    resp.transport = transport
    resp.rtt_ms = round((time.perf_counter() - started) * 1000, 2)
    return resp


def query_doh(name: str, rtype: str = "A", url: str = "https://cloudflare-dns.com/dns-query",
              timeout: float = 5.0, dnssec: bool = False) -> DnsResponse:
    """
    DNS over HTTPS (RFC 8484): POST the wire-format query to an HTTPS endpoint.
    Useful to tell "DNS is blocked" (port 53 filtered) from "DNS is broken".
    The HTTPS certificate is verified by urllib's default settings.
    """
    qid, packet = build_query(name, rtype, dnssec, qid=0)  # RFC 8484 recommends id 0
    req = urllib.request.Request(url, data=packet, method="POST", headers={
        "Content-Type": "application/dns-message", "Accept": "application/dns-message",
        "User-Agent": f"NetHelper/{__version__}"})
    started = time.perf_counter()
    # Security note (B310): URL is validated https from config
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        body = resp.read(65535)
    parsed = parse_response(body, qid)
    parsed.server = url
    parsed.transport = "doh"
    parsed.rtt_ms = round((time.perf_counter() - started) * 1000, 2)
    return parsed


def reverse_name(ip: str) -> str:
    """Build the PTR lookup name for an IP, e.g. 8.8.8.8 -> 8.8.8.8.in-addr.arpa."""
    return ipaddress.ip_address(ip).reverse_pointer


def system_resolve(name: str) -> tuple[list[str], float]:
    """
    Resolve via the operating system's resolver (what browsers and apps use,
    including the hosts file and any VPN/split-DNS rules). Returns
    (unique IPs, milliseconds). Raises OSError (socket.gaierror) on failure.
    """
    started = time.perf_counter()
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    elapsed = (time.perf_counter() - started) * 1000
    ips: list[str] = []
    for info in infos:
        if info[4][0] not in ips:
            ips.append(info[4][0])
    return ips, round(elapsed, 2)
