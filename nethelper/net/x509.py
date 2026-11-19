"""
Minimal X.509 certificate reader (subject, issuer, validity dates, SANs).

Python's ssl module only decodes a certificate for us when it passed
verification. But the interesting cases in troubleshooting are exactly the
ones that FAIL verification (expired, self-signed, wrong name, or a firewall
re-signing traffic), so we need to read the raw certificate ourselves.

Certificates are encoded in DER: nested "TLV" items - a Tag byte saying what
kind of item it is, a Length, then the Value (which may contain more TLVs).
We walk just enough of that structure to pull out the useful fields. Input is
untrusted (it comes from the network), so every read is bounds-checked and any
inconsistency raises ValueError rather than reading out of range.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress

# Object identifiers (OIDs) for the name parts we display, in DER-encoded form.
_NAME_OIDS = {
    bytes.fromhex("550403"): "CN",   # commonName
    bytes.fromhex("55040a"): "O",    # organizationName
    bytes.fromhex("55040b"): "OU",   # organizationalUnitName
    bytes.fromhex("550406"): "C",    # country
    bytes.fromhex("550407"): "L",    # locality
    bytes.fromhex("550408"): "ST",   # state/province
}
_OID_SAN = bytes.fromhex("551d11")  # 2.5.29.17 subjectAltName extension


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """
    Read one DER item header at `pos`.
    Returns (tag, value_start, value_end). Supports long-form lengths.
    """
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:  # long form: low 7 bits = how many length bytes follow
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos: pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("DER value runs past end")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """List the (tag, start, end) of each item directly inside a container."""
    items = []
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        items.append((tag, vs, ve))
        pos = ve
    return items


def _parse_name(data: bytes, start: int, end: int) -> dict[str, str]:
    """Decode a Name (SEQUENCE of SET of {OID, value}) into {"CN": ..., "O": ...}."""
    out: dict[str, str] = {}
    for _, s_start, s_end in _children(data, start, end):            # each SET
        for _, a_start, a_end in _children(data, s_start, s_end):    # each SEQUENCE {oid, value}
            parts = _children(data, a_start, a_end)
            if len(parts) < 2:
                continue
            oid = data[parts[0][1]: parts[0][2]]
            key = _NAME_OIDS.get(oid)
            if key:
                value = data[parts[1][1]: parts[1][2]].decode("utf-8", errors="replace")
                out[key] = value if key not in out else out[key] + ", " + value
    return out


def _parse_time(data: bytes, tag: int, start: int, end: int) -> dt.datetime:
    """Decode UTCTime (tag 0x17, YYMMDDHHMMSSZ) or GeneralizedTime (0x18, YYYYMMDDHHMMSSZ)."""
    text = data[start:end].decode("ascii").rstrip("Z")
    if tag == 0x17:
        year = int(text[:2])
        year += 2000 if year < 50 else 1900  # RFC 5280 two-digit year rule
        text = f"{year}{text[2:]}"
    return dt.datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)


def parse_certificate(der: bytes) -> dict:
    """
    Parse a DER certificate. Returns a dict with:
      subject, issuer   - {"CN": ..., "O": ...}
      not_before/after  - ISO-8601 UTC timestamps
      days_left         - days until expiry (negative = expired)
      san               - list of DNS names / IPs the cert is valid for
      self_signed       - subject == issuer
      sha256            - fingerprint, to compare against a known-good cert
    Raises ValueError on malformed input.
    """
    _, cs, ce = _tlv(der, 0)                    # Certificate ::= SEQUENCE
    tbs_tag, ts, te = _tlv(der, cs)             # tbsCertificate ::= SEQUENCE
    if tbs_tag != 0x30:
        raise ValueError("not a certificate")
    fields = _children(der, ts, te)
    idx = 0
    if fields and fields[0][0] == 0xA0:         # optional [0] version
        idx += 1
    idx += 2                                    # serialNumber, signature algorithm
    issuer = _parse_name(der, fields[idx][1], fields[idx][2])
    validity = _children(der, fields[idx + 1][1], fields[idx + 1][2])
    not_before = _parse_time(der, validity[0][0], validity[0][1], validity[0][2])
    not_after = _parse_time(der, validity[1][0], validity[1][1], validity[1][2])
    subject = _parse_name(der, fields[idx + 2][1], fields[idx + 2][2])
    san: list[str] = []
    for tag, vs, _ve in fields[idx + 4:]:
        if tag != 0xA3:                         # [3] extensions
            continue
        _, xs, xe = _tlv(der, vs)               # SEQUENCE OF Extension
        for _, es, ee in _children(der, xs, xe):
            parts = _children(der, es, ee)
            if not parts or der[parts[0][1]: parts[0][2]] != _OID_SAN:
                continue
            octet = parts[-1]                   # OCTET STRING wrapping GeneralNames
            _, gs, ge = _tlv(der, octet[1])
            for gtag, g1, g2 in _children(der, gs, ge):
                if gtag == 0x82:                # dNSName
                    san.append(der[g1:g2].decode("ascii", errors="replace"))
                elif gtag == 0x87:              # iPAddress (4 or 16 raw bytes)
                    try:
                        san.append(str(ipaddress.ip_address(der[g1:g2])))
                    except ValueError:
                        pass
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "san": san,
        "self_signed": subject == issuer,
        "sha256": hashlib.sha256(der).hexdigest(),
    }


def name_matches(hostname: str, patterns: list[str]) -> bool:
    """
    True if `hostname` is covered by one of the certificate names, honouring a
    single leading wildcard label ("*.example.com" matches "www.example.com"
    but not "example.com" or "a.b.example.com"), per RFC 6125.
    """
    host = hostname.lower().rstrip(".")
    for pattern in patterns:
        pat = pattern.lower().rstrip(".")
        if pat == host:
            return True
        if pat.startswith("*.") and host.count(".") == pat.count(".") and host.endswith(pat[1:]):
            return True
    return False
