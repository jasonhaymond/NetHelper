"""
Clock check using SNTP (Simple Network Time Protocol, RFC 4330).

Why a network tool cares about the clock: TLS certificates, Kerberos/Active
Directory logons (5-minute tolerance), MFA codes and many APIs all fail when
the local clock is wrong - and the error messages rarely say "your clock is
off". This sends one NTP request over UDP port 123 and computes the offset.

Offset maths (the standard NTP formula), with timestamps:
  t1 = we sent, t2 = server received, t3 = server replied, t4 = we received
  offset = ((t2 - t1) + (t3 - t4)) / 2     (positive = our clock is behind)
  delay  = (t4 - t1) - (t3 - t2)           (network round trip)
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

NTP_EPOCH_DELTA = 2208988800  # seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch)


@dataclass
class NtpResult:
    """server, offset_s (positive = local clock behind), delay_ms, stratum, error."""

    server: str
    offset_s: float | None = None
    delay_ms: float | None = None
    stratum: int | None = None
    error: str | None = None


def _to_ntp(ts: float) -> bytes:
    """Unix time -> 64-bit NTP timestamp (32-bit seconds + 32-bit fraction)."""
    secs = int(ts) + NTP_EPOCH_DELTA
    frac = int((ts % 1) * (1 << 32))
    return struct.pack("!II", secs & 0xFFFFFFFF, frac & 0xFFFFFFFF)


def _from_ntp(data: bytes) -> float:
    """64-bit NTP timestamp -> Unix time."""
    secs, frac = struct.unpack("!II", data)
    return secs - NTP_EPOCH_DELTA + frac / (1 << 32)


def query(server: str, timeout: float = 3.0) -> NtpResult:
    """Ask one NTP server for the time; never raises (see NtpResult.error)."""
    # First byte 0x23: leap indicator 0, version 4, mode 3 (client).
    t1 = time.time()
    packet = b"\x23" + b"\0" * 39 + _to_ntp(t1)
    try:
        infos = socket.getaddrinfo(server, 123, 0, socket.SOCK_DGRAM)
        fam, _, _, _, addr = infos[0]
        with socket.socket(fam, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, addr)
            data, _ = sock.recvfrom(512)
        t4 = time.time()
    except OSError as exc:
        return NtpResult(server, error=f"no reply ({exc})")
    if len(data) < 48:
        return NtpResult(server, error="short NTP reply")
    # The server copies our transmit time into "originate"; mismatch = not our reply.
    if data[24:32] != _to_ntp(t1):
        return NtpResult(server, error="reply does not match our request")
    stratum = data[1]
    if stratum == 0:
        return NtpResult(server, stratum=0, error="server sent a 'kiss of death' (rate limited / refused)")
    t2 = _from_ntp(data[32:40])  # server receive time
    t3 = _from_ntp(data[40:48])  # server transmit time
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    return NtpResult(server, round(offset, 4), round(delay * 1000, 1), stratum)
