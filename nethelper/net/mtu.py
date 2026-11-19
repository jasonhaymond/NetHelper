"""
Path MTU discovery: the largest packet that can reach a target without being
split ("fragmented").

Why it matters: VPN tunnels, PPPoE DSL links and some cloud networks shrink
the usable packet size below the normal 1500 bytes. If a firewall also blocks
the ICMP "fragmentation needed" messages that normally signal this, large
packets silently vanish - the classic symptom being "websites half-load", "VPN
connects but file shares hang", or "small pings work but big transfers stall".

Method: send pings with the Don't-Fragment (DF) flag set and binary-search
the payload size. MTU = largest working payload + 28 bytes (20-byte IPv4
header + 8-byte ICMP header). Uses icmp.py, so no admin is needed.
"""

from __future__ import annotations

from dataclasses import dataclass

from nethelper.net import icmp

IP_ICMP_OVERHEAD = 28  # IPv4 header (20) + ICMP header (8)


@dataclass
class MtuResult:
    """
    target/address   - what was tested
    mtu              - discovered path MTU in bytes, or None if undeterminable
    max_payload      - largest ping payload that got through with DF set
    black_hole       - True when big packets vanish silently (no "too big"
                       reply) rather than being refused politely
    error            - why the test couldn't run (e.g. target ignores ping)
    """

    target: str
    address: str | None
    mtu: int | None = None
    max_payload: int | None = None
    black_hole: bool = False
    error: str | None = None


def _works(ip: str, payload: int, timeout: float) -> tuple[bool, str]:
    """Try one DF ping of `payload` bytes (two attempts to ride out packet loss)."""
    status = icmp.TIMEOUT
    for attempt in range(2):
        reply = icmp.echo(ip, seq=payload + attempt, timeout=timeout, size=payload, df=True)
        status = reply.status
        if status == icmp.OK:
            return True, status
        if status == icmp.TOO_BIG:
            return False, status
    return False, status


def discover(host: str, timeout: float = 1.5, low: int = 548, high: int = 1472) -> MtuResult:
    """
    Binary-search the largest DF ping payload between `low` and `high` bytes
    (1472 + 28 = 1500, the Ethernet maximum). IPv4 only: IPv6 routers never
    fragment, so the same black-hole problem shows differently there.
    """
    try:
        ip, _ = icmp.resolve(host, family=2)  # 2 = AF_INET (IPv4)
    except (OSError, ValueError) as exc:
        return MtuResult(target=host, address=None, error=f"could not resolve: {exc}")
    result = MtuResult(target=host, address=ip)
    small_ok, _ = _works(ip, 64, timeout)
    if not small_ok:
        result.error = "target does not answer ping, so MTU can't be measured against it"
        return result
    full_ok, _ = _works(ip, high, timeout)
    if full_ok:
        result.max_payload = high
        result.mtu = high + IP_ICMP_OVERHEAD
        return result
    saw_too_big = False
    lo, hi = low, high  # invariant: lo works (assumed), hi fails
    if not _works(ip, lo, timeout)[0]:
        lo = 64
    while hi - lo > 1:
        mid = (lo + hi) // 2
        ok, status = _works(ip, mid, timeout)
        if ok:
            lo = mid
        else:
            hi = mid
            saw_too_big = saw_too_big or status == icmp.TOO_BIG
    result.max_payload = lo
    result.mtu = lo + IP_ICMP_OVERHEAD
    # If nothing ever said "too big", oversized packets were silently dropped.
    result.black_hole = not saw_too_big
    return result
