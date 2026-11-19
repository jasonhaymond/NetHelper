"""
Ping (ICMP echo) that works without administrator rights on every OS.

ICMP is the protocol behind `ping`. Sending it normally needs a "raw socket",
which requires admin/root. This module picks the best method available:

  Windows  -> the IcmpSendEcho / Icmp6SendEcho2 functions in iphlpapi.dll,
              called through ctypes (Python's built-in bridge to Windows
              DLLs). These are what ping.exe uses, need no elevation, return
              language-independent results, and support TTL and the
              Don't-Fragment flag, which also gives us traceroute and MTU
              discovery without parsing localised command output.
  Linux/   -> an "unprivileged ICMP datagram socket" (socket type SOCK_DGRAM
  macOS       + IPPROTO_ICMP). macOS always allows it; Linux allows it when
              the net.ipv4.ping_group_range sysctl includes the user (default
              on most current distros).
  root     -> a classic raw socket, which additionally sees "TTL exceeded"
              replies from routers (used for traceroute when elevated).
  fallback -> the system `ping` command, with its output parsed.

Nothing here needs elevation; elevated runs simply get more methods.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass, field

from nethelper.core import cmd, validate

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# Reply status words used throughout NetHelper.
OK, TIMEOUT, TTL_EXPIRED, UNREACHABLE, TOO_BIG, ERROR = (
    "ok", "timeout", "ttl_expired", "unreachable", "too_big", "error")


@dataclass
class EchoReply:
    """
    Result of one echo request.
      status   - ok / timeout / ttl_expired / unreachable / too_big / error
      rtt_ms   - round-trip time in milliseconds (when a reply came back)
      from_ip  - who answered (the target, or a router for ttl_expired)
      detail   - extra text for errors
    """

    seq: int
    status: str
    rtt_ms: float | None = None
    from_ip: str | None = None
    detail: str = ""


@dataclass
class PingStats:
    """
    Summary of a series of pings to one target.
      target / address - what was asked for and the IP actually pinged
      method           - which mechanism was used (winapi, dgram, raw, system)
    """

    target: str
    address: str | None
    sent: int = 0
    received: int = 0
    rtts: list[float] = field(default_factory=list)
    replies: list[EchoReply] = field(default_factory=list)
    method: str = ""
    error: str | None = None

    @property
    def loss_pct(self) -> float:
        """Percentage of requests that got no reply (0-100)."""
        return 100.0 if self.sent == 0 else round(100.0 * (self.sent - self.received) / self.sent, 1)

    @property
    def min_ms(self) -> float | None:
        return round(min(self.rtts), 2) if self.rtts else None

    @property
    def avg_ms(self) -> float | None:
        return round(sum(self.rtts) / len(self.rtts), 2) if self.rtts else None

    @property
    def max_ms(self) -> float | None:
        return round(max(self.rtts), 2) if self.rtts else None

    @property
    def jitter_ms(self) -> float | None:
        """
        Jitter = average change in latency between consecutive replies
        (the same definition VoIP tools use). High jitter makes calls choppy
        even when average latency looks fine.
        """
        if len(self.rtts) < 2:
            return None
        diffs = [abs(b - a) for a, b in zip(self.rtts, self.rtts[1:], strict=False)]
        return round(sum(diffs) / len(diffs), 2)

    def to_dict(self) -> dict:
        """Plain-dict form for reports (drops the per-packet list to keep it short)."""
        data = asdict(self)
        data.pop("replies", None)
        data.update(loss_pct=self.loss_pct, min_ms=self.min_ms, avg_ms=self.avg_ms,
                    max_ms=self.max_ms, jitter_ms=self.jitter_ms)
        return data


def resolve(host: str, family: int | None = None, timeout: float = 5.0) -> tuple[str, int]:
    """
    Turn a hostname into one IP address using the system resolver.
    Returns (ip, family) where family is socket.AF_INET or AF_INET6.
    IPv4 is preferred unless `family` asks for IPv6. Raises OSError on failure.
    """
    host = validate.hostname(host)
    if validate.is_ip(host):
        ip = ipaddress.ip_address(host.split("%")[0])
        return host, socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    fams = [family] if family else [socket.AF_INET, socket.AF_INET6]
    last: OSError | None = None
    for fam in fams:
        try:
            infos = socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM)
            if infos:
                return infos[0][4][0], fam
        except OSError as exc:
            last = exc
    raise last or OSError(f"could not resolve {host}")


def _checksum(data: bytes) -> int:
    """
    The 16-bit "Internet checksum" every ICMP packet carries: sum all 16-bit
    words, fold the carries back in, then invert the bits.
    """
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes, v6: bool = False) -> bytes:
    """
    Build an ICMP Echo Request packet: type (8 for IPv4, 128 for IPv6),
    code 0, checksum, identifier, sequence number, then payload bytes.
    (For IPv6 the kernel fills in the checksum itself.)
    """
    icmp_type = 128 if v6 else 8
    header = struct.pack("!BBHHH", icmp_type, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    if v6:
        return header + payload
    csum = _checksum(header + payload)
    return struct.pack("!BBHHH", icmp_type, 0, csum, ident & 0xFFFF, seq & 0xFFFF) + payload


# --------------------------------------------------------------------------
# Windows: IcmpSendEcho / Icmp6SendEcho2 through ctypes
# --------------------------------------------------------------------------

_win_lock = threading.Lock()
_win = None  # lazily-initialised ctypes bindings


def _win_api():
    """
    Load iphlpapi.dll and declare the C function signatures we call.

    ctypes needs to be told each function's argument and return types so it
    passes data correctly on 64-bit Windows. Structures mirror the C structs in
    the Windows SDK header ipexport.h.
    """
    global _win
    with _win_lock:
        if _win is not None:
            return _win
        import ctypes
        from ctypes import wintypes

        class IP_OPTION_INFORMATION(ctypes.Structure):
            # TTL to send with, type-of-service, flags (0x02 = Don't Fragment).
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                        ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            # Address of whoever replied, status code, round-trip time in ms.
            _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong),
                        ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                        ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                        ("Options", IP_OPTION_INFORMATION)]

        class SOCKADDR_IN6(ctypes.Structure):
            _fields_ = [("sin6_family", ctypes.c_short), ("sin6_port", ctypes.c_ushort),
                        ("sin6_flowinfo", ctypes.c_ulong), ("sin6_addr", ctypes.c_ubyte * 16),
                        ("sin6_scope_id", ctypes.c_ulong)]

        class IPV6_ADDRESS_EX(ctypes.Structure):
            _pack_ = 1  # the SDK declares this struct byte-packed
            _fields_ = [("sin6_port", ctypes.c_ushort), ("sin6_flowinfo", ctypes.c_ulong),
                        ("sin6_addr", ctypes.c_ubyte * 16), ("sin6_scope_id", ctypes.c_ulong)]

        class ICMPV6_ECHO_REPLY(ctypes.Structure):
            _fields_ = [("Address", IPV6_ADDRESS_EX), ("Status", ctypes.c_ulong),
                        ("RoundTripTime", ctypes.c_uint)]

        lib = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.Icmp6CreateFile.restype = wintypes.HANDLE
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_ushort,
                                     ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                     ctypes.c_ulong, ctypes.c_ulong]
        lib.IcmpSendEcho.restype = ctypes.c_ulong
        lib.Icmp6SendEcho2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(SOCKADDR_IN6), ctypes.POINTER(SOCKADDR_IN6),
                                       ctypes.c_void_p, ctypes.c_ushort,
                                       ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                       ctypes.c_ulong, ctypes.c_ulong]
        lib.Icmp6SendEcho2.restype = ctypes.c_ulong
        # IcmpSendEcho2Ex = IcmpSendEcho plus a chosen SOURCE address, which
        # sends the ping out of a specific interface (per-interface tests).
        lib.IcmpSendEcho2Ex.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_ushort,
                                        ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.c_ulong]
        lib.IcmpSendEcho2Ex.restype = ctypes.c_ulong
        _win = {
            "ctypes": ctypes, "lib": lib, "OPT": IP_OPTION_INFORMATION, "REPLY": ICMP_ECHO_REPLY,
            "SA6": SOCKADDR_IN6, "REPLY6": ICMPV6_ECHO_REPLY,
        }
        return _win


# Windows IP_STATUS codes (ipexport.h) mapped to our status words.
_WIN_STATUS = {
    0: OK,
    11002: UNREACHABLE,  # destination net unreachable
    11003: UNREACHABLE,  # destination host unreachable
    11004: UNREACHABLE,  # destination protocol unreachable
    11005: UNREACHABLE,  # destination port unreachable
    11009: TOO_BIG,      # packet too big (needs fragmenting but DF set)
    11010: TIMEOUT,      # request timed out
    11013: TTL_EXPIRED,  # TTL expired in transit (a router answered: traceroute hop)
    11014: TTL_EXPIRED,  # TTL expired during reassembly
    11050: ERROR,        # general failure
    # Win32 error codes the API can return instead (via GetLastError):
    1231: UNREACHABLE,   # ERROR_NETWORK_UNREACHABLE - no route (e.g. no IPv6 connectivity)
    1232: UNREACHABLE,   # ERROR_HOST_UNREACHABLE
    1214: ERROR,         # ERROR_INVALID_NETNAME
}


def _win_echo(ip: str, v6: bool, seq: int, timeout: float, size: int, ttl: int | None, df: bool,
              source: str | None = None) -> EchoReply:
    """Send one echo via the Windows ICMP API (optionally from a source IP) and translate the reply."""
    api = _win_api()
    ctypes = api["ctypes"]
    lib = api["lib"]
    payload = (b"nethelper" * ((size // 9) + 1))[:size]
    data = ctypes.create_string_buffer(payload, len(payload))
    opts = api["OPT"](Ttl=ttl or 128, Tos=0, Flags=0x02 if df else 0, OptionsSize=0, OptionsData=None)
    reply_size = ctypes.sizeof(api["REPLY"]) + len(payload) + 8 + 1024  # room for ICMP error data
    reply_buf = ctypes.create_string_buffer(reply_size)
    ms = max(int(timeout * 1000), 1)

    handle = lib.Icmp6CreateFile() if v6 else lib.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return EchoReply(seq, ERROR, detail="IcmpCreateFile failed")
    try:
        if v6:
            src = api["SA6"](sin6_family=23)  # 23 = AF_INET6 on Windows; zero address = any source
            if source:
                ctypes.memmove(src.sin6_addr, socket.inet_pton(socket.AF_INET6, source.split("%")[0]), 16)
            dst = api["SA6"](sin6_family=23)
            addr, _, scope = ip.partition("%")
            ctypes.memmove(dst.sin6_addr, socket.inet_pton(socket.AF_INET6, addr), 16)
            if scope.isdigit():
                dst.sin6_scope_id = int(scope)
            count = lib.Icmp6SendEcho2(handle, None, None, None, ctypes.byref(src), ctypes.byref(dst),
                                       data, len(payload), ctypes.byref(opts), reply_buf, reply_size, ms)
            reply = api["REPLY6"].from_buffer(reply_buf)
            status_code = reply.Status if count else (reply.Status or ctypes.get_last_error())
            from_ip = socket.inet_ntop(socket.AF_INET6, bytes(reply.Address.sin6_addr))
            rtt = float(reply.RoundTripTime)
        else:
            # IPAddr is the 4 address bytes in network order read as a
            # little-endian integer - i.e. the raw bytes, unchanged in memory.
            dest = int.from_bytes(socket.inet_aton(ip), "little")
            if source:
                src4 = int.from_bytes(socket.inet_aton(source), "little")
                count = lib.IcmpSendEcho2Ex(handle, None, None, None, src4, dest, data, len(payload),
                                            ctypes.byref(opts), reply_buf, reply_size, ms)
            else:
                count = lib.IcmpSendEcho(handle, dest, data, len(payload), ctypes.byref(opts),
                                         reply_buf, reply_size, ms)
            reply = api["REPLY"].from_buffer(reply_buf)
            status_code = reply.Status if (count or reply.Address) else ctypes.get_last_error()
            from_ip = socket.inet_ntoa(reply.Address.to_bytes(4, "little")) if reply.Address else None
            rtt = float(reply.RoundTripTime)
    finally:
        lib.IcmpCloseHandle(handle)

    status = _WIN_STATUS.get(status_code, ERROR if status_code else TIMEOUT)
    if status_code == 0 and not count:
        status = TIMEOUT
    if from_ip and ipaddress.ip_address(from_ip).is_unspecified:  # API's "no address" placeholder
        from_ip = None
    if status == OK:
        # The API reports whole milliseconds; "0" really means "under 1 ms".
        return EchoReply(seq, OK, max(rtt, 0.5), from_ip or ip)
    return EchoReply(seq, status, rtt if status == TTL_EXPIRED else None, from_ip,
                     detail=f"IP_STATUS {status_code}")


# --------------------------------------------------------------------------
# Linux/macOS: unprivileged datagram ICMP socket, or raw socket when root
# --------------------------------------------------------------------------

def _posix_socket(v6: bool) -> tuple[socket.socket, str]:
    """
    Open the best available ICMP socket. Returns (socket, kind) where kind is
    "dgram" (unprivileged) or "raw" (root). Raises PermissionError if neither
    is allowed - the caller then falls back to the system ping command.
    """
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
    try:
        return socket.socket(fam, socket.SOCK_DGRAM, proto), "dgram"
    except (PermissionError, OSError):
        pass
    return socket.socket(fam, socket.SOCK_RAW, proto), "raw"


def _apply_ttl_df(sock: socket.socket, v6: bool, ttl: int | None, df: bool) -> None:
    """Set the outgoing TTL (hop limit) and Don't-Fragment behaviour on a socket."""
    if ttl:
        if v6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    if df and not v6:
        if sys.platform.startswith("linux"):
            # IP_MTU_DISCOVER (10) = IP_PMTUDISC_DO (2): always set DF, never fragment.
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)
        elif IS_MAC:
            sock.setsockopt(socket.IPPROTO_IP, 28, 1)  # 28 = IP_DONTFRAG on macOS


def bind_source(sock: socket.socket, source: str | None, device: str | None = None) -> None:
    """
    Make a socket send from a specific interface:
      - bind to the interface's IP address (works for everyone), and
      - on Linux when root, also SO_BINDTODEVICE (option 25) to pin the
        interface even if the routing table would prefer another one.
    Without root on Linux the source-IP bind still selects that address, but
    the kernel may route it via a different interface (documented limitation).
    """
    if device and sys.platform.startswith("linux"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), device.encode() + b"\0")
        except (PermissionError, OSError):
            pass  # needs root/CAP_NET_RAW - fall back to source-IP binding only
    if source:
        sock.bind((source, 0))


def _posix_echo(ip: str, v6: bool, seq: int, timeout: float, size: int, ttl: int | None, df: bool,
                sock_info: tuple[socket.socket, str] | None = None, source: str | None = None,
                device: str | None = None) -> EchoReply:
    """
    Send one echo request on an ICMP socket and wait for the matching reply.

    Matching: a random token in the payload identifies *our* packets. On a
    raw socket we also receive everyone else's ICMP traffic and router error
    messages (TTL exceeded / unreachable) that quote our original packet, so
    we look for our identifier inside those too.
    """
    own = sock_info is None
    sock, kind = sock_info or _posix_socket(v6)
    try:
        if own:
            bind_source(sock, source, device)
        _apply_ttl_df(sock, v6, ttl, df)
        ident = (os.getpid() ^ secrets.randbits(16)) & 0xFFFF
        token = secrets.token_bytes(8)
        payload = (token + b"nethelper" * ((size // 9) + 1))[:max(size, 8)]
        packet = build_echo(ident, seq, payload, v6)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.sendto(packet, (ip, 0))
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.EMSGSIZE:  # bigger than local MTU with DF set
                return EchoReply(seq, TOO_BIG, detail="message too long for local interface MTU")
            return EchoReply(seq, ERROR, detail=str(exc))
        deadline = started + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return EchoReply(seq, TIMEOUT)
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                return EchoReply(seq, TIMEOUT)
            rtt = (time.perf_counter() - started) * 1000
            # Strip the IPv4 header when present (raw sockets, and macOS dgram sockets).
            if not v6 and data and (data[0] >> 4) == 4:
                data = data[(data[0] & 0x0F) * 4:]
            if len(data) < 8:
                continue
            icmp_type = data[0]
            echo_reply = 129 if v6 else 0
            if icmp_type == echo_reply and token in data[8:]:
                return EchoReply(seq, OK, round(rtt, 3), addr[0])
            # Router error messages quote our original packet (header + 8 bytes).
            ttl_types = (3,) if v6 else (11,)
            unreach_types = (1,) if v6 else (3,)
            too_big = (2,) if v6 else ()
            if icmp_type in ttl_types + unreach_types + too_big and kind == "raw":
                inner = data[8:]
                if not v6 and inner and (inner[0] >> 4) == 4:
                    inner = inner[(inner[0] & 0x0F) * 4:]
                elif v6:
                    inner = inner[40:]
                if len(inner) >= 8 and struct.unpack("!H", inner[4:6])[0] == ident:
                    if icmp_type in ttl_types:
                        return EchoReply(seq, TTL_EXPIRED, round(rtt, 3), addr[0])
                    if icmp_type in too_big or (not v6 and icmp_type == 3 and data[1] == 4):
                        return EchoReply(seq, TOO_BIG, None, addr[0], "fragmentation needed")
                    return EchoReply(seq, UNREACHABLE, None, addr[0], f"ICMP type {icmp_type} code {data[1]}")
    finally:
        if own:
            sock.close()


# --------------------------------------------------------------------------
# Fallback: the system ping command
# --------------------------------------------------------------------------

# Regex: the round-trip time in ping output. Matches "time=12.3 ms",
# "time<1ms", "time=4ms" (Windows/Linux/macOS, English output).
_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
# Regex: a router reporting TTL expiry, e.g. Linux
# "From 10.0.0.1 icmp_seq=1 Time to live exceeded", Windows
# "Reply from 10.0.0.1: TTL expired in transit.", macOS
# "92 bytes from 10.0.0.1: Time to live exceeded".
_TTL_RE = re.compile(r"(?:from|From)\s+([0-9a-fA-F:.]+)[:\s].*(?:Time to live exceeded|TTL expired)", re.IGNORECASE)


def system_ping_argv(ip: str, v6: bool, timeout: float, size: int, ttl: int | None, df: bool,
                     source: str | None = None) -> list[str]:
    """Build the OS-specific ping command line for ONE echo request (optionally from a source IP)."""
    if IS_WINDOWS:
        argv = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), "-l", str(size)]
        if ttl:
            argv += ["-i", str(ttl)]
        if df and not v6:
            argv.append("-f")
        if source:
            argv += ["-S", source]
        argv.append("-6" if v6 else "-4")
    elif IS_MAC:
        argv = ["ping6" if v6 else "ping", "-c", "1", "-s", str(size)]
        if not v6:
            argv += ["-W", str(int(timeout * 1000))]  # macOS: -W is milliseconds
            if ttl:
                argv += ["-m", str(ttl)]
            if df:
                argv.append("-D")
            if source:
                argv += ["-S", source]
        else:
            if ttl:
                argv += ["-h", str(ttl)]
            if source:
                argv += ["-S", source]
    else:
        argv = ["ping", "-6" if v6 else "-4", "-c", "1", "-W", str(max(int(timeout), 1)), "-s", str(size)]
        if ttl:
            argv += ["-t", str(ttl)]
        if df:
            argv += ["-M", "do"]
        if source:
            argv += ["-I", source]  # iputils: source address (or interface name)
    return argv + [ip]


def parse_system_ping(output: str, seq: int, target: str) -> EchoReply:
    """Interpret the text output of a single system ping (see regexes above)."""
    m = _TTL_RE.search(output)
    if m:
        return EchoReply(seq, TTL_EXPIRED, None, m.group(1))
    m = _TIME_RE.search(output)
    if m:
        return EchoReply(seq, OK, max(float(m.group(1)), 0.5), target)
    low = output.lower()
    if "unreachable" in low:
        return EchoReply(seq, UNREACHABLE, detail="destination unreachable")
    if "needs to be fragmented" in low or "message too long" in low or "frag needed" in low:
        return EchoReply(seq, TOO_BIG, detail="fragmentation needed")
    return EchoReply(seq, TIMEOUT)


def _system_echo(ip: str, v6: bool, seq: int, timeout: float, size: int, ttl: int | None, df: bool,
                 source: str | None = None) -> EchoReply:
    """Run the system ping command for one echo and parse the result."""
    res = cmd.run(system_ping_argv(ip, v6, timeout, size, ttl, df, source), timeout=timeout + 5)
    if res.error:
        return EchoReply(seq, ERROR, detail=res.error)
    return parse_system_ping(res.stdout + res.stderr, seq, ip)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

_method_cache: dict[bool, str] = {}


def best_method(v6: bool = False) -> str:
    """
    Decide (once per address family) which ping mechanism works here:
    "winapi", "dgram", "raw" or "system".
    """
    if v6 in _method_cache:
        return _method_cache[v6]
    method = "system"
    if IS_WINDOWS:
        try:
            _win_api()
            method = "winapi"
        except (OSError, AttributeError):
            method = "system"
    else:
        try:
            sock, kind = _posix_socket(v6)
            sock.close()
            method = kind
        except (PermissionError, OSError):
            method = "system"
    _method_cache[v6] = method
    return method


def echo(ip: str, seq: int = 1, timeout: float = 2.0, size: int = 32, ttl: int | None = None,
         df: bool = False, method: str | None = None, source: str | None = None,
         device: str | None = None) -> EchoReply:
    """
    Send ONE echo request to an IP address and return the reply.
    `size` is the payload size in bytes (not counting IP/ICMP headers).
    `source` (an IP of this machine) / `device` (interface name, Linux root)
    send the ping out of a specific interface.
    """
    v6 = ":" in ip
    method = method or best_method(v6)
    try:
        if method == "winapi":
            return _win_echo(ip, v6, seq, timeout, size, ttl, df, source)
        if method in ("dgram", "raw"):
            return _posix_echo(ip, v6, seq, timeout, size, ttl, df, source=source, device=device)
    except OSError as exc:
        # Unexpected socket/API failure: fall back to the ping command.
        reply = _system_echo(ip, v6, seq, timeout, size, ttl, df, source)
        if reply.status == ERROR:
            reply.detail = f"{exc}; {reply.detail}"
        return reply
    return _system_echo(ip, v6, seq, timeout, size, ttl, df, source)


def ping(host: str, count: int = 4, timeout: float = 2.0, interval: float = 0.2, size: int = 32,
         family: int | None = None, source: str | None = None, device: str | None = None) -> PingStats:
    """
    Ping a host `count` times and return statistics.

    Parameters: host (name or IP), count, per-request timeout (s), pause
    between requests (s), payload size, optional address family, optional
    source IP / device to test one specific interface.
    Never raises for network problems - they're reported in PingStats.error
    or as lost packets.
    """
    try:
        ip, fam = resolve(host, family)
    except (OSError, validate.ValidationError) as exc:
        return PingStats(target=host, address=None, error=f"could not resolve: {exc}")
    stats = PingStats(target=host, address=ip, method=best_method(fam == socket.AF_INET6))
    for seq in range(1, count + 1):
        reply = echo(ip, seq=seq, timeout=timeout, size=size, source=source, device=device)
        stats.sent += 1
        stats.replies.append(reply)
        if reply.status == OK and reply.rtt_ms is not None:
            stats.received += 1
            stats.rtts.append(reply.rtt_ms)
        elif reply.status in (ERROR, UNREACHABLE) and stats.error is None:
            # Remember the first hard failure so the check can explain it.
            stats.error = f"{reply.status}: {reply.detail}" if reply.detail else reply.status
        if seq < count:
            time.sleep(interval)
    return stats
