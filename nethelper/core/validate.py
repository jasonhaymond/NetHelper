"""
Input validation for anything a user (or a profile file) can type that ends up
in a network operation or an external command: hostnames, IP addresses, ports,
URLs, interface names, capture filters.

SECURITY: cmd.py already prevents shell command injection by never using a
shell. These checks are a second, independent layer: they reject values that
could still be misinterpreted by the *target program itself* - for example a
"hostname" starting with "-" that ping would treat as an option
("argument injection": `ping -n 1 -S 10.0.0.5` style tricks), or control
characters that could corrupt log files and reports. Validate first, then use.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Regex: one DNS label - letters, digits, hyphen, underscore (used in SRV/DMARC
# names), 1-63 chars, not starting or ending with a hyphen.
# Matches: "www", "my-server", "_ldap"   Rejects: "-bad", "bad-", "a b"
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")

# Regex: interface names as the OS shows them. Windows allows spaces and
# parentheses ("Ethernet 2", "Wi-Fi (Intel)"), Linux uses e.g. "eth0.10",
# "enp3s0", "wlan0", macOS "en0". Must not start with "-" (option injection)
# and has no quotes, semicolons, pipes or other shell-special characters.
_IFACE = re.compile(r"^(?!-)[\w .:()#\-{}\\]{1,128}$", re.UNICODE)


class ValidationError(ValueError):
    """Raised when user input is rejected. The message is safe to show."""


def is_ip(value: str) -> bool:
    """True if value is a valid IPv4 or IPv6 address (e.g. 10.0.0.1, fe80::1)."""
    try:
        ipaddress.ip_address(value.split("%", 1)[0])  # strip IPv6 zone id like %eth0
        return True
    except ValueError:
        return False


def hostname(value: str) -> str:
    """
    Validate a hostname or IP address and return it cleaned up (trimmed,
    trailing dot removed). Raises ValidationError if unsafe or malformed.

    Accepts: "server01", "fs.acme.local", "8.8.8.8", "2606:4700::1111"
    Rejects: "-S 1.2.3.4", "host;rm -rf", "a..b", names over 253 chars
    """
    if not isinstance(value, str):
        raise ValidationError("host must be text")
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):  # [IPv6] URL-style brackets
        value = value[1:-1]
    if not value:
        raise ValidationError("host is empty")
    if value.startswith("-"):
        raise ValidationError(f"host may not start with '-': {value!r}")
    if is_ip(value):
        return value
    value = value.rstrip(".")
    if len(value) > 253:
        raise ValidationError("hostname is longer than 253 characters")
    labels = value.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise ValidationError(f"not a valid hostname or IP address: {value!r}")
    return value


def port(value: int | str) -> int:
    """Validate a TCP/UDP port number (1-65535) and return it as an int."""
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise ValidationError(f"port must be a number: {value!r}") from exc
    if not 1 <= number <= 65535:
        raise ValidationError(f"port out of range 1-65535: {number}")
    return number


def ports(value: str) -> list[int]:
    """
    Parse a port list such as "22,80,443" or "8000-8010" into integers.
    Ranges are capped at 1024 ports to avoid accidental huge scans.
    """
    result: list[int] = []
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = port(lo_s), port(hi_s)
            if hi < lo or hi - lo > 1024:
                raise ValidationError(f"port range too large or reversed: {part}")
            result.extend(range(lo, hi + 1))
        else:
            result.append(port(part))
    if not result:
        raise ValidationError("no ports given")
    return result


def url(value: str) -> str:
    """
    Validate an http:// or https:// URL and return it. A bare hostname is
    upgraded to https://hostname/ for convenience.
    """
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValidationError(f"only http/https URLs are supported: {value!r}")
    if not parts.hostname:
        raise ValidationError(f"URL has no host: {value!r}")
    hostname(parts.hostname)
    try:
        # Reading .port validates it; "javascript:alert(1)" (after the https://
        # prefix above) fails here because "alert(1)" isn't a port number.
        _ = parts.port
    except ValueError as exc:
        raise ValidationError(f"invalid port in URL: {value!r}") from exc
    if any(ord(c) < 32 for c in value):
        raise ValidationError("URL contains control characters")
    return value


def interface(value: str) -> str:
    """
    Validate a network interface name (as later passed to tcpdump -i,
    Restart-NetAdapter, ip link ...). Callers should ALSO confirm the name
    exists in the system's interface list before acting on it.
    """
    value = value.strip()
    if not _IFACE.match(value):
        raise ValidationError(f"not a valid interface name: {value!r}")
    return value


def bpf_filter(value: str) -> str:
    """
    Light sanity check on a raw BPF capture filter (e.g. "host 10.0.0.5 and
    port 53") passed to tcpdump/dumpcap. The filter is handed over as ONE
    argument (no shell), so the main risk is option injection; we reject a
    leading "-" and control characters, and cap the length.
    """
    value = value.strip()
    if not value:
        raise ValidationError("filter is empty")
    if value.startswith("-") or len(value) > 512 or any(ord(c) < 32 for c in value):
        raise ValidationError("filter rejected (starts with '-', too long, or has control characters)")
    return value


def cidr(value: str, max_hosts: int = 1024) -> ipaddress.IPv4Network:
    """
    Validate an IPv4 network such as "192.168.1.0/24" for a LAN sweep and
    refuse ranges bigger than max_hosts (a /22 by default), so a typo like
    "10.0.0.0/8" can't launch a 16-million-address scan.
    """
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValidationError(f"not a valid network: {value!r}") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValidationError("only IPv4 networks can be swept")
    if net.num_addresses > max_hosts:
        raise ValidationError(f"{net} has {net.num_addresses} addresses; limit is {max_hosts} (use --max-hosts to raise)")
    return net


def safe_text(value: str, limit: int = 300) -> str:
    """
    Make untrusted text (a server banner, an SSID, an LLDP system name sent by
    a switch) safe to print and store: strip control characters that could
    mess up the terminal (ANSI escape injection) or reports, and cap length.
    """
    cleaned = "".join(ch if (ch.isprintable() or ch == " ") else "?" for ch in str(value))
    return cleaned[:limit]
