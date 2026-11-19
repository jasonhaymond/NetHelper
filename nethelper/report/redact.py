"""
Redaction: scrub identifying details from results before a report leaves
the machine (emailed to a vendor, attached to a ticket, posted to a forum).

Two levels:
  standard (--redact)      public IPv4/IPv6 addresses, MAC addresses, Wi-Fi
                           network names (SSIDs), this computer's hostname and
                           the current user name. Private (RFC1918) addresses
                           are kept, because they matter for troubleshooting and
                           don't identify a site from the outside.
  all (--redact-all)       additionally replaces private IP addresses.

Each distinct value gets a stable token (IP-1, MAC-2, SSID-1 ...), so the
report still shows "the same address appears in these three places"
without revealing what it is. Redaction works on the structured results, so
every output format (JSON/HTML/Markdown/bundle) is covered.
"""

from __future__ import annotations

import getpass
import ipaddress
import re
import socket
from typing import Any

# Regex: IPv4 address, e.g. "203.0.113.7" (word boundaries prevent matching inside longer numbers).
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Regex: IPv6 address, e.g. "2606:4700::1111" - at least two colons with hex groups.
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}(?::|[0-9a-fA-F]{1,4})(?:[0-9a-fA-F:]*)(?![\w:])")
# Regex: MAC address with ':' or '-' separators, e.g. "aa:bb:cc:dd:ee:ff" / "AA-BB-CC-DD-EE-FF".
_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b")

# Internal address ranges kept at the "standard" redaction level: they're
# useful for troubleshooting and don't identify a site from the internet.
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918 private
    "100.64.0.0/10",                                   # carrier-grade NAT
    "169.254.0.0/16",                                  # IPv4 link-local (APIPA)
    "fc00::/7", "fe80::/10",                           # IPv6 unique-local and link-local
)]


class Redactor:
    """Holds the value -> token mapping for one report so tokens stay consistent."""

    def __init__(self, level: str = "standard", extra_secrets: list[str] | None = None):
        self.level = level
        self.map: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        # Literal strings to hide: hostname, user name, and anything passed in (SSIDs).
        self.literals: list[tuple[str, str]] = []
        for value, kind in [(socket.gethostname(), "HOST"), (_safe_user(), "USER")] + \
                [(s, "SSID") for s in (extra_secrets or [])]:
            if value and len(value) >= 3:
                self.literals.append((value, self._token(kind, value)))
        # Longest first, so "office-wifi-5g" is replaced before "office-wifi".
        self.literals.sort(key=lambda kv: -len(kv[0]))

    def _token(self, kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in self.map:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.map[key] = f"{kind}-{self.counters[kind]}"
        return self.map[key]

    def _ip(self, match: re.Match) -> str:
        text = match.group(0)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        # Never informative to hide: loopback, 0.0.0.0/::, multicast.
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return text
        # Internal (RFC1918 / CGNAT / ULA / link-local) addresses are kept
        # unless --redact-all. An explicit list is used rather than Python's
        # is_private, which also counts some routable special ranges as private.
        if self.level != "all" and any(ip in net for net in _INTERNAL_NETS if net.version == ip.version):
            return text
        if str(ip) == "255.255.255.255":  # limited broadcast - not identifying
            return text
        return self._token("IP", str(ip))

    def text(self, value: str) -> str:
        """Redact one string."""
        for literal, token in self.literals:
            if literal in value:
                value = value.replace(literal, token)
        value = _MAC.sub(lambda m: m.group(0) if m.group(0).lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
                         else self._token("MAC", m.group(0).replace("-", ":").lower()), value)
        value = _IPV4.sub(self._ip, value)
        value = _IPV6.sub(self._ip, value)
        return value

    def walk(self, obj: Any) -> Any:
        """Recursively redact every string inside dicts/lists/tuples (keys included)."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.walk(k) if isinstance(k, str) else k: self.walk(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.walk(v) for v in obj]
        return obj


def _safe_user() -> str:
    """Current user name, or empty if it can't be determined."""
    try:
        return getpass.getuser()
    except (OSError, KeyError, ImportError):
        return ""
