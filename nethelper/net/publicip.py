"""
Public IP / ISP lookup: which address does the internet see this machine
coming from, and which network (ASN / ISP) owns it?

Useful for: confirming whether traffic goes out through the VPN or the local
ISP, spotting failover to a backup WAN link, checking firewall allow-lists,
and spotting CGNAT (when the router's WAN address differs from this one).

This contacts a third-party service (ipinfo.io by default; configurable in
the profile, disable with --offline). Only a plain HTTPS GET is sent; the
service sees this machine's public IP, as any website would.
"""

from __future__ import annotations

import json
import urllib.request

from nethelper import __version__
from nethelper.core.validate import safe_text

FALLBACK_V4 = "https://api.ipify.org?format=json"
FALLBACK_V6 = "https://api6.ipify.org?format=json"


def _get_json(url: str, timeout: float) -> dict:
    """HTTPS GET returning parsed JSON (certificate verified by urllib)."""
    req = urllib.request.Request(url, headers={"User-Agent": f"NetHelper/{__version__}",
                                               "Accept": "application/json"})
    # Security note (B310): validated https URL from config
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return json.loads(resp.read(65536).decode("utf-8", errors="replace"))


def lookup(url: str = "https://ipinfo.io/json", timeout: float = 6.0) -> dict:
    """
    Return {"ip", "hostname", "city", "region", "country", "org", "source"}.
    Falls back to ipify (IP only) if the primary service fails. Raises
    OSError/ValueError if both fail.
    """
    try:
        data = _get_json(url, timeout)
        keys = ("ip", "hostname", "city", "region", "country", "org", "timezone")
        out = {k: safe_text(str(data[k]), 120) for k in keys if data.get(k)}
        out["source"] = url
        if out.get("ip"):
            return out
    except (OSError, ValueError):
        pass
    data = _get_json(FALLBACK_V4, timeout)
    return {"ip": safe_text(str(data.get("ip", "")), 60), "source": FALLBACK_V4}


def lookup_v6(timeout: float = 4.0) -> str | None:
    """Public IPv6 address, or None if this machine has no working IPv6 path."""
    try:
        return safe_text(str(_get_json(FALLBACK_V6, timeout).get("ip", "")), 60) or None
    except (OSError, ValueError):
        return None
