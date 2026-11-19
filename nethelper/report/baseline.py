"""
Baselines: save a "known good" run, then compare a later run against it.

The usual troubleshooting question is "what changed?". A baseline captured
when everything worked answers it directly: a different gateway MAC, new DNS
servers, a different public IP/ISP, the jack now patched into another switch
port or VLAN, a link that dropped from 1000 to 100 Mb/s, latency that doubled,
or checks that used to pass and now fail.

Baselines are JSON report documents stored in <data dir>/baselines/<name>.json.
Names are restricted to letters, digits, dash and underscore so a name can
never escape that folder (path traversal like "../../somewhere").
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from nethelper.core.paths import sub_dir
from nethelper.core.validate import ValidationError

# Regex: allowed baseline names - 1-64 of letters, digits, "-" or "_".
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _path(name: str) -> Path:
    """Map a validated baseline name to its file."""
    if not _NAME.match(name):
        raise ValidationError("baseline names may only contain letters, digits, '-' and '_' (max 64)")
    return sub_dir("baselines") / f"{name}.json"


def save(name: str, doc: dict) -> Path:
    """Store a report document as the named baseline (overwrites)."""
    path = _path(name)
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return path


def load(name: str) -> dict:
    """Load a named baseline, or a JSON report file path. Raises FileNotFoundError."""
    candidate = Path(name)
    if candidate.suffix.lower() == ".json" and candidate.is_file():
        return json.loads(candidate.read_text(encoding="utf-8"))
    return json.loads(_path(name).read_text(encoding="utf-8"))


def list_names() -> list[tuple[str, str]]:
    """(name, generated-timestamp) for each saved baseline."""
    out = []
    for p in sorted(sub_dir("baselines").glob("*.json")):
        try:
            out.append((p.stem, json.loads(p.read_text(encoding="utf-8")).get("generated", "?")))
        except (OSError, json.JSONDecodeError):
            out.append((p.stem, "unreadable"))
    return out


def by_id(doc: dict) -> dict[str, dict]:
    """Index a report document's results by check id."""
    return {r["check_id"]: r for r in doc.get("results", [])}


def _get(d: dict, *keys, default=None):
    """Safely read a nested value: _get(x, "details", "gateway")."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


# (label, check id, path inside the result) for facts worth comparing.
FACTS = [
    ("Default gateway", "local.routing", ("summary",)),
    ("Gateway MAC", "lan.gateway_mac", ("details", "mac")),
    ("DNS servers", "local.dns_config", ("details", "servers")),
    ("Primary interface", "local.interfaces", ("details", "primary")),
    ("Public IP", "app.public_ip", ("details", "ip")),
    ("ISP / ASN", "app.public_ip", ("details", "org")),
    ("Switchport", "l2.switchport", ("summary",)),
    ("Observed VLAN", "l2.vlan_validation", ("details", "observed_vlan")),
    ("Link", "l2.link", ("summary",)),
    ("Wi-Fi", "local.wifi", ("summary",)),
    ("VPN", "local.vpn", ("summary",)),
    ("Path MTU", "conn.mtu", ("details", "mtu")),
]
# Latency measurements compared for big relative increases.
LATENCY = [("Gateway latency", "conn.gateway_ping", ("details", "avg_ms"))]


def diff(old: dict, new: dict) -> dict:
    """
    Compare two report documents. Returns:
      status_changes - checks whose status changed (e.g. PASS -> FAIL)
      fact_changes   - key facts that differ
      latency        - latency increases of more than 50% (and > 5 ms)
    """
    a, b = by_id(old), by_id(new)
    status_changes = []
    for cid in sorted(set(a) | set(b)):
        sa, sb = _get(a, cid, "status"), _get(b, cid, "status")
        if sa and sb and sa != sb and "SKIP" not in (sa, sb):
            status_changes.append({"check": cid, "title": _get(b, cid, "title") or cid, "before": sa, "after": sb,
                                   "now": _get(b, cid, "summary")})
    facts = []
    for label, cid, path in FACTS:
        va, vb = _get(a.get(cid, {}), *path), _get(b.get(cid, {}), *path)
        if va is not None and vb is not None and va != vb:
            facts.append({"fact": label, "before": va, "after": vb})
    latency = []
    for label, cid, path in LATENCY:
        va, vb = _get(a.get(cid, {}), *path), _get(b.get(cid, {}), *path)
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)) and vb > va * 1.5 and vb - va > 5:
            latency.append({"metric": label, "before_ms": va, "after_ms": vb})
    targets_a = {t["target"]: t for t in _get(a.get("conn.internet_ping", {}), "details", "targets", default=[]) or []}
    for t in _get(b.get("conn.internet_ping", {}), "details", "targets", default=[]) or []:
        before = targets_a.get(t["target"], {}).get("avg_ms")
        after = t.get("avg_ms")
        if isinstance(before, (int, float)) and isinstance(after, (int, float)) and after > before * 1.5 and after - before > 5:
            latency.append({"metric": f"Latency to {t['target']}", "before_ms": before, "after_ms": after})
    return {"baseline_generated": old.get("generated"), "status_changes": status_changes,
            "fact_changes": facts, "latency": latency}
