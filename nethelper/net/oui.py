"""
MAC address -> hardware vendor lookup ("OUI" = Organizationally Unique
Identifier, the first 3 bytes of a MAC address assigned to a manufacturer).

Knowing a device is "Ubiquiti", "HP" or "Espressif" (cheap IoT chips) makes an
ARP table or LAN sweep far more useful. The vendor database is not bundled
(it's ~4 MB and changes weekly); sources are used in this order:
  1. <data dir>/oui.csv           downloaded by `nethelper oui update` (IEEE registry)
  2. Wireshark's "manuf" file      if Wireshark is installed
  3. /usr/share/ieee-data/oui.txt  Debian/Ubuntu ieee-data package
  4. nmap's nmap-mac-prefixes      if nmap is installed

Also detects *randomised* (locally administered) MACs: phones and laptops
use a random MAC per Wi-Fi network for privacy, so "unknown vendor" for those
is expected, not suspicious.
"""

from __future__ import annotations

import csv
import io
import os
import threading
import urllib.request
from pathlib import Path

from nethelper import __version__
from nethelper.core.paths import data_dir

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"

_db: dict[str, str] | None = None
_lock = threading.Lock()


def _candidate_files() -> list[Path]:
    """Places a vendor database might exist on this machine."""
    paths = [data_dir() / "oui.csv"]
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), "/usr/share", "/usr/local/share",
                 "/opt/homebrew/share", "/Applications/Wireshark.app/Contents/Resources/share"):
        paths.append(Path(base) / "Wireshark" / "manuf")
        paths.append(Path(base) / "wireshark" / "manuf")
    paths += [Path("/usr/share/ieee-data/oui.txt"), Path("/usr/share/nmap/nmap-mac-prefixes"),
              Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Nmap" / "nmap-mac-prefixes"]
    return paths


def _load_file(path: Path, db: dict[str, str]) -> None:
    """Parse one vendor file (format detected from its name/contents) into db."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "oui.csv":
        # IEEE CSV columns: Registry, Assignment (6 hex digits), Organization Name, Address
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 3 and len(row[1]) == 6:
                db.setdefault(row[1].upper(), row[2].strip())
    elif path.name == "oui.txt":
        for line in text.splitlines():
            if "(base 16)" in line:
                prefix, _, name = line.partition("(base 16)")
                db.setdefault(prefix.strip().upper(), name.strip())
    elif path.name == "manuf":
        # Wireshark manuf: "00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc" (short name, then full name).
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            prefix = parts[0].replace(":", "").replace("-", "").upper() if parts else ""
            if len(parts) >= 2 and len(prefix) == 6:  # skip /28 and /36 sub-blocks
                db.setdefault(prefix, parts[2] if len(parts) >= 3 else parts[1])
    else:
        # nmap-mac-prefixes: "00000C Cisco Systems"
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and len(parts[0]) == 6:
                db.setdefault(parts[0].upper(), parts[1].strip())


def _database() -> dict[str, str]:
    """Load (once) and return the merged prefix -> vendor dictionary."""
    global _db
    with _lock:
        if _db is None:
            db: dict[str, str] = {}
            for path in _candidate_files():
                try:
                    if path.is_file():
                        _load_file(path, db)
                except OSError:
                    continue
            _db = db
        return _db


def is_randomized(mac: str | None) -> bool:
    """
    True if the MAC is "locally administered" - bit 0x02 of the first byte.
    That's how randomised/private Wi-Fi MACs (and many VMs) are marked.
    """
    if not mac:
        return False
    try:
        return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def vendor(mac: str | None) -> str | None:
    """Return the vendor name for a MAC, "randomized" for private MACs, or None."""
    if not mac:
        return None
    if is_randomized(mac):
        return "(randomized/private MAC)"
    prefix = "".join(c for c in mac.upper() if c in "0123456789ABCDEF")[:6]
    return _database().get(prefix)


def database_size() -> int:
    """Number of vendor prefixes loaded (0 = no database available)."""
    return len(_database())


def update(timeout: float = 60.0) -> tuple[Path, int]:
    """
    Download the IEEE OUI registry to <data dir>/oui.csv over HTTPS
    (certificate verified). Returns (path, number of entries).
    """
    global _db
    req = urllib.request.Request(IEEE_URL, headers={"User-Agent": f"NetHelper/{__version__}"})
    # Security note (B310): fixed https URL
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        body = resp.read(50_000_000)
    target = data_dir() / "oui.csv"
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(body)
    tmp.replace(target)  # atomic swap so a failed download never leaves half a file
    with _lock:
        _db = None
    return target, database_size()
