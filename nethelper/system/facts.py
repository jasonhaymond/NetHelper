"""
Entry point for gathering local system facts: picks the collector for the
current OS, fills in the cross-platform bits (hostname), and never lets a
collector crash the run - failures are recorded in Snapshot.errors instead.
"""

from __future__ import annotations

import logging
import socket
import time

from nethelper.core.privileges import Capabilities
from nethelper.system.model import Snapshot

log = logging.getLogger("nethelper.facts")


def collect_snapshot(caps: Capabilities, light: bool = False) -> Snapshot:
    """
    Collect and return a Snapshot of the local network configuration.
    light=True gathers only interfaces/addresses/routes/DNS where that's
    meaningfully faster (Windows); other OSes are already fast.
    """
    snap = Snapshot(hostname=socket.gethostname())
    started = time.perf_counter()
    try:
        if caps.os == "windows":
            from nethelper.system import windows

            windows.collect(snap, light=light)
        elif caps.os == "linux":
            from nethelper.system import linux

            linux.collect(snap)
        elif caps.os == "macos":
            from nethelper.system import macos

            macos.collect(snap)
        else:
            snap.errors.append(f"no collector for OS '{caps.os}'")
            return snap
    except Exception as exc:  # noqa: BLE001 - a broken collector must not stop diagnostics
        log.exception("facts collector failed")
        snap.errors.append(f"collector crashed: {type(exc).__name__}: {exc}")
    log.info("system facts collected in %.1f s (%s): %d interfaces, gateway %s, DNS %s",
             time.perf_counter() - started, "light" if light else "full", len(snap.interfaces),
             snap.default_gateway(), snap.dns_servers)
    for err in snap.errors:
        log.warning("facts: %s", err)
    return snap
