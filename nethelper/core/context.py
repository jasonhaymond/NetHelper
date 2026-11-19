"""
The shared "context" object handed to every check while a run is in progress.

It bundles:
  - caps     what this machine/privilege level can do (privileges.py)
  - profile  the site profile (config.py)
  - options  command-line choices (timeouts, interface, intrusive allowed...)
  - facts    the system snapshot (interfaces, routes, DNS...) - collected once
  - memo()   a thread-safe cache so expensive work shared by several checks
             (e.g. listening for LLDP from the switch for 35 seconds) happens
             exactly once even though checks run in parallel

Checks run concurrently in a thread pool, so anything shared here must be
safe to use from several threads at once; that's what the locks are for.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from nethelper.core.config import Profile
from nethelper.core.privileges import Capabilities


@dataclass
class Options:
    """
    Run-time choices, mostly from command-line flags.

      timeout          - default per-operation network timeout (seconds)
      interfaces       - adapters to restrict interface-specific checks to
                         (empty = automatic; ["all"] = every usable adapter);
                         names are checked against the real list by the CLI
      allow_intrusive  - permit scan-like checks (LAN sweep)
      external         - permit contacting third-party services (public IP
                         lookup, speed test); False with --offline
      targets          - extra hosts/URLs given on the command line
      switchport_wait  - seconds to listen for LLDP/CDP (overrides profile)
      ping_count       - echo requests per ping test
      baseline         - previously saved results to compare against (or None)
      settings         - the loaded .env Settings (or None in tests)
    """

    timeout: float = 3.0
    interfaces: list[str] = field(default_factory=list)
    allow_intrusive: bool = False
    external: bool = True
    targets: list[str] = field(default_factory=list)
    switchport_wait: int | None = None
    ping_count: int = 10
    baseline: dict | None = None
    settings: Any = None

    @property
    def interface(self) -> str | None:
        """The single explicitly chosen interface, if exactly one was given (else None)."""
        if len(self.interfaces) == 1 and self.interfaces[0].lower() != "all":
            return self.interfaces[0]
        return None

    @property
    def all_interfaces(self) -> bool:
        """True when the user asked for every interface (-i all)."""
        return any(i.lower() == "all" for i in self.interfaces)

    def setting(self, key: str, default: Any = None) -> Any:
        """Read a .env setting, falling back to `default` when settings aren't loaded (tests)."""
        return self.settings.get(key) if self.settings is not None else default


class Context:
    """State shared by all checks in one run. See module docstring."""

    def __init__(self, caps: Capabilities, profile: Profile, options: Options | None = None):
        self.caps = caps
        self.profile = profile
        self.options = options or Options()
        self.log = logging.getLogger("nethelper.check")
        self._memo: dict[str, Any] = {}
        self._memo_locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._facts = None

    @property
    def facts(self):
        """
        The system snapshot (interfaces, routes, DNS servers, ...), collected
        on first use and then reused by every check. Imported lazily to keep
        start-up fast for commands that never need it (e.g. `nethelper ping`).
        """
        def collect():
            from nethelper.system.facts import collect_snapshot

            return collect_snapshot(self.caps)

        return self.memo("facts", collect)

    def memo(self, key: str, producer: Callable[[], Any]) -> Any:
        """
        Return the cached value for `key`, computing it with `producer()` the
        first time. If two checks ask for the same key at the same moment, the
        second waits for the first instead of doing the work twice.

        If the producer raises, the exception is cached and re-raised for every
        caller, so a failing shared step is reported consistently.
        """
        with self._guard:
            lock = self._memo_locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._memo:
                try:
                    self._memo[key] = ("ok", producer())
                except Exception as exc:  # noqa: BLE001 - cached and re-raised below
                    self._memo[key] = ("err", exc)
            kind, value = self._memo[key]
        if kind == "err":
            raise value
        return value

    @property
    def threshold(self):
        """Shortcut to the profile's warning thresholds."""
        return self.profile.thresholds

    def switchport_wait(self) -> int:
        """Seconds to listen for switch discovery frames (flag beats profile)."""
        return self.options.switchport_wait or self.profile.switchport_wait
