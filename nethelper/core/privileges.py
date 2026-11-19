"""
Detects what NetHelper is able to do on this machine right now:
  - Are we elevated? (Administrator on Windows, root on Linux/macOS)
  - Which helper programs are installed (tcpdump, tshark, pktmon, lldpctl...)?
  - Which packet-capture methods are therefore usable?

NetHelper is designed to run both elevated and non-elevated. Each check
declares what it needs (see registry.py); the runner compares that against the
Capabilities found here to decide whether to run a check fully, run it with
reduced detail, or skip it with a clear "needs administrator" note.

`nethelper caps` prints this information directly.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from functools import lru_cache

from nethelper.core import cmd

# Helper programs NetHelper can use when present. None are required; each
# simply unlocks or improves certain checks.
OPTIONAL_TOOLS = [
    "ping", "ping6", "traceroute", "tracert", "tracepath",
    "tcpdump", "tshark", "dumpcap", "pktmon",
    "lldpctl", "iperf3", "arping",
    "ip", "ss", "nmcli", "iw", "resolvectl", "ethtool",
    "ifconfig", "netstat", "scutil", "networksetup", "ipconfig", "arp",
    "powershell", "netsh", "ufw", "firewall-cmd", "nft",
]


def os_name() -> str:
    """Return a simple OS key used throughout NetHelper: windows / linux / macos / other."""
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    return "other"


def is_elevated() -> bool:
    """
    True when running with administrator/root rights.

    - Windows: asks the shell32 DLL "is the current user an admin in this
      process?" - this is False in a normal terminal even for an admin account
      unless the terminal was started with "Run as administrator" (UAC).
    - Linux/macOS: the effective user id is 0 (root), e.g. under sudo.
    """
    if os_name() == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def elevation_hint(command: str = "nethelper") -> str:
    """
    Plain-English instructions for re-running with elevated rights,
    tailored to the OS. Printed whenever checks were limited by privileges.
    """
    if os_name() == "windows":
        return ('Open a terminal with "Run as administrator" (right-click Windows Terminal / '
                f'PowerShell -> Run as administrator) and run "{command}" again.')
    return f'Re-run with sudo, e.g.: sudo {command}'


@dataclass
class Capabilities:
    """
    Snapshot of the environment, gathered once per run.

    Fields:
      os        - windows / linux / macos / other
      elevated  - running as Administrator/root
      tools     - map of tool name -> full path, only for tools that exist
      os_detail - human description, e.g. "Windows 11 (10.0.26300)"
      python    - Python version string
    """

    os: str
    elevated: bool
    tools: dict[str, str] = field(default_factory=dict)
    os_detail: str = ""
    python: str = ""

    def has(self, tool: str) -> bool:
        """True when the named helper program is installed."""
        return tool in self.tools

    def capture_backends(self) -> list[tuple[str, bool, str]]:
        """
        List every packet-capture method and whether it's usable right now.

        Returns (name, usable, note) tuples, in order of preference. Logic:
          dumpcap/tshark - Wireshark's capture engine. Works non-elevated when
                           Npcap (Windows) was installed without "admin only",
                           or the user is in the `wireshark` group (Linux), or
                           ChmodBPF is installed (macOS). We can't know for sure
                           without trying, so it's "usable (may need admin)".
          tcpdump        - Linux/macOS; needs root (or BPF permissions on macOS).
          pktmon         - built into Windows 10 2004+/11; always needs admin.
          raw socket     - Linux only, built into Python; needs root.
        """
        out: list[tuple[str, bool, str]] = []
        for tool in ("dumpcap", "tshark"):
            if self.has(tool):
                note = "installed" + ("" if self.elevated else " (non-admin capture works only if permitted by Npcap/wireshark group)")
                out.append((tool, True, note))
        if self.has("tcpdump") and self.os in ("linux", "macos"):
            out.append(("tcpdump", self.elevated or self.os == "macos",
                        "installed" if self.elevated else "installed, needs root (macOS: works if BPF devices are readable)"))
        if self.os == "windows":
            if self.has("pktmon"):
                out.append(("pktmon", self.elevated, "built into Windows" + ("" if self.elevated else ", needs Administrator")))
        if self.os == "linux":
            out.append(("rawsocket", self.elevated, "built into Python" + ("" if self.elevated else ", needs root")))
        return out

    def can_capture(self) -> bool:
        """True when at least one capture method should work right now."""
        return any(usable for _, usable, _ in self.capture_backends())


@lru_cache(maxsize=1)
def detect() -> Capabilities:
    """
    Gather Capabilities once and cache them (lru_cache memoises the result so
    repeated calls are free). Looking up ~30 programs on PATH is cheap but
    there's no reason to repeat it for every check.
    """
    tools = {}
    for tool in OPTIONAL_TOOLS:
        path = cmd.which(tool)
        if path:
            tools[tool] = path
    name = os_name()
    if name == "windows":
        detail = f"Windows {platform.release()} ({platform.version()})"
    elif name == "macos":
        detail = f"macOS {platform.mac_ver()[0]}"
    else:
        detail = f"{platform.system()} {platform.release()}"
        try:
            # /etc/os-release describes the Linux distribution (e.g. "Ubuntu 24.04 LTS").
            with open("/etc/os-release", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        detail = line.split("=", 1)[1].strip().strip('"') + f" (kernel {platform.release()})"
                        break
        except OSError:
            pass
    return Capabilities(
        os=name,
        elevated=is_elevated(),
        tools=tools,
        os_detail=detail,
        python=platform.python_version(),
    )
