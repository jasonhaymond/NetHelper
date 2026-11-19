"""
Opt-in repair actions: the standard "turn it off and on again" steps for
networking, run with explicit confirmation.

Every action:
  - is run only from `nethelper fix <action>`, never automatically
  - shows exactly which commands it will run and asks for confirmation
    (typing "yes"; --yes skips the prompt for scripted use)
  - warns loudly when the action will drop network connectivity and NetHelper
    appears to be running over SSH or Remote Desktop (you'd cut yourself off)
  - needs Administrator/root where the OS requires it, and says so
  - validates any interface name against the real interface list first

Actions:
  flush-dns        clear the DNS resolver cache
  renew-dhcp       release and re-request the DHCP lease (brief disconnect)
  restart-adapter  disable + re-enable a network adapter (disconnects it)
  reset-winsock    Windows: reset the Winsock catalogue (needs reboot)
  reset-tcpip      Windows: reset TCP/IP stack settings (needs reboot)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable

from nethelper.core import cmd

OS = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")


@dataclass
class Action:
    """
    A repair action.
      admin       - needs elevation on this OS
      disruptive  - drops connectivity while it runs
      needs_iface - requires an interface name
      reboot      - takes effect only after a reboot
      commands    - function(interface) -> list of argv lists to run in order
    """

    name: str
    description: str
    admin: bool
    disruptive: bool
    needs_iface: bool
    reboot: bool
    commands: Callable[[str | None], list[list[str]]]


def _flush_dns(_: str | None) -> list[list[str]]:
    if OS == "windows":
        return [["ipconfig", "/flushdns"]]
    if OS == "macos":
        return [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]
    if cmd.which("resolvectl"):
        return [["resolvectl", "flush-caches"]]
    return [["systemd-resolve", "--flush-caches"]]


def _renew_dhcp(iface: str | None) -> list[list[str]]:
    if OS == "windows":
        return [["ipconfig", "/release", iface], ["ipconfig", "/renew", iface]] if iface else \
            [["ipconfig", "/release"], ["ipconfig", "/renew"]]
    if not iface:  # Linux/macOS need an interface (the CLI enforces needs_iface)
        raise ValueError("renew-dhcp needs an interface name on this OS")
    if OS == "macos":
        return [["ipconfig", "set", iface, "DHCP"]]
    if cmd.which("nmcli"):
        return [["nmcli", "device", "reapply", iface]]
    if cmd.which("networkctl"):
        return [["networkctl", "renew", iface]]
    return [["dhclient", "-r", iface], ["dhclient", iface]]


def _restart_adapter(iface: str | None) -> list[list[str]]:
    if not iface:  # the CLI enforces needs_iface; this is a second guard
        raise ValueError("restart-adapter needs an interface name")
    if OS == "windows":
        return [["netsh", "interface", "set", "interface", f"name={iface}", "admin=disabled"],
                ["netsh", "interface", "set", "interface", f"name={iface}", "admin=enabled"]]
    if OS == "macos":
        return [["ifconfig", iface, "down"], ["ifconfig", iface, "up"]]
    return [["ip", "link", "set", "dev", iface, "down"], ["ip", "link", "set", "dev", iface, "up"]]


ACTIONS: dict[str, Action] = {
    "flush-dns": Action("flush-dns", "Clear the DNS resolver cache (fixes stale/incorrect cached answers).",
                        admin=True, disruptive=False, needs_iface=False, reboot=False,
                        commands=_flush_dns),
    "renew-dhcp": Action("renew-dhcp", "Release and renew the DHCP lease (new IP/gateway/DNS from the server).",
                         admin=True, disruptive=True, needs_iface=OS != "windows", reboot=False,
                         commands=_renew_dhcp),
    "restart-adapter": Action("restart-adapter", "Disable and re-enable a network adapter.",
                              admin=True, disruptive=True, needs_iface=True, reboot=False,
                              commands=_restart_adapter),
}
if OS == "windows":
    ACTIONS["reset-winsock"] = Action("reset-winsock", "Reset the Winsock catalogue (fixes broken LSPs left by "
                                      "old VPN/antivirus software).", admin=True, disruptive=False,
                                      needs_iface=False, reboot=True,
                                      commands=lambda _: [["netsh", "winsock", "reset"]])
    ACTIONS["reset-tcpip"] = Action("reset-tcpip", "Reset TCP/IP stack settings to defaults (removes static "
                                    "IP settings!).", admin=True, disruptive=True, needs_iface=False, reboot=True,
                                    commands=lambda _: [["netsh", "int", "ip", "reset"]])
