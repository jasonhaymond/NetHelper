"""
Interactive menu shown when `nethelper` is run with no arguments.

Covers every feature through numbered sub-menus. Each item asks only for what
it needs - with defaults in [brackets], input validated and re-asked on
mistakes, and interfaces picked from a numbered list - then builds the same
command line you could type yourself and runs it through the regular CLI
(cli.execute). The menu and the command line therefore always behave
identically, and the equivalent command is shown each time so the shortcut
can be learned.

Also here: the Settings (.env) editor, guided settings setup, the Logs
browser and the Help browser.

Navigation: type a number and Enter; 0 or Enter on an empty line goes back;
q quits from anywhere; Ctrl+C cancels the current action and returns to the menu.
"""

from __future__ import annotations

import argparse
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from nethelper import APP_NAME, __version__, helptext
from nethelper.core import settings as settings_mod
from nethelper.core import validate
from nethelper.core.console import Console
from nethelper.core.privileges import detect, elevation_hint


class Quit(Exception):
    """Raised when the user types q to leave the menu entirely."""


class Back(Exception):
    """Raised when the user cancels an item's prompts (goes back without running)."""


@dataclass
class Prompt:
    """
    One question asked before running an item.
      label    - question text
      kind     - text | host | target | url | int | float | choice | iface | ifaces | yesno | file
      flag     - option name (e.g. "-c"); None = positional argument
      default  - shown in [brackets] and used on empty input (None = optional, omitted if blank)
      required - re-ask until answered
      choices  - allowed answers for kind="choice"
      lo, hi   - numeric limits
    """

    label: str
    kind: str = "text"
    flag: str | None = None
    default: str | None = None
    required: bool = False
    choices: tuple[str, ...] = ()
    lo: float | None = None
    hi: float | None = None


@dataclass
class Item:
    """A menu entry that runs a command: base argv + prompts (+ optional report offer)."""

    label: str
    argv: list[str]
    prompts: list[Prompt] = field(default_factory=list)
    report: bool = False


@dataclass
class Action:
    """A menu entry that calls a Python function (settings, logs, help screens)."""

    label: str
    func: Callable[[Console], None]


@dataclass
class Menu:
    """A sub-menu: a title and its entries."""

    label: str
    entries: list


IFACE_OPT = Prompt("Interface(s) to use (blank = automatic)", "ifaces", flag="-i")
ONE_IFACE = Prompt("Send from a specific interface? (blank = automatic)", "iface", flag="-i")


def build_tree() -> Menu:
    """The complete menu structure."""
    return Menu(f"{APP_NAME} {__version__}", [
        Item("Quick health check", ["quick"], [IFACE_OPT], report=True),
        Item("Full diagnostic (a few minutes)", ["full"], [
            IFACE_OPT, Prompt("Seconds to listen for the switch (LLDP/CDP)", "int", "--wait", "35", lo=5, hi=180)], report=True),
        Item("Test a host, website or port", ["check"], [
            Prompt("Host, IP, URL, host:port or 'gateway'", "target", required=True),
            Prompt("TCP ports to test (blank = automatic, e.g. 445 or 80,443)", "text", "-p"),
            Prompt("Always show the route (traceroute)?", "yesno", "--trace", "n")]),
        Menu("Interfaces (multiple adapters)", [
            Item("List active interfaces", ["interfaces"]),
            Item("List ALL interfaces (incl. down/virtual)", ["interfaces", "--all"]),
            Item("Test each interface's path (gateway / internet / DNS)", ["interfaces", "--test"], [IFACE_OPT], report=True),
            Item("Interface details (addresses, MAC, vendor)", ["interfaces", "-v"], [IFACE_OPT]),
        ]),
        Menu("Wi-Fi", [
            Item("Current connection & adapter", ["wifi", "status"]),
            Item("Scan nearby networks", ["wifi", "scan"]),
            Item("Channel congestion & recommendation", ["wifi", "channels"]),
            Item("Monitor signal & roaming (Ctrl+C to stop)", ["wifi", "monitor"], [
                Prompt("Seconds between samples", "float", "-n", "2", lo=0.5, hi=60),
                Prompt("Stop after seconds (blank = until Ctrl+C)", "int", "--duration", lo=1, hi=86400),
                Prompt("CSV file to log samples (blank = none)", "file", "--csv")]),
            Item("Saved Wi-Fi networks", ["wifi", "profiles"]),
        ]),
        Menu("Connectivity tools", [
            Item("Ping", ["ping"], [Prompt("Host, IP or 'gateway'", "target", required=True),
                                    Prompt("Count", "int", "-c", "10", lo=1, hi=10000),
                                    Prompt("Payload bytes", "int", "-s", "32", lo=0, hi=65000), ONE_IFACE]),
            Item("Traceroute", ["trace"], [Prompt("Host, IP or 'gateway'", "target", required=True)]),
            Item("DNS lookup (compare servers)", ["dns"], [
                Prompt("Name or IP", "text", required=True),
                Prompt("Record type", "choice", "-t", "A", choices=("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV", "CAA")),
                Prompt("Specific DNS server (blank = configured + public)", "host", "-s")]),
            Item("TCP port test", ["port"], [Prompt("Host, IP or 'gateway'", "target", required=True),
                                             Prompt("Ports (e.g. 22,80,443 or 8000-8010)", "text", required=True), ONE_IFACE]),
            Item("HTTP timing breakdown", ["http"], [Prompt("URL", "url", required=True)]),
            Item("TLS certificate", ["tls"], [Prompt("Host or host:port", "text", required=True)]),
            Item("Path MTU", ["mtu"], [Prompt("Host, IP or 'gateway' (blank = 1.1.1.1)", "target")]),
            Item("Local configuration only", ["info"], report=True),
        ]),
        Menu("Speed & throughput", [
            Item("Internet speed test (+ bufferbloat)", ["speed"]),
            Item("Throughput to the GATEWAY", ["throughput", "gateway"], [
                Prompt("Seconds per direction", "int", "-t", "10", lo=1, hi=60), ONE_IFACE]),
            Item("Throughput to a host (running 'nethelper serve' or iperf3)", ["throughput"], [
                Prompt("Host or IP", "target", required=True),
                Prompt("Direction", "choice", "--direction", "both", choices=("both", "upload", "download")),
                Prompt("Seconds per direction", "int", "-t", "10", lo=1, hi=60),
                Prompt("Parallel streams", "int", "-P", "1", lo=1, hi=8),
                Prompt("Server key (blank = from settings / none)", "text", "--key"), ONE_IFACE]),
            Item("UDP loss & jitter test (VoIP/video)", ["throughput", "--udp"], [
                Prompt("Host or IP running 'nethelper serve'", "target", required=True),
                Prompt("Send rate in Mb/s", "float", "--rate", "10", lo=0.01, hi=10000),
                Prompt("Seconds", "int", "-t", "10", lo=1, hi=60), ONE_IFACE]),
            Item("Run a throughput SERVER on this machine (Ctrl+C to stop)", ["serve"], [
                Prompt("Require a key? (blank = from settings / none)", "text", "--key"),
                Prompt("Exit after one test?", "yesno", "--once", "n")]),
        ]),
        Menu("LAN & switch", [
            Item("LAN overview (gateway identity, ARP, mDNS/UPnP, rogue DHCP)", ["lan"], report=True),
            Item("Sweep the local subnet (active scan)", ["lan", "--sweep"], report=True),
            Item("Sweep a specific network", ["lan"], [Prompt("Network (CIDR, e.g. 10.0.40.0/24)", "text", "--net", required=True)]),
            Item("Rogue DHCP check", ["dhcp"]),
            Item("Switchport: which switch/port/VLAN? (LLDP/CDP)", ["switchport"], [
                Prompt("Seconds to listen (65 for CDP-only switches)", "int", "--wait", "35", lo=5, hi=180), IFACE_OPT]),
            Item("All VLAN checks (use a profile with your VLAN plan)", ["vlan"], [
                Prompt("Site profile file (blank = none/default)", "file", "--profile")], report=True),
        ]),
        Menu("Packet capture", [
            Item("Capture with a preset", ["capture"], [
                Prompt("Preset", "choice", "-f", "all", choices=("all", "dns", "dhcp", "arp", "icmp", "lldp", "cdp",
                                                                   "l2discovery", "vlan", "tcp", "udp")),
                Prompt("Seconds", "int", "-d", "30", lo=1, hi=3600),
                Prompt("Stop after N packets (blank = no limit)", "int", "-c", lo=1, hi=10_000_000),
                Prompt("Save to file (blank = automatic)", "file", "-o"), ONE_IFACE]),
            Item("Capture traffic to/from one host", ["capture"], [
                Prompt("Host IP", "host", "-f", required=True), Prompt("Seconds", "int", "-d", "30", lo=1, hi=3600)]),
            Item("Capture with a raw BPF filter (dumpcap/tcpdump)", ["capture"], [
                Prompt("BPF filter (e.g. tcp port 445 and host 10.0.0.9)", "text", "--bpf", required=True),
                Prompt("Seconds", "int", "-d", "30", lo=1, hi=3600)]),
            Item("Summarise an existing capture file", ["capture"], [Prompt("pcap/pcapng file", "file", "--read", required=True)]),
        ]),
        Menu("Monitoring", [
            Item("Connection monitor (Ctrl+C to stop)", ["monitor"], [
                Prompt("Seconds between rounds", "float", "-n", "5", lo=1, hi=3600),
                Prompt("Stop after seconds (blank = until Ctrl+C)", "int", "--duration", lo=1, hi=604800),
                Prompt("CSV log file (blank = none)", "file", "--csv"), IFACE_OPT]),
            Item("Wi-Fi signal & roaming monitor", ["wifi", "monitor"], [
                Prompt("Seconds between samples", "float", "-n", "2", lo=0.5, hi=60),
                Prompt("CSV log file (blank = none)", "file", "--csv")]),
        ]),
        Menu("Baselines & reports", [
            Item("Save current state as a baseline", ["baseline", "save"], [
                Prompt("Baseline name", "text", default="default"), Prompt("Use a full run?", "yesno", "--full", "n")]),
            Item("Compare with a baseline", ["baseline", "diff"], [Prompt("Baseline name", "text", default="default")]),
            Item("List baselines", ["baseline", "list"]),
            Item("Convert / redact a saved JSON report", ["report"], [
                Prompt("Report .json file", "file", required=True),
                Prompt("Output file (.html/.md/.json)", "file", "-o", required=True),
                Prompt("Redact identifying details?", "yesno", "--redact", "y")]),
        ]),
        Menu("Repair actions", [
            Item("Flush DNS cache", ["fix", "flush-dns"]),
            Item("Renew DHCP lease", ["fix", "renew-dhcp"], [ONE_IFACE]),
            Item("Restart a network adapter", ["fix", "restart-adapter"], [Prompt("Interface", "iface", "-i", required=True)]),
            Item("Reset Winsock (Windows, needs reboot)", ["fix", "reset-winsock"]),
            Item("Reset TCP/IP stack (Windows, needs reboot)", ["fix", "reset-tcpip"]),
        ]),
        Menu("Output destinations (copy reports/captures/logs elsewhere)", [
            Item("Show configured destinations", ["dest", "list"]),
            Item("Add a destination", ["dest", "add"], [Prompt(
                "Destination (folder, \\\\server\\share, smb://, sftp://user@host/path, webdavs://, https://, ftps://, "
                "s3://bucket/prefix, mailto:address, syslog+tls://server)",
                "text", required=True)]),
            Item("Remove a destination", ["dest", "remove"], [Prompt("Destination to remove (exactly as listed)", "text", required=True)]),
            Item("Test all configured destinations", ["dest", "test"]),
            Item("Test one destination", ["dest", "test"], [Prompt("Destination", "text", required=True)]),
            Item("Upload a file now", ["upload"], [Prompt("File to upload", "file", required=True),
                                                   Prompt("Destination (blank = configured ones)", "text", "--to")]),
            Action("Destination types & credentials (help)", lambda con: con.print(helptext.topic_page("destinations"))),
        ]),
        Action("Settings (.env)", lambda con: settings_menu(con, _cli().SETTINGS.path if _cli().SETTINGS else settings_mod.env_path())),
        Action("Logs (last runs)", lambda con: logs_menu(con)),
        Action("Help & command reference", lambda con: help_menu(con)),
        Item("What can I run at this privilege level?", ["caps"]),
    ])


def _cli():
    """Import cli lazily (avoids a circular import at module load)."""
    from nethelper import cli

    return cli


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def ask(label: str, default: str | None = None) -> str:
    """Prompt for one line. 'q' raises Quit; Ctrl+D/EOF returns ''."""
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        answer = input(f"  {label}{suffix}: ").strip()
    except EOFError:
        raise Quit() from None
    if answer.lower() == "q":
        raise Quit()
    return answer


_iface_cache: list | None = None


def _interfaces() -> list:
    """Interfaces for the picker (collected once per menu session, light/fast)."""
    global _iface_cache
    if _iface_cache is None:
        from nethelper.system.facts import collect_snapshot

        snap = collect_snapshot(detect(), light=True)
        _iface_cache = [i for i in snap.interfaces if i.kind != "loopback"]
    return _iface_cache


def pick_interfaces(con: Console, label: str, multi: bool, required: bool) -> list[str]:
    """Show a numbered interface list; return chosen names (or ['all'])."""
    from nethelper.checks._util import first_ipv4

    ifaces = _interfaces()
    con.print(f"  {label}")
    for n, i in enumerate(ifaces, 1):
        state = "up" if i.up else "down"
        con.print(f"     {n:>2}) {i.name:<34} {i.kind:<8} {state:<4} {first_ipv4(i) or ''}")
    hint = "numbers separated by commas, 'a' = all" if multi else "a number"
    while True:
        answer = ask(f"Choose ({hint}; blank = {'none' if not required else 'cancel'})")
        if not answer:
            if required:
                raise Back()
            return []
        if multi and answer.lower() in ("a", "all"):
            return ["all"]
        try:
            picks = [int(x) for x in answer.replace(" ", "").split(",") if x]
            if not picks or any(not 1 <= p <= len(ifaces) for p in picks) or (not multi and len(picks) > 1):
                raise ValueError
            return [ifaces[p - 1].name for p in picks]
        except ValueError:
            con.print(con.c(f"  Please enter {hint} from the list.", "yellow"))


def answer_prompt(con: Console, p: Prompt) -> list[str]:
    """Ask one Prompt (re-asking on invalid input) and return the argv pieces it contributes."""
    while True:
        if p.kind in ("iface", "ifaces"):
            names = pick_interfaces(con, p.label, p.kind == "ifaces", p.required)
            return [p.flag, ",".join(names)] if names else []
        if p.kind == "choice":
            raw = ask(f"{p.label} ({'/'.join(p.choices)})", p.default) or (p.default or "")
        elif p.kind == "yesno":
            raw = (ask(f"{p.label} (y/n)", p.default) or p.default or "n").lower()
            if raw in ("y", "yes"):
                return [p.flag] if p.flag else []
            if raw in ("n", "no"):
                return []
            con.print(con.c("  Please answer y or n.", "yellow"))
            continue
        else:
            raw = ask(p.label, p.default) or (p.default or "")
        if not raw:
            if p.required:
                con.print(con.c("  This is required (q to quit, Ctrl+C to go back).", "yellow"))
                continue
            return []
        try:
            value = _validate(p, raw)
        except (ValueError, validate.ValidationError) as exc:
            con.print(con.c(f"  {exc}", "yellow"))
            continue
        if p.flag == "-f" and p.kind == "host":
            value = f"host:{value}"  # capture "host:<ip>" preset
        return [p.flag, value] if p.flag else [value]


def _validate(p: Prompt, raw: str) -> str:
    """Validate a typed answer for its prompt kind; returns the normalised text."""
    if p.kind == "host":
        return validate.hostname(raw)
    if p.kind == "target":
        if raw.lower() == "gateway" or "://" in raw:
            return validate.url(raw) if "://" in raw else "gateway"
        if raw.count(":") == 1 and not validate.is_ip(raw):
            h, port = raw.split(":")
            return f"{validate.hostname(h)}:{validate.port(port)}"
        return validate.hostname(raw)
    if p.kind == "url":
        return validate.url(raw)
    if p.kind in ("int", "float"):
        num = int(raw) if p.kind == "int" else float(raw)
        if (p.lo is not None and num < p.lo) or (p.hi is not None and num > p.hi):
            raise ValueError(f"must be between {p.lo:g} and {p.hi:g}")
        return str(num)
    if p.kind == "choice":
        match = [c for c in p.choices if c.lower() == raw.lower()]
        if not match:
            raise ValueError(f"choose one of: {', '.join(p.choices)}")
        return match[0]
    if p.kind == "file":
        if any(ord(c) < 32 for c in raw):
            raise ValueError("file name contains control characters")
        return raw.strip('"')
    return validate.safe_text(raw, 500)


# ---------------------------------------------------------------------------
# Running items
# ---------------------------------------------------------------------------

def run_item(con: Console, parser: argparse.ArgumentParser, item: Item) -> int:
    """Ask the item's questions, build the command line, show it, and run it."""
    import logging

    argv = list(item.argv)
    for p in item.prompts:
        argv += [a for a in answer_prompt(con, p) if a is not None]
    if item.report:
        save = ask("Save a report? File name (.html/.md/.json), or Enter to skip")
        if save:
            if not save.lower().endswith((".html", ".md", ".json")):
                save += ".html"
            folder = _cli()._settings().get("NETHELPER_REPORT_DIR")
            if folder and not Path(save).is_absolute():
                save = str(Path(folder).expanduser() / save)
            argv += ["--report", save]
    con.print(con.c(f"  equivalent command: nethelper {' '.join(shlex.quote(a) for a in argv)}", "grey"))
    logging.getLogger("nethelper.menu").info("menu action: %s", argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 3
    return _cli().execute(args)


def show_menu(con: Console, parser: argparse.ArgumentParser, menu: Menu, top: bool = False) -> int:
    """Display a menu level in a loop; returns the last exit code."""
    last = 0
    while True:
        con.print("")
        con.print(con.c(menu.label if not top else f"{APP_NAME} {__version__} - network troubleshooting", "bold", "cyan"))
        if top and not detect().elevated:
            con.print(con.c("Standard user: switchport/VLAN capture and some checks are limited. " + elevation_hint(), "yellow"))
        for n, entry in enumerate(menu.entries, 1):
            arrow = "  >" if isinstance(entry, Menu) else ""
            con.print(f"  {n:>2}) {entry.label}{arrow}")
        con.print("   0) " + ("Exit" if top else "Back") + con.c("     (q = quit, Ctrl+C = cancel)", "grey"))
        choice = ask("Choose")
        if choice in ("", "0"):
            return last
        if not choice.isdigit() or not 1 <= int(choice) <= len(menu.entries):
            con.print(con.c("  Please enter a number from the list.", "yellow"))
            continue
        entry = menu.entries[int(choice) - 1]
        try:
            if isinstance(entry, Menu):
                last = show_menu(con, parser, entry)
                continue
            if isinstance(entry, Action):
                entry.func(con)
                continue
            last = run_item(con, parser, entry)
            con.print(con.c(f"  (exit code {last})", "grey"))
        except Back:
            con.print("  cancelled")
            continue
        except KeyboardInterrupt:
            from nethelper.core import cmd

            cmd.stop_all()  # stop any capture tool left running by the interrupted action
            con.print("\n  stopped")
        ask("Press Enter to continue")


def interactive(parser: argparse.ArgumentParser) -> int:
    """Entry point for `nethelper` with no command."""
    con = _cli()._console(argparse.Namespace(no_color=False, json=False))
    try:
        return show_menu(con, parser, build_tree(), top=True)
    except Quit:
        return 0


# ---------------------------------------------------------------------------
# Settings, logs and help screens
# ---------------------------------------------------------------------------

def _reload_settings() -> None:
    """Re-read the .env file after a change so the rest of the session uses it."""
    cli = _cli()
    cli.SETTINGS = settings_mod.load(str(cli.SETTINGS.path) if cli.SETTINGS else None)


def settings_menu(con: Console, path: Path) -> None:
    """Interactive .env editor: pick a setting by number, change/reset it, saved immediately (with .env.bak backup)."""
    while True:
        values = settings_mod.current_file_values(path)
        con.heading(f"Settings - {path}" + ("" if path.exists() else " (not created yet)"))
        group = None
        for n, spec in enumerate(settings_mod.SPECS, 1):
            if spec.group != group:
                group = spec.group
                con.print(con.c(f"  -- {group} --", "cyan"))
            shown = settings_mod.MASK if spec.secret and values[spec.key] else (values[spec.key] or "(empty)")
            con.print(f"  {n:>2}) {spec.key:<36} {shown}")
        con.print("   g) guided setup of all settings    p) show file path    0) back")
        choice = ask("Setting number to change")
        if choice in ("", "0"):
            return
        if choice.lower() == "p":
            con.print(f"  {path}")
            continue
        if choice.lower() == "g":
            settings_init(con, path)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(settings_mod.SPECS):
            con.print(con.c("  Please enter a number from the list.", "yellow"))
            continue
        spec = settings_mod.SPECS[int(choice) - 1]
        con.print(f"  {spec.key}: {spec.help}")
        con.print(con.c(f"  default: {spec.default or '(empty)'}   current: "
                        f"{settings_mod.MASK if spec.secret and values[spec.key] else values[spec.key] or '(empty)'}", "grey"))
        new = ask("New value (Enter = keep, '-' = reset to default)")
        if not new:
            continue
        new = spec.default if new == "-" else new
        try:
            values[spec.key] = settings_mod.validate_value(spec.key, new)
        except ValueError as exc:
            con.print(con.c(f"  not saved: {exc}", "yellow"))
            continue
        backup = settings_mod.save(path, values)
        _reload_settings()
        con.print(con.c(f"  saved{' (previous version: ' + backup.name + ')' if backup else ''}", "green"))


def settings_init(con: Console, path: Path) -> int:
    """Guided setup: ask for every setting (Enter keeps the shown value). Asks before overwriting an existing file."""
    if path.exists():
        if ask(f"{path} already exists. Review and overwrite it? (yes/no)", "no").lower() != "yes":
            con.print("  left unchanged")
            return 0
    values = settings_mod.current_file_values(path)
    con.print("  Press Enter to keep each value; type 'skip' to keep all remaining values.")
    for spec in settings_mod.SPECS:
        shown = settings_mod.MASK if spec.secret and values[spec.key] else values[spec.key]
        while True:
            con.print(con.c(f"  {spec.key} - {spec.help}", "grey"))
            new = ask("value", shown)
            if new.lower() == "skip":
                break
            if not new or new == shown:
                break
            try:
                values[spec.key] = settings_mod.validate_value(spec.key, new)
                break
            except ValueError as exc:
                con.print(con.c(f"  {exc}", "yellow"))
        if new.lower() == "skip":
            break
    backup = settings_mod.save(path, values)
    _reload_settings()
    con.print(con.c(f"  settings saved to {path}" + (f" (previous: {backup.name})" if backup else ""), "green"))
    return 0


def logs_menu(con: Console) -> None:
    """Browse run logs: list, view whole, view the last lines."""
    from nethelper.core import logsetup

    folder = logsetup.log_dir(_cli()._settings().get("NETHELPER_LOG_DIR"))
    while True:
        runs = [r for r in logsetup.list_runs(folder) if r["path"] != logsetup.current_log()][:40]
        con.heading(f"Run logs - {folder}")
        con.table(["#", "started", "command", "exit", "size"],
                  [[n, r["started"], r["command"], r["exit"], f"{r['size'] // 1024} KB"] for n, r in enumerate(runs, 1)])
        choice = ask("Number to view (t<number> = last 60 lines, 0 = back)")
        if choice in ("", "0"):
            return
        tail = choice.lower().startswith("t")
        num = choice[1:] if tail else choice
        if not num.isdigit() or not 1 <= int(num) <= len(runs):
            con.print(con.c("  Please enter a number from the list.", "yellow"))
            continue
        text = runs[int(num) - 1]["path"].read_text(encoding="utf-8", errors="replace").splitlines()
        con.print(con.c(f"--- {runs[int(num) - 1]['path'].name} ---", "grey"))
        for line in (text[-60:] if tail else text):
            con.print(line)
        ask("Press Enter to continue")


def help_menu(con: Console) -> None:
    """Browse help pages for commands and topics."""
    pages = [("command", c) for c in helptext.COMMANDS] + [("topic", t) for t in helptext.TOPICS]
    while True:
        con.heading("Help - choose a page")
        for n, (kind, name) in enumerate(pages, 1):
            summary = helptext.COMMANDS[name]["summary"] if kind == "command" else helptext.TOPICS[name][0]
            con.print(f"  {n:>2}) {name:<12} {con.c(summary[:80], 'grey')}")
        con.print("   o) overview of all commands    0) back")
        choice = ask("Page")
        if choice in ("", "0"):
            return
        if choice.lower() == "o":
            con.print(helptext.overview())
        elif choice.isdigit() and 1 <= int(choice) <= len(pages):
            con.print("")
            con.print(helptext.lookup(pages[int(choice) - 1][1]) or "")
        else:
            con.print(con.c("  Please enter a number from the list.", "yellow"))
            continue
        ask("Press Enter to continue")
