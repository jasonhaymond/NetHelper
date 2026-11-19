"""
NetHelper's command-line interface: parses what the user typed and runs it.

Design goal: simple to use. Running `nethelper` with no arguments opens an
interactive menu (menu.py) covering every feature. Everything is also a short
command for scripting; `nethelper help` lists them all with examples
(help text lives in helptext.py).

Every invocation:
  1. loads settings from the .env file (settings.py)
  2. opens a per-run log file (logsetup.py; the newest 40 are kept)
  3. runs the command inside execute(), which turns every kind of failure
     into a clear one-line message + exit code (and a traceback in the log)
  4. on Ctrl+C, stops any running capture tools before exiting

Exit codes: 0 all good, 1 warnings, 2 failures found, 3 usage or
configuration error, 4 unexpected internal error, 130 interrupted (Ctrl+C).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path

from nethelper import APP_NAME, __version__, helptext
from nethelper.core import cmd as runcmd
from nethelper.core import destinations
from nethelper.core import settings as settings_mod
from nethelper.core import validate
from nethelper.core.config import ProfileError, load_profile
from nethelper.core.console import Console
from nethelper.core.context import Context, Options
from nethelper.core.logsetup import current_log, end_run, start_run
from nethelper.core.privileges import detect, elevation_hint
from nethelper.core.registry import REGISTRY, SECTION_TITLES, SECTIONS, Admin, load_all, select
from nethelper.core.result import Status
from nethelper.core.runner import gate, run_checks

log = logging.getLogger("nethelper.cli")

EXIT_USAGE = 3
EXIT_INTERNAL = 4
EXIT_INTERRUPTED = 130

# Settings loaded once per process (main() sets it; tests may replace it).
SETTINGS: settings_mod.Settings | None = None


def _settings() -> settings_mod.Settings:
    """The loaded settings (loading defaults on first use)."""
    global SETTINGS
    if SETTINGS is None:
        SETTINGS = settings_mod.load()
    return SETTINGS


class UsageError(Exception):
    """A user mistake (bad interface name, bad combination of options). Message is shown as-is."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _common() -> argparse.ArgumentParser:
    """Options accepted by every command (a 'parent' parser shared by all)."""
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("common options")
    g.add_argument("--profile", metavar="FILE", help="site profile (TOML) with targets/expectations")
    g.add_argument("-i", "--interface", action="append", default=[], metavar="NAME[,NAME]",
                   help="adapter(s) to use: a name, comma list, repeat -i, or 'all' (see 'nethelper interfaces')")
    g.add_argument("--timeout", type=float, default=None, metavar="SEC", help="per-probe timeout (default from settings, 3)")
    g.add_argument("--report", metavar="FILE", help="save a report: .html, .md or .json")
    g.add_argument("--bundle", metavar="FILE.zip", help="save report + raw outputs + captures as a zip")
    g.add_argument("--redact", action="store_true", help="hide public IPs, MACs, SSIDs, host/user names in reports")
    g.add_argument("--redact-all", action="store_true", help="like --redact, and hide private IPs too")
    g.add_argument("--json", action="store_true", help="print results as JSON instead of text")
    g.add_argument("--hide-limited", action="store_true", default=None, help="hide checks that need elevation")
    g.add_argument("--offline", action="store_true", help="don't contact third-party services (public IP, speed test)")
    g.add_argument("--allow-intrusive", action="store_true", help="allow scan-like checks (LAN sweep)")
    g.add_argument("--target", action="append", default=[], metavar="HOST|URL|HOST:PORT",
                   help="extra target to test (repeatable)")
    g.add_argument("--upload", action="append", default=[], metavar="DEST",
                   help="copy this run's outputs to DEST (folder, \\\\server\\share, smb://, sftp://, webdavs://, https://, "
                        "ftps://, s3://, mailto:, syslog+tls://)")
    g.add_argument("--no-upload", action="store_true", help="don't copy outputs to the destinations configured in settings")
    g.add_argument("--env", metavar="FILE", help="use this settings file instead of the default .env")
    g.add_argument("-v", "--verbose", action="store_true", help="show check details and echo the log to the screen")
    g.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p


def build_parser() -> argparse.ArgumentParser:
    """Define every command and its options (descriptions/examples come from helptext.py)."""
    common = _common()
    parser = argparse.ArgumentParser(
        prog="nethelper",
        description=f"{APP_NAME} {__version__} - cross-platform network troubleshooting. "
                    "Run with no command for the interactive menu; 'nethelper help' for all commands and examples.",
        epilog="Common options go after the command, e.g.: nethelper quick --report site.html",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("--env", metavar="FILE", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="command")

    def add(name: str) -> argparse.ArgumentParser:
        info = helptext.COMMANDS[name]
        return sub.add_parser(name, help=info["summary"], description=f"{info['summary']}.\n\n{info['description']}",
                              epilog=helptext.epilog(name), parents=[common],
                              formatter_class=argparse.RawDescriptionHelpFormatter)

    for name in ("quick", "full"):
        p = add(name)
        p.add_argument("--save-baseline", metavar="NAME", help="also save this run as a named baseline")
        p.add_argument("--compare", metavar="NAME", help="compare against a saved baseline (or report .json)")
        if name == "full":
            p.add_argument("--wait", type=int, metavar="SEC", help="seconds to listen for LLDP/CDP (default 35)")

    p = add("check")
    p.add_argument("target", help="hostname, IP, URL, host:port, or 'gateway'")
    p.add_argument("-p", "--ports", help="TCP ports to test, e.g. 445 or 80,443 or 8000-8010")
    p.add_argument("--trace", action="store_true", help="always include a traceroute")

    p = add("interfaces")
    p.add_argument("--all", action="store_true", help="include disconnected and virtual adapters")
    p.add_argument("--test", action="store_true", help="test gateway/internet/DNS through each adapter")

    p = add("wifi")
    p.add_argument("action", nargs="?", default="status", choices=["status", "scan", "channels", "monitor", "profiles"])
    p.add_argument("-n", "--interval", type=float, default=2.0, help="monitor: seconds between samples (default 2)")
    p.add_argument("--duration", type=float, help="monitor: stop after this many seconds")
    p.add_argument("--csv", metavar="FILE", help="monitor: append samples to a CSV file")

    p = add("ping")
    p.add_argument("host", help="host, IP, or 'gateway'")
    p.add_argument("-c", "--count", type=int, default=None, help="number of pings (default from settings, 10)")
    p.add_argument("-s", "--size", type=int, default=32, help="payload bytes (default 32)")

    p = add("trace")
    p.add_argument("host", help="host, IP, or 'gateway'")
    p.add_argument("--max-hops", type=int, default=30)

    p = add("dns")
    p.add_argument("name")
    p.add_argument("-t", "--type", default="A", help="record type: A AAAA MX TXT NS SOA CNAME PTR SRV CAA")
    p.add_argument("-s", "--server", action="append", help="query this DNS server (repeatable)")

    p = add("port")
    p.add_argument("host", help="host, IP, or 'gateway'")
    p.add_argument("ports", help="e.g. 22 or 80,443 or 8000-8010")

    p = add("http")
    p.add_argument("url")

    p = add("tls")
    p.add_argument("host", help="host or host:port")

    p = add("mtu")
    p.add_argument("host", nargs="?", default=None, help="host, IP, or 'gateway' (default: profile trace target)")

    add("info")
    p = add("lan")
    p.add_argument("--sweep", action="store_true", help="also actively sweep the local subnet")
    p.add_argument("--net", metavar="CIDR", help="sweep this network instead (max /22 unless --max-hosts)")
    p.add_argument("--max-hosts", type=int, default=1024)
    p = add("switchport")
    p.add_argument("--wait", type=int, metavar="SEC", help="seconds to listen (default 35; CDP needs ~65)")
    p = add("vlan")
    p.add_argument("--wait", type=int, metavar="SEC", help="seconds to listen for LLDP/CDP")
    add("dhcp")
    p = add("speed")
    p.add_argument("--no-latency", action="store_true", help="skip latency-under-load (bufferbloat) measurement")

    p = add("throughput")
    p.add_argument("target", help="host/IP running 'nethelper serve' (or iperf3), or 'gateway'")
    p.add_argument("-t", "--seconds", type=int, help="seconds per direction (default from settings, 10)")
    p.add_argument("-P", "--parallel", type=int, help="parallel TCP streams (default from settings, 1)")
    p.add_argument("--direction", choices=["both", "upload", "download"], default="both")
    p.add_argument("--udp", action="store_true", help="UDP test: report loss and jitter at --rate")
    p.add_argument("--rate", type=float, default=10.0, help="UDP send rate in Mb/s (default 10)")
    p.add_argument("--size", type=int, default=1200, help="UDP packet size in bytes (default 1200)")
    p.add_argument("--port", type=int, help="server port (default from settings, 5202)")
    p.add_argument("--key", help="shared key if the server requires one (default from settings)")
    p.add_argument("--no-fallback", action="store_true", help="don't fall back to iperf3/ICMP load")

    p = add("serve")
    p.add_argument("--bind", default=None, help="listen address (default: all addresses)")
    p.add_argument("--port", type=int, help="port (default from settings, 5202)")
    p.add_argument("--key", help="require this shared key (default from settings)")
    p.add_argument("--once", action="store_true", help="exit after one completed test")

    p = add("capture")
    p.add_argument("-d", "--duration", type=float, default=30, help="seconds to capture (default 30)")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    p.add_argument("-f", "--filter", default="all", help="filter preset (default all)")
    p.add_argument("--bpf", help="raw BPF filter for dumpcap/tcpdump, e.g. \"host 10.0.0.5 and port 53\"")
    p.add_argument("-o", "--output", help="capture file to write (.pcap/.pcapng)")
    p.add_argument("--backend", choices=["dumpcap", "tshark", "tcpdump", "pktmon", "rawsocket"])
    p.add_argument("--read", metavar="FILE", help="don't capture; summarise an existing pcap/pcapng file")

    p = add("monitor")
    p.add_argument("hosts", nargs="*", help="extra hosts to monitor")
    p.add_argument("-n", "--interval", type=float, help="seconds between rounds (default 5)")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--csv", metavar="FILE", help="append every round to a CSV file")

    p = add("baseline")
    p.add_argument("action", choices=["save", "diff", "list"])
    p.add_argument("name", nargs="?", default="default")
    p.add_argument("--full", action="store_true", help="use a full run instead of a quick run")

    p = add("report")
    p.add_argument("input", help="report .json file")
    p.add_argument("-o", "--output", required=True, help="output .html / .md / .json")

    p = add("fix")
    p.add_argument("action", nargs="?", help="flush-dns, renew-dhcp, restart-adapter, reset-winsock, reset-tcpip")
    p.add_argument("--yes", action="store_true", help="don't ask for confirmation")

    p = add("config")
    p.add_argument("action", nargs="?", default="show", choices=["show", "set", "unset", "edit", "init", "path", "validate"])
    p.add_argument("key", nargs="?", help="setting name, e.g. NETHELPER_TIMEOUT")
    p.add_argument("value", nargs="?", help="new value (for 'set')")

    p = add("logs")
    p.add_argument("action", nargs="?", default="list", choices=["list", "show", "path", "clear"])
    p.add_argument("number", nargs="?", type=int, default=1, help="show: which run (1 = latest)")

    p = add("upload")
    p.add_argument("files", nargs="+", help="file(s) to copy (reports, captures, logs...)")
    p.add_argument("--to", action="append", default=[], metavar="DEST",
                   help="destination (repeatable; default: NETHELPER_OUTPUT_DESTINATIONS)")
    p.add_argument("--subdir", help="sub-folder at the destination (default: NETHELPER_OUTPUT_SUBDIR)")

    p = add("dest")
    p.add_argument("action", nargs="?", default="list", choices=["list", "test", "add", "remove"])
    p.add_argument("destination", nargs="?", help="destination string (test/add/remove); test without it = all configured")

    add("caps")
    add("list")
    p = add("oui")
    p.add_argument("action", choices=["update", "status"])
    p = add("help")
    p.add_argument("topic", nargs="?", help="command or topic name")
    return parser


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _console(args: argparse.Namespace) -> Console:
    """A Console honouring --no-color, --json and the NETHELPER_COLOR setting."""
    mode = _settings().get("NETHELPER_COLOR")
    if getattr(args, "no_color", False) or getattr(args, "json", False) or mode == "never":
        return Console(color=False)
    return Console(color=True if mode == "always" else None)


def _interface_names(args: argparse.Namespace) -> list[str]:
    """
    Interface selection from -i (repeatable, comma-separated) or the
    NETHELPER_INTERFACES setting. Each name is syntax-checked here; existence
    is checked against the system later (check_interfaces).
    """
    raw = list(getattr(args, "interface", []) or [])
    if not raw and _settings().get("NETHELPER_INTERFACES"):
        raw = [_settings().get("NETHELPER_INTERFACES")]
    names: list[str] = []
    for item in raw:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                names.append("all" if part.lower() == "all" else validate.interface(part))
    return list(dict.fromkeys(names))


def check_interfaces(names: list[str], snap) -> list:
    """
    Resolve interface names against the real adapter list. Raises UsageError
    listing the valid names if any don't exist (instead of silently testing nothing).
    """
    found, missing = [], []
    for n in names:
        if n == "all":
            continue
        iface = snap.interface(n)
        (found if iface else missing).append(iface or n)
    if missing:
        known = ", ".join(f'"{i.name}"' for i in snap.interfaces if i.kind != "loopback") or "none found"
        raise UsageError(f"no interface named {', '.join(map(repr, missing))}. Available: {known}")
    return found


def _context(args: argparse.Namespace, light_facts: bool = False) -> Context:
    """Build the run Context from command-line args + settings (validating user input)."""
    st = _settings()
    profile = load_profile(getattr(args, "profile", None), st)
    for raw in getattr(args, "target", []) or []:
        if "://" in raw:
            validate.url(raw)
        elif raw.count(":") == 1:
            h, p = raw.split(":")
            validate.hostname(h)
            validate.port(p)
        else:
            validate.hostname(raw)
    timeout = args.timeout if getattr(args, "timeout", None) is not None else st.get("NETHELPER_TIMEOUT")
    opts = Options(timeout=max(0.5, min(float(timeout), 30.0)), interfaces=_interface_names(args),
                   allow_intrusive=getattr(args, "allow_intrusive", False),
                   external=not getattr(args, "offline", False) and st.get("NETHELPER_EXTERNAL_LOOKUPS"),
                   targets=list(getattr(args, "target", []) or []), switchport_wait=getattr(args, "wait", None),
                   ping_count=st.get("NETHELPER_PING_COUNT"), settings=st)
    ctx = Context(detect(), profile, opts)
    if light_facts:
        from nethelper.system.facts import collect_snapshot

        ctx._memo["facts"] = ("ok", collect_snapshot(ctx.caps, light=True))
    if opts.interfaces:
        check_interfaces(opts.interfaces, ctx.facts)
    return ctx


def _hide_limited(args) -> bool:
    return bool(args.hide_limited) if getattr(args, "hide_limited", None) is not None else _settings().get("NETHELPER_HIDE_LIMITED")


def _progress():
    """Return a progress callback that shows a live counter on stderr (TTY only)."""
    if not sys.stderr.isatty():
        return None

    def show(done: int, total: int, result) -> None:
        msg = f"\r  running checks... {done}/{total} ({result.title[:30]})"
        sys.stderr.write(msg.ljust(70))
        if done == total:
            sys.stderr.write("\r" + " " * 72 + "\r")
        sys.stderr.flush()

    return show


def _redactor(args: argparse.Namespace, ctx: Context | None):
    """Create a Redactor if --redact/--redact-all was given, else None."""
    if not (getattr(args, "redact", False) or getattr(args, "redact_all", False)):
        return None
    from nethelper.report.redact import Redactor

    ssids = []
    if ctx is not None and "facts" in ctx._memo:
        ssids = [w.ssid for w in ctx.facts.wifi if w.ssid]
    return Redactor("all" if args.redact_all else "standard", ssids)


def resolve_target(word: str, ctx: Context | None = None, iface=None) -> str:
    """
    Turn a command-line target into a host: 'gateway' becomes the default
    gateway (or the gateway of the chosen interface); anything else is validated.
    """
    if word.strip().lower() != "gateway":
        return validate.hostname(word)
    if ctx is None:
        raise UsageError("'gateway' needs system information")
    from nethelper.checks._util import interface_gateway

    gw = interface_gateway(ctx, iface) if iface else ctx.facts.default_gateway()
    if not gw:
        raise UsageError("no default gateway found" + (f" on {iface.name}" if iface else ""))
    return gw


def _source_for(ctx: Context) -> tuple[str | None, object | None]:
    """(source IP, interface) when exactly one interface was chosen with -i, else (None, None)."""
    from nethelper.checks._util import first_ipv4

    name = ctx.options.interface
    if not name:
        if ctx.options.interfaces:
            raise UsageError("this command takes one interface (-i NAME), not several or 'all'")
        return None, None
    iface = ctx.facts.interface(name)
    src = first_ipv4(iface)
    if not src:
        raise UsageError(f"interface {iface.name} has no usable IPv4 address")
    return src, iface


def run_suite(args: argparse.Namespace, title: str, mode: str | None = None, ids: list[str] | None = None,
              sections: list[str] | None = None, ctx: Context | None = None) -> int:
    """
    Run a set of checks, print them with the verdict, and write any requested
    reports/bundles/baselines. Shared by quick/full/info/lan/switchport/etc.
    """
    from nethelper.report import baseline as bl
    from nethelper.report import console as rcon
    from nethelper.report.export import build_document, exit_code, to_json, write_bundle, write_report
    from nethelper.report.verdict import diagnose

    con = _console(args)
    ctx = ctx or _context(args)
    compare = getattr(args, "compare", None)
    if compare:
        ctx.options.baseline = bl.by_id(bl.load(compare))
    specs = select(mode=mode, ids=ids, sections=sections)
    log.info("running %d checks (%s): %s", len(specs), title, ", ".join(s.id for s in specs))
    if not args.json:
        rcon.header(con, ctx.caps, ctx.profile.source, title)
        for w in ctx.profile.warnings:
            con.print(con.c(f"profile warning: {w}", "yellow"))
        for p in _settings().problems:
            con.print(con.c(f"settings warning: {p}", "yellow"))
    results = run_checks(specs, ctx, progress=None if args.json else _progress())
    for r in results:
        log.info("result %s %s: %s (%.0f ms)", r.check_id, r.status.value, r.summary, r.duration_ms)
        if r.details:
            log.debug("details %s: %s", r.check_id, json.dumps(r.details, default=str)[:4000])
    findings = diagnose(results)
    for f in findings:
        log.info("verdict [%s] %s: %s", f.severity, f.title, f.explanation)
    meta = {"host": ctx.facts.hostname if "facts" in ctx._memo else "", "os": ctx.caps.os_detail,
            "elevated": ctx.caps.elevated, "mode": title, "profile": ctx.profile.source}
    doc = build_document(results, findings, meta)
    if compare:
        doc["baseline_diff"] = bl.diff(bl.load(compare), doc)
    red = _redactor(args, ctx)
    out_doc = red.walk(doc) if red else doc
    hide = _hide_limited(args)
    if args.json:
        print(to_json(out_doc))
    else:
        rcon.results(con, results, hide_limited=hide, verbose=args.verbose)
        if compare:
            _print_diff(con, doc["baseline_diff"])
        rcon.verdict(con, findings)
        rcon.footer(con, results, ctx.caps, hide)
    if args.report:
        path = write_report(args.report, out_doc)
        destinations.register("reports", path)
        log.info("report saved: %s", path)
        if not args.json:
            con.print(con.c(f"Report saved: {path.resolve()}", "green"))
    for r in results:  # captures made by checks (e.g. switchport) are outputs too
        if r.details.get("capture_file") and Path(r.details["capture_file"]).is_file():
            destinations.register("captures", r.details["capture_file"])
    if _settings().get("NETHELPER_SAVE_RESULTS") or (_upload_targets(args) and "results" in _include()):
        path = write_report(_results_dir() / f"results-{time.strftime('%Y%m%d-%H%M%S')}-{args.command}.json", out_doc)
        destinations.register("results", path)
        log.info("results saved: %s", path)
    if args.bundle:
        raw: dict[str, str] = {}
        if "facts" in ctx._memo:
            raw.update(ctx.facts.raw)
        for r in results:
            for label, text in r.raw.items():
                raw[f"{r.check_id}-{label}"] = text
        if current_log():
            raw["nethelper-run-log"] = Path(current_log()).read_text(encoding="utf-8", errors="replace")[:2_000_000]
        if red:
            raw = {k: red.text(v) for k, v in raw.items()}
        extra = [Path(r.details["capture_file"]) for r in results
                 if r.details.get("capture_file") and not red]  # raw packets can't be redacted
        path = write_bundle(args.bundle, out_doc, raw, extra)
        destinations.register("reports", path)
        log.info("bundle saved: %s", path)
        if not args.json:
            con.print(con.c(f"Bundle saved: {path.resolve()}", "green"))
    save_as = getattr(args, "save_baseline", None)
    if save_as:
        path = bl.save(save_as, doc)
        destinations.register("results", path)
        if not args.json:
            con.print(con.c(f"Baseline '{save_as}' saved: {path}", "green"))
    return exit_code(results)


def _print_diff(con: Console, d: dict) -> None:
    """Print a baseline comparison."""
    con.heading(f"Changes since baseline ({d.get('baseline_generated')})")
    if not (d["status_changes"] or d["fact_changes"] or d["latency"]):
        con.print("  no significant changes")
    for c in d["status_changes"]:
        con.print(f"  {c['title']}: {c['before']} -> {con.c(c['after'], 'bold')}  ({c['now']})")
    for f in d["fact_changes"]:
        con.print(f"  {f['fact']}: {f['before']} -> {con.c(str(f['after']), 'bold')}")
    for lat in d["latency"]:
        con.print(f"  {lat['metric']}: {lat['before_ms']} ms -> {con.c(str(lat['after_ms']) + ' ms', 'yellow')}")


def _results_dir() -> Path:
    """Folder for saved results JSON (NETHELPER_RESULTS_DIR or <data dir>/results)."""
    from nethelper.core.paths import sub_dir

    configured = _settings().get("NETHELPER_RESULTS_DIR")
    if configured:
        p = Path(configured).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p
    return sub_dir("results")


def _include() -> set[str]:
    """Output categories to copy to destinations (NETHELPER_OUTPUT_INCLUDE)."""
    return {c.strip() for c in _settings().get("NETHELPER_OUTPUT_INCLUDE").split(",") if c.strip()}


def _upload_targets(args) -> list[str]:
    """Destinations for this run: --upload values plus configured ones (unless --no-upload)."""
    targets = list(getattr(args, "upload", []) or [])
    if not getattr(args, "no_upload", False):
        targets += destinations.configured(_settings())
    return list(dict.fromkeys(targets))


def upload_files(files: list[Path], targets: list[str], subdir: str | None = None, quiet: bool = False,
                 auto: bool = False) -> int:
    """
    Copy files to each destination, printing one line per destination (to
    stderr, so --json output stays clean). Returns the number of failures.

    auto=True marks the automatic end-of-run copy: email destinations then
    skip a batch that is only run logs, otherwise every command (even
    'nethelper ping') would send an email. An explicit 'nethelper upload' of a
    log file to a mailto: destination still sends it.
    """
    st = _settings()
    sub = destinations.expand_subdir(subdir if subdir is not None else st.get("NETHELPER_OUTPUT_SUBDIR"))
    failures = 0
    for raw in targets:
        try:
            dest = destinations.parse(raw, allow_insecure=st.get("NETHELPER_DEST_ALLOW_INSECURE"))
        except destinations.DestinationError as exc:
            print(f"upload: {raw}: {exc}", file=sys.stderr)
            failures += 1
            continue
        if auto and dest.kind == "email" and all(Path(f).suffix.lower() == ".log" for f in files):
            continue
        results = destinations.send(dest, files, sub, st)
        if not results:
            continue
        ok = [r for r in results if r.ok]
        bad = [r for r in results if not r.ok]
        failures += len(bad)
        if not quiet:
            # File destinations: show the folder the files landed in. Email/syslog have no folder: show the summary.
            if ok and dest.kind in ("email", "syslog"):
                where = ok[0].remote
            else:
                where = os.path.dirname(ok[0].remote) if ok else raw
            msg = f"upload: {len(ok)}/{len(results)} file(s) -> {dest.label} {where}"
            if bad:
                msg += f"  FAILED: {bad[0].error}"
            print(msg, file=sys.stderr)
    return failures


def _upload_run_outputs(args, include_logs: bool) -> None:
    """Copy this run's registered outputs (and optionally the run log) to the destinations."""
    targets = _upload_targets(args)
    if not targets:
        return
    include = _include()
    files = destinations.produced(include - {"logs"})
    if include_logs and "logs" in include and current_log():
        files.append(Path(current_log()))
    if files:
        upload_files(files, targets, quiet=False, auto=True)


def _badge_for(ok: bool | None, partial: bool = False) -> Status:
    return Status.PASS if ok else (Status.WARN if partial else Status.FAIL)


# ---------------------------------------------------------------------------
# Single-shot tools
# ---------------------------------------------------------------------------

def cmd_ping(args, con: Console) -> int:
    from nethelper.checks._util import ping_summary
    from nethelper.net import icmp

    needs_facts = args.host.lower() == "gateway" or bool(_interface_names(args))
    ctx = _context(args, light_facts=True) if needs_facts else None
    src, iface = _source_for(ctx) if ctx else (None, None)
    host = resolve_target(args.host, ctx, iface)
    count = max(1, min(args.count or _settings().get("NETHELPER_PING_COUNT"), 10000))
    size = max(0, min(args.size, 65000))
    timeout = args.timeout or _settings().get("NETHELPER_TIMEOUT")
    try:
        ip, _ = icmp.resolve(host)
    except OSError as exc:
        con.print(f"{con.badge(Status.FAIL)} cannot resolve {host}: {exc}")
        return 2
    via = f" from {src} ({iface.name})" if src else ""
    con.print(f"Pinging {host} [{ip}] with {size} bytes{via} ({icmp.best_method(':' in ip)}):")
    stats = icmp.PingStats(target=host, address=ip)
    try:
        for seq in range(1, count + 1):
            r = icmp.echo(ip, seq=seq, timeout=timeout, size=size, source=src)
            stats.sent += 1
            if r.status == icmp.OK:
                stats.received += 1
                stats.rtts.append(r.rtt_ms)
                con.print(f"  reply from {r.from_ip}: seq={seq} time={r.rtt_ms:g} ms")
            else:
                con.print(con.c(f"  seq={seq} {r.status}" + (f" from {r.from_ip}" if r.from_ip else "")
                                + (f" ({r.detail})" if r.detail and r.status == icmp.ERROR else ""), "yellow"))
            if seq < count:
                time.sleep(0.5)
    except KeyboardInterrupt:
        con.print("  (stopped)")
    status = Status.PASS if stats.received == stats.sent else Status.WARN if stats.received else Status.FAIL
    con.print(f"{con.badge(status)} {ping_summary(stats)}")
    log.info("ping %s: %s", host, ping_summary(stats))
    return 0 if stats.received == stats.sent else (1 if stats.received else 2)


def cmd_trace(args, con: Console) -> int:
    from nethelper.net import traceroute

    ctx = _context(args, light_facts=True) if args.host.lower() == "gateway" else None
    host = resolve_target(args.host, ctx)
    res = traceroute.trace(host, max_hops=max(1, min(args.max_hops, 64)),
                           timeout=min(args.timeout or _settings().get("NETHELPER_TIMEOUT"), 3.0))
    if res.error and not res.hops:
        con.print(f"{con.badge(Status.FAIL)} {res.error}")
        return 2
    con.print(f"Route to {host} [{res.address}] via {res.method}:")
    con.table(["hop", "address", "name", "avg ms", "samples"],
              [[h.ttl, h.address or "*", h.hostname or "", h.avg_ms if h.avg_ms is not None else "*",
                ", ".join(f"{x:g}" for x in h.rtts)] for h in res.hops])
    con.print(f"{con.badge(Status.PASS if res.reached else Status.WARN)} "
              f"{'reached destination' if res.reached else 'destination not reached'} in {len(res.hops)} hops")
    return 0 if res.reached else 1


def cmd_dns(args, con: Console) -> int:
    from nethelper.net import dnswire
    from nethelper.system.facts import collect_snapshot

    rtype = args.type.upper()
    if rtype not in dnswire.TYPES or rtype == "OPT":
        raise UsageError(f"unsupported record type {rtype}; use one of A AAAA MX TXT NS SOA CNAME PTR SRV CAA")
    name = args.name.strip()
    if validate.is_ip(name):
        name, rtype = dnswire.reverse_name(name), "PTR"
    else:
        name = validate.hostname(name)
    servers = [validate.hostname(s) for s in (args.server or [])]
    if not servers:
        profile = load_profile(args.profile, _settings())
        servers = collect_snapshot(detect(), light=True).dns_servers[:3] + list(profile.public_resolvers.values())
    timeout = args.timeout or _settings().get("NETHELPER_TIMEOUT")
    rows = []
    if rtype in ("A", "AAAA"):
        try:
            ips, took = dnswire.system_resolve(name)
            rows.append(["system resolver", "OK", f"{took:.0f}", ", ".join(ips[:4])])
        except OSError as exc:
            rows.append(["system resolver", "FAIL", "", str(exc)])
    worst = 0
    for s in dict.fromkeys(servers):
        try:
            r = dnswire.query(name, rtype, server=s, timeout=timeout)
            vals = r.values(rtype) or r.values()
            rows.append([s, r.rcode + (" AD" if r.ad else ""), f"{r.rtt_ms:.0f}", "; ".join(vals[:4]) or "(no records)"])
            worst = max(worst, 0 if r.rcode == "NOERROR" else 1)
        except (OSError, dnswire.DnsError) as exc:
            rows.append([s, "TIMEOUT" if "timed out" in str(exc) else "ERROR", "", str(exc) or type(exc).__name__])
            worst = 2
    con.print(f"{rtype} records for {name}:")
    con.table(["server", "result", "ms", "answer"], rows)
    return worst


def cmd_port(args, con: Console) -> int:
    from nethelper.net import tcp

    needs_facts = args.host.lower() == "gateway" or bool(_interface_names(args))
    ctx = _context(args, light_facts=True) if needs_facts else None
    src, iface = _source_for(ctx) if ctx else (None, None)
    host = resolve_target(args.host, ctx, iface)
    ports = validate.ports(args.ports)
    timeout = args.timeout or _settings().get("NETHELPER_TIMEOUT")
    results = tcp.connect_many([(host, p) for p in ports], timeout=timeout, source=src)
    con.table(["port", "state", "ms", "note"], [[r.port, r.state, r.connect_ms or "", r.error or ""] for r in results])
    opened = sum(r.state == "open" for r in results)
    con.print(f"{con.badge(_badge_for(opened == len(results), bool(opened)))} {opened}/{len(results)} open on {host}")
    return 0 if opened == len(results) else (1 if opened else 2)


def cmd_http(args, con: Console) -> int:
    from nethelper.checks._util import ms
    from nethelper.net import httpcheck

    res = httpcheck.fetch(validate.url(args.url), timeout=(args.timeout or _settings().get("NETHELPER_TIMEOUT")) + 7)
    for h in res.hops:
        con.print(f"  {h.url}")
        con.print(f"    status {h.status} {h.reason}  ip {h.ip}  server {h.server or '-'}"
                  + (f"  -> {h.location}" if h.location else ""))
        con.print(f"    dns {ms(h.dns_ms)} | connect {ms(h.connect_ms)} | tls {ms(h.tls_ms)} | "
                  f"first byte {ms(h.ttfb_ms)} | total {ms(h.total_ms)}" + (f"  ERROR: {h.error}" if h.error else ""))
    con.print(f"{con.badge(Status.PASS if res.ok else Status.FAIL)} " + (f"HTTP {res.status}" if res.status else res.error or "failed"))
    return 0 if res.ok else 2


def cmd_tls(args, con: Console) -> int:
    from nethelper.net import tlscheck

    text = args.host.split("://", 1)[-1].split("/")[0]  # accept "https://host:port/path" too
    host, port = (text.rsplit(":", 1) if text.count(":") == 1 else (text, ""))  # IPv6 literals keep their colons
    r = tlscheck.inspect(validate.hostname(host), validate.port(port or 443),
                         timeout=(args.timeout or _settings().get("NETHELPER_TIMEOUT")) + 2)
    if r.error and not r.cert:
        con.print(f"{con.badge(Status.FAIL)} {r.error}")
        return 2
    c = r.cert
    con.kv("trusted", "yes" if r.trusted else f"NO - {r.verify_error}")
    con.kv("name matches", r.name_ok)
    con.kv("subject", ", ".join(f"{k}={v}" for k, v in c.get("subject", {}).items()))
    con.kv("issuer", ", ".join(f"{k}={v}" for k, v in c.get("issuer", {}).items()))
    con.kv("valid", f"{c.get('not_before')} -> {c.get('not_after')} ({c.get('days_left')} days left)")
    con.kv("names (SAN)", ", ".join(c.get("san", [])[:8]) + (" ..." if len(c.get("san", [])) > 8 else ""))
    con.kv("protocol", f"{r.tls_version} {r.cipher}")
    con.kv("sha256", c.get("sha256"))
    if r.interception:
        con.kv("interception", con.c(f"YES - issuer looks like {r.interception}", "yellow"))
    for i, link in enumerate(r.chain):
        con.kv(f"chain[{i}]", f"{link['subject'].get('CN', link['subject'])} (issuer {link['issuer'].get('CN', '')})")
    ok = r.trusted and r.name_ok and (c.get("days_left") or 0) >= 0
    return 0 if ok else 2


def cmd_mtu(args, con: Console) -> int:
    from nethelper.net import mtu

    if args.host and args.host.lower() == "gateway":
        host = resolve_target("gateway", _context(args, light_facts=True))
    else:
        host = validate.hostname(args.host) if args.host else load_profile(args.profile, _settings()).trace_target
    r = mtu.discover(host, timeout=min(args.timeout or 2.0, 2.0))
    if r.error:
        con.print(f"{con.badge(Status.SKIP)} {r.error}")
        return 1
    con.print(f"{con.badge(Status.PASS if r.mtu == 1500 else Status.WARN)} path MTU to {host} [{r.address}]: "
              f"{r.mtu} bytes (largest DF ping payload {r.max_payload})" + ("; black hole detected" if r.black_hole else ""))
    return 0 if r.mtu == 1500 else 1


def cmd_check(args, con: Console) -> int:
    """Focused diagnosis of a single target, step by step."""
    from urllib.parse import urlsplit

    from nethelper.checks._util import ms, ping_summary
    from nethelper.core.result import worst as worst_of
    from nethelper.net import dnswire, httpcheck, icmp, tcp, tlscheck, traceroute

    raw = args.target.strip()
    timeout = args.timeout or _settings().get("NETHELPER_TIMEOUT")
    url = None
    if raw.lower() == "gateway":
        host = resolve_target("gateway", _context(args, light_facts=True))
        default_ports = [80, 443]
    elif "://" in raw:
        url = validate.url(raw)
        parts = urlsplit(url)
        host = parts.hostname
        default_ports = [parts.port or (443 if parts.scheme == "https" else 80)]
    elif raw.count(":") == 1 and not validate.is_ip(raw):
        host, p = raw.split(":")
        host = validate.hostname(host)
        default_ports = [validate.port(p)]
    else:
        host = validate.hostname(raw)
        default_ports = [80, 443]
    ports = validate.ports(args.ports) if args.ports else default_ports
    state = {"worst": Status.PASS}

    def line(status: Status, text: str) -> None:
        state["worst"] = worst_of([state["worst"], status])
        con.print(f"  {con.badge(status)} {text}")
        log.info("check %s: %s %s", raw, status.value, text)

    con.print(con.c(f"Checking {raw}", "bold"))
    ip = host if validate.is_ip(host) else None
    if not ip:
        try:
            ips, took = dnswire.system_resolve(host)
            ip = ips[0]
            line(Status.PASS, f"DNS (system): {host} -> {', '.join(ips[:4])} in {ms(took)}")
        except OSError as exc:
            line(Status.FAIL, f"DNS (system): {host} does not resolve ({exc})")
        try:
            r = dnswire.query(host, "A", server="1.1.1.1", timeout=timeout)
            pub = r.values("A")
            if pub and not ip:
                line(Status.WARN, f"DNS (public 1.1.1.1) resolves it to {', '.join(pub[:3])} - local DNS is the problem "
                     "(or it's a public name your DNS filters)")
                ip = pub[0]
            elif not pub:
                line(Status.INFO, f"DNS (public 1.1.1.1): {r.rcode} - internal-only name" if ip else
                     f"DNS (public 1.1.1.1): {r.rcode} - name doesn't exist publicly either")
        except (OSError, dnswire.DnsError) as exc:
            log.debug("public DNS lookup failed: %s", exc)
    if not ip:
        return 2
    stats = icmp.ping(ip, count=4, timeout=timeout, interval=0.2)
    line(Status.PASS if stats.received else Status.INFO, f"ping {ip}: {ping_summary(stats)}"
         + ("" if stats.received else " (ICMP may simply be blocked)"))
    open_ports = []
    for res in tcp.connect_many([(ip, p) for p in ports], timeout=timeout):
        line(Status.PASS if res.state == "open" else Status.FAIL,
             f"TCP {res.port}: {res.state}" + (f" in {ms(res.connect_ms)}" if res.connect_ms else "")
             + (f" - {res.error}" if res.error else ""))
        if res.state == "open":
            open_ports.append(res.port)
    web = url or (f"https://{host}/" if 443 in open_ports else f"http://{host}/" if 80 in open_ports else None)
    if web:
        h = httpcheck.fetch(web, timeout=timeout + 7)
        last = h.hops[-1] if h.hops else None
        line(Status.PASS if h.ok else Status.FAIL, f"HTTP {web}: " + (
            f"{h.status} (dns {ms(last.dns_ms)}, connect {ms(last.connect_ms)}, tls {ms(last.tls_ms)}, "
            f"server {ms(last.ttfb_ms)}, total {ms(last.total_ms)})" if h.status and last else h.error or "failed"))
    tls_port = 443 if 443 in open_ports else (default_ports[0] if url and url.startswith("https") and open_ports else None)
    if tls_port:
        t = tlscheck.inspect(host, tls_port, timeout=timeout + 2)
        if t.cert:
            st = Status.PASS if t.trusted and (t.cert.get("days_left") or 0) > 14 else Status.WARN if t.trusted else Status.FAIL
            line(st, f"TLS: {'trusted' if t.trusted else 'NOT trusted (' + str(t.verify_error) + ')'}, "
                     f"{t.tls_version}, expires in {t.cert.get('days_left')} days, issuer "
                     f"{t.cert.get('issuer', {}).get('O') or t.cert.get('issuer', {}).get('CN')}"
                     + (f", INTERCEPTED by {t.interception}" if t.interception else ""))
    if args.trace or state["worst"] is Status.FAIL or (not stats.received and not open_ports):
        tr = traceroute.trace(ip, timeout=min(timeout, 2.0))
        path = " > ".join(h.address or "*" for h in tr.hops)
        line(Status.PASS if tr.reached else Status.WARN, f"route ({len(tr.hops)} hops, {tr.method}): {path}")
    return {Status.FAIL: 2, Status.WARN: 1}.get(state["worst"], 0)


def cmd_interfaces(args, con: Console) -> int:
    """List adapters (and optionally test each one's own path)."""
    from nethelper.checks._util import first_ipv4, interface_gateway
    from nethelper.net import oui

    if args.test:
        args.interface = args.interface or ["all"]
        return run_suite(args, "per-interface test", ids=["conn.per_interface", "local.interfaces"])
    ctx = _context(args, light_facts=False)
    snap = ctx.facts
    chosen = check_interfaces([n for n in ctx.options.interfaces if n != "all"], snap) if ctx.options.interfaces else None
    ifaces = chosen or [i for i in snap.interfaces if args.all or (i.up and i.kind not in ("loopback",))]
    if not args.all and not chosen:
        ifaces = [i for i in ifaces if i.kind != "virtual" or i.usable]
    wifi_by = {w.interface: w for w in snap.wifi}
    primary = snap.primary_interface()
    if args.json:
        print(json.dumps([{**{k: v for k, v in vars(i).items() if k != "addresses"},
                           "addresses": [vars(a) for a in i.addresses], "gateway": interface_gateway(ctx, i),
                           "dns": snap.dns_by_interface.get(i.name, [])} for i in ifaces], indent=2, default=str))
        return 0
    rows = []
    for i in ifaces:
        w = wifi_by.get(i.name)
        rows.append([("* " if primary and i.name == primary.name else "  ") + i.name, i.kind, "up" if i.up else "down",
                     first_ipv4(i) or ", ".join(a.ip for a in i.ipv4) or "-",
                     interface_gateway(ctx, i) or "-", ", ".join(snap.dns_by_interface.get(i.name, [])[:2]) or "-",
                     f"{i.speed_mbps:g}" if i.speed_mbps else "-", i.duplex or "-", i.mtu or "-", i.vlan_id or "-",
                     (w.ssid if w else "") or "-"])
    con.table(["interface", "kind", "state", "IPv4", "gateway", "DNS", "Mb/s", "duplex", "MTU", "VLAN", "Wi-Fi"], rows,
              shrink_first=[5, 10, 7, 9, 8, 4])  # DNS, Wi-Fi, duplex, VLAN, MTU, gateway shrink before names/IPs
    con.print(con.c("  * = primary (carries the default route)", "grey"))
    if args.verbose:
        for i in ifaces:
            con.heading(i.name)
            con.kv("description", i.description or "-")
            con.kv("MAC / vendor", f"{i.mac or '-'} {oui.vendor(i.mac) or ''}")
            for a in i.addresses:
                con.kv(f"IPv{a.family}", f"{a.ip}/{a.prefix} ({a.origin or '?'}, {a.state or '?'})")
    con.print(f"{len(ifaces)} interface(s). Test each one's path with: nethelper interfaces --test")
    return 0


def cmd_wifi(args, con: Console) -> int:
    """Wi-Fi status / scan / channels / monitor / profiles."""
    from nethelper.net import wifi

    if args.action == "profiles":
        names, method = wifi.profiles()
        if args.json:
            print(json.dumps({"profiles": names, "method": method}, indent=2))
            return 0
        con.print(f"Saved Wi-Fi networks ({method}):" if names else f"No saved Wi-Fi networks found ({method}).")
        for n in names:
            con.print(f"  - {n}")
        return 0
    if args.action == "monitor":
        from nethelper.monitor import wifi_monitor

        try:
            return wifi_monitor(con, max(0.5, args.interval), args.duration, Path(args.csv) if args.csv else None)
        finally:
            if args.csv and Path(args.csv).is_file():
                destinations.register("results", args.csv)
    if args.action == "status":
        infos = wifi.current()
        caps = wifi.adapter_capabilities()
        if args.json:
            print(json.dumps({"connections": [vars(w) for w in infos], "adapter": caps}, indent=2, default=str))
            return 0
        if not infos:
            con.print(f"{con.badge(Status.INFO)} not connected to Wi-Fi (or details unavailable - Location permission?)")
        for w in infos:
            con.heading(f"Wi-Fi: {w.interface}")
            if w.note and not w.ssid:
                con.print(f"  {w.note}")
                continue
            quality = ("excellent" if (w.rssi_dbm or -100) >= -60 else "good" if (w.rssi_dbm or -100) >= -67 else
                       "fair" if (w.rssi_dbm or -100) >= -70 else "poor")
            con.kv("network (SSID)", w.ssid)
            con.kv("access point (BSSID)", w.bssid)
            con.kv("signal", f"{w.rssi_dbm} dBm ({w.signal_pct}%) - {quality}" if w.rssi_dbm is not None else "-")
            con.kv("band / channel", f"{w.band or '-'} / {w.channel or '-'}")
            con.kv("radio", w.radio or "-")
            con.kv("link rate", f"rx {w.rx_mbps or '-'} / tx {w.tx_mbps or '-'} Mb/s")
            con.kv("security", w.security or "-")
        if caps:
            con.heading("Adapter")
            con.kv("driver", f"{caps.get('driver', '-')} {caps.get('version', '')}")
            con.kv("radio types", " ".join(caps.get("radio_types", [])) or "-")
            con.kv("WPA3 / PMF", f"{'yes' if caps.get('wpa3_supported') else 'no'} / {'yes' if caps.get('pmf_supported') else 'no'}")
        return 0
    # scan / channels
    res = wifi.scan()
    cur = next(iter(wifi.current()), None)
    if args.json:
        out = {"method": res.method, "note": res.note, "networks": wifi.to_dicts(res.networks)}
        if args.action == "channels":
            out["analysis"] = wifi.analyze_channels(res.networks, cur.channel if cur else None, own_bssid=cur.bssid if cur else None)
            out["evil_twin_suspects"] = wifi.evil_twin_suspects(res.networks)
        print(json.dumps(out, indent=2, default=str))
        return 0
    if res.note:
        con.print(con.c(f"note: {res.note}", "yellow"))
    if not res.networks:
        con.print(f"{con.badge(Status.WARN)} no networks found")
        return 1
    if args.action == "scan":
        con.table(["SSID", "BSSID", "band", "ch", "signal", "dBm", "security", "radio", "load"],
                  [[("* " if cur and n.bssid == cur.bssid else "  ") + n.ssid, n.bssid or "", n.band or "", n.channel or "",
                    f"{n.signal_pct}%" if n.signal_pct is not None else "", n.rssi_dbm if n.rssi_dbm is not None else "",
                    n.security or "", n.radio or "", f"{n.utilization_pct}%" if n.utilization_pct is not None else ""]
                   for n in res.networks])
        con.print(f"{len(res.networks)} access point(s) via {res.method}" + ("  (* = connected)" if cur else ""))
        return 0
    a = wifi.analyze_channels(res.networks, cur.channel if cur else None, own_bssid=cur.bssid if cur else None)
    con.heading("Access points per channel")
    con.table(["channel", "band", "APs", "congestion score"],
              [[ch, "2.4 GHz" if ch <= 14 else "5 GHz", n,
                a["score_24ghz"].get(ch, a["score_5ghz"].get(ch, ""))] for ch, n in a["aps_per_channel"].items()])
    con.heading("Assessment")
    if cur and cur.channel:
        crowded = a["strong_aps_on_or_overlapping_current"]
        st = Status.WARN if crowded >= 3 else Status.PASS
        con.print(f"  {con.badge(st)} you're on channel {cur.channel}: {crowded} strong neighbouring AP(s) on/overlapping it"
                  f" ({a['own_radio_bssids_excluded']} of your AP's own SSIDs excluded)")
    con.print(f"  {con.badge(Status.INFO)} least congested: 2.4 GHz channel {a['recommended_24ghz']} (use 1/6/11 only), "
              f"5 GHz channel {a['recommended_5ghz']} (non-DFS)")
    twins = wifi.evil_twin_suspects(res.networks)
    for t in twins:
        con.print(f"  {con.badge(Status.WARN)} '{t['ssid']}' is broadcast with different security types "
                  f"({', '.join(t['security_types'])}) - verify these APs are yours (possible evil twin)")
    return 1 if twins else 0


def cmd_speed(args, con: Console) -> int:
    """Internet speed test with bufferbloat grading."""
    from nethelper.checks.app import internet_speed

    ctx = _context(args)
    if not ctx.options.external:
        raise UsageError("the internet speed test contacts a third-party service; it's disabled by --offline / settings")
    con.print(f"Testing download ({ctx.profile.bandwidth.download_bytes // 1_000_000} MB) and upload "
              f"({ctx.profile.bandwidth.upload_bytes // 1_000_000} MB)"
              + ("" if args.no_latency else " while measuring latency under load") + " ...")
    details = internet_speed(ctx, latency=not args.no_latency)
    if args.json:
        print(json.dumps(details, indent=2, default=str))
        return 0
    rc = 0
    for direction in ("download", "upload"):
        d = details[direction]
        if d.get("error"):
            con.print(f"{con.badge(Status.FAIL)} {direction}: {d['error']}")
            rc = 2
            continue
        con.print(f"{con.badge(Status.INFO)} {direction}: {con.c(str(d['mbps']) + ' Mb/s', 'bold')} "
                  f"({d['bytes'] / 1e6:.1f} MB in {d['seconds']} s)")
        for target, lat in (d.get("latency") or {}).items():
            idle, loaded = lat["idle"], lat["loaded"]
            con.print(f"         latency to {target}: idle {idle['avg_ms']} ms -> loaded {loaded['avg_ms']} ms "
                      f"(p95 {loaded['p95_ms']}, max {loaded['max_ms']}), +{lat['increase_ms']} ms")
        if d.get("bufferbloat_grade"):
            g = d["bufferbloat_grade"]
            st = Status.PASS if g in ("A+", "A", "B") else Status.WARN
            con.print(f"         {con.badge(st)} bufferbloat grade {g}")
            if st is Status.WARN:
                rc = max(rc, 1)
    return rc


def cmd_throughput(args, con: Console) -> int:
    """LAN/WAN throughput to a NetHelper server, iperf3 server, or (fallback) ICMP load."""
    from nethelper.net import throughput as tp

    st = _settings()
    needs_facts = args.target.lower() == "gateway" or bool(_interface_names(args))
    ctx = _context(args, light_facts=True) if needs_facts else None
    src, iface = _source_for(ctx) if ctx else (None, None)
    host = resolve_target(args.target, ctx, iface)
    port = validate.port(args.port or st.get("NETHELPER_THROUGHPUT_PORT"))
    seconds = max(1, min(args.seconds or st.get("NETHELPER_THROUGHPUT_SECONDS"), tp.MAX_SECONDS))
    streams = max(1, min(args.parallel or st.get("NETHELPER_THROUGHPUT_STREAMS"), tp.MAX_STREAMS))
    key = args.key if args.key is not None else st.get("NETHELPER_THROUGHPUT_KEY")
    via = f" via {iface.name} ({src})" if iface else ""
    results: dict = {"target": host, "port": port}
    if args.udp:
        con.print(f"UDP test to {host}:{port}{via}: {args.rate:g} Mb/s for {seconds} s, {args.size}-byte packets ...")
        r = tp.udp_test(host, port, args.rate, seconds, args.size, key, src)
        results["udp"] = vars(r)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
            return 0 if not r.error else 2
        if r.error:
            con.print(f"{con.badge(Status.FAIL)} {r.error}")
            return 2
        u = r.udp
        st_ = Status.PASS if u["loss_pct"] < 1 and u["jitter_ms"] < 30 else Status.WARN
        con.print(f"{con.badge(st_)} achieved {r.mbps} Mb/s of {args.rate:g} offered; loss {u['loss_pct']}% "
                  f"({u['lost']}/{u['expected']}), jitter {u['jitter_ms']} ms, out-of-order {u['out_of_order']}, dup {u['duplicates']}")
        con.print(con.c("  VoIP needs roughly <1% loss and <30 ms jitter.", "grey"))
        return 0 if st_ is Status.PASS else 1
    directions = ("upload", "download") if args.direction == "both" else (args.direction,)
    con.print(f"Throughput to {host}{via}: {', '.join(directions)}, {seconds} s each, {streams} stream(s) ...")
    res = tp.auto_test(host, port, seconds, streams, key, src, directions, st.get("NETHELPER_IPERF_PORT"),
                       allow_icmp=not args.no_fallback)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
        return 0 if not res.get("error") else 2
    for note in res["notes"][:-1] if res["method"] == "icmp-load" else res["notes"]:
        con.print(con.c(f"  note: {note}", "grey"))
    if res.get("error"):
        con.print(f"{con.badge(Status.FAIL)} {res['error']}")
        return 2
    if res["method"] == "icmp-load":
        i = res["results"]["icmp"]
        con.print(f"{con.badge(Status.INFO)} ICMP load to {host}: ~{con.c(str(i['mbps_echoed']) + ' Mb/s', 'bold')} echoed "
                  f"(approximate lower bound); latency under load avg {i['avg_ms']} ms, max {i['max_ms']} ms, loss {i['loss_pct']}%")
        con.print(con.c(f"  {res['notes'][-1]}", "yellow"))
        return 0
    rc = 0
    for d, r in res["results"].items():
        if r.get("error"):
            con.print(f"{con.badge(Status.FAIL)} {d}: {r['error']}")
            rc = 2
        else:
            extra = f" ({', '.join(map(str, r.get('per_stream_mbps') or []))} per stream)" if (r.get("streams") or 1) > 1 else ""
            retr = f", {r['retransmits']} retransmits" if r.get("retransmits") is not None else ""
            con.print(f"{con.badge(Status.INFO)} {d}: {con.c(str(r.get('mbps')) + ' Mb/s', 'bold')} via {res['method']}{extra}{retr}")
    return rc


def cmd_serve(args, con: Console) -> int:
    """Run the throughput server in the foreground until Ctrl+C."""
    from nethelper.net import throughput as tp

    st = _settings()
    port = validate.port(args.port or st.get("NETHELPER_THROUGHPUT_PORT"))
    bind = validate.hostname(args.bind) if args.bind else tp.ANY_ADDRESS
    key = args.key if args.key is not None else st.get("NETHELPER_THROUGHPUT_KEY")
    server = tp.Server(bind=bind, port=port, key=key, once=args.once,
                       on_event=lambda m: con.print(f"{time.strftime('%H:%M:%S')}  {m}"))
    try:
        server.listen()
    except OSError as exc:
        raise UsageError(f"cannot listen on {bind}:{port} ({exc.strerror or exc}) - port in use? try --port") from exc
    con.print(con.c(f"NetHelper throughput server listening on {bind}:{port} (TCP; UDP tests use a temporary port)", "bold"))
    con.print(f"  key required: {'yes' if key else 'no - anyone who can reach this port can run tests (add --key)'}")
    con.print(f"  test from another machine:  nethelper throughput <this machine's IP>{' --key ...' if key else ''}")
    con.print(con.c("  Allow TCP/UDP in the host firewall if prompted. Press Ctrl+C to stop.", "grey"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        con.print("stopping")
    finally:
        server.stop()
        server.close()
    con.print(f"{server.completed} test stream(s) completed")
    return 0


def cmd_capture(args, con: Console) -> int:
    """Packet capture with presets, followed by a summary."""
    from nethelper.net import capture, l2proto, pcap

    caps = detect()
    if args.read:
        try:
            packets = pcap.read(args.read)
        except ValueError as exc:
            raise UsageError(f"{args.read}: {exc}") from exc
        file = Path(args.read)
        con.print(f"Read {len(packets)} packets from {file}")
    else:
        names = _interface_names(args)
        if len(names) > 1 or names == ["all"]:
            raise UsageError("capture takes a single interface (-i NAME); omit -i for the default")
        capdir = _settings().get("NETHELPER_CAPTURE_DIR")
        spec = capture.CaptureSpec(interface=names[0] if names else None, duration=max(1.0, min(args.duration, 3600)),
                                   count=max(0, args.count), preset=args.filter, bpf=args.bpf,
                                   outfile=Path(args.output) if args.output else None, backend=args.backend,
                                   outdir=Path(capdir) if capdir else None)
        con.print(f"Capturing '{args.filter}'{' bpf: ' + args.bpf if args.bpf else ''} for up to "
                  f"{spec.duration:g}s on {spec.interface or 'default interface'}... (Ctrl+C to stop early)")
        res = capture.run_capture(spec, caps)
        if not res.ok:
            con.print(f"{con.badge(Status.FAIL)} {res.error}")
            if not caps.elevated:
                con.print(con.c(f"  {elevation_hint('nethelper capture')}", "yellow"))
            return 2
        packets, file = res.packets, res.file
        if file:
            destinations.register("captures", file)
        con.print(f"{con.badge(Status.PASS)} {len(packets)} packets captured with {res.backend} -> {file}")
        for note in res.notes:
            con.print(con.c(f"  note: {note}", "grey"))
    s = pcap.summarize(packets)
    if args.json:
        print(json.dumps({"file": str(file), "summary": s}, indent=2, default=str))
        return 0
    con.heading("Capture summary")
    con.kv("packets / bytes", f"{s['packets']} / {s['bytes']} over {s['duration_s']} s")
    con.kv("protocols", ", ".join(f"{k} {v}" for k, v in list(s["protocols"].items())[:8]) or "-")
    if s["vlans_seen"]:
        con.kv("802.1Q VLANs", ", ".join(f"{k} ({v})" for k, v in s["vlans_seen"].items()))
    if s["top_talkers"]:
        con.kv("top talkers", ", ".join(f"{ip} ({b} B)" for ip, b in s["top_talkers"][:5]))
    if s["top_ports"]:
        con.kv("top ports", ", ".join(f"{p} ({n})" for p, n in s["top_ports"][:6]))
    if s["dns_queries"]:
        con.kv("DNS queries", ", ".join(f"{n} ({c})" for n, c in s["dns_queries"][:8]))
    if s["dhcp"]:
        con.kv("DHCP", ", ".join(f"{d.get('type')} {d.get('server_id') or d.get('src_ip')}" for d in s["dhcp"][:6]))
    if s["arp_conflicts"]:
        con.kv("ARP conflicts", con.c(str(s["arp_conflicts"]), "red"))
    if s["tcp_resets"] or s["icmp_unreachable"]:
        con.kv("TCP resets / ICMP unreachable", f"{s['tcp_resets']} / {s['icmp_unreachable']}")
    from nethelper.checks.layer2 import _describe

    for n in l2proto.find_neighbors(packets):
        con.kv(n["protocol"], _describe(n))
    if args.report:
        Path(args.report).write_text(json.dumps({"file": str(file), "summary": s}, indent=2, default=str), encoding="utf-8")
    return 0


def cmd_lan_net(args, con: Console) -> int:
    """`lan --net CIDR`: sweep an explicit network and print the hosts."""
    from nethelper.net import arp

    net = validate.cidr(args.net, max_hosts=max(1, min(args.max_hosts, 65536)))
    con.print(f"Sweeping {net} ({net.num_addresses} addresses)...")
    hosts = arp.sweep(net, timeout=min(args.timeout or 1.0, 2.0))
    con.table(["ip", "mac", "vendor", "name", "ping", "ports", "found by"],
              [[h.ip, h.mac or "", h.vendor or "", h.hostname or "", h.ping_ms or "",
                ",".join(map(str, h.open_ports or [])), ",".join(h.methods or [])] for h in hosts])
    con.print(f"{con.badge(Status.INFO)} {len(hosts)} live host(s)")
    return 0


def cmd_monitor(args, con: Console) -> int:
    from nethelper import monitor
    from nethelper.checks._util import first_ipv4, interface_gateway

    ctx = _context(args, light_facts=True)
    snap = ctx.facts
    targets: list[tuple[str, str, str | None]] = []  # (label, host, source IP)
    sel = [snap.interface(n) for n in ctx.options.interfaces if n != "all"]
    if ctx.options.all_interfaces:
        sel = [i for i in snap.interfaces if i.usable and i.kind not in ("loopback", "virtual")]
    if sel:
        for iface in sel:
            src = first_ipv4(iface)
            gw = interface_gateway(ctx, iface)
            if gw:
                targets.append((f"{iface.name}:gw", gw, src))
            for h in ctx.profile.public_ping[:1]:
                targets.append((f"{iface.name}:{h}", h, src))
    else:
        gw = snap.default_gateway()
        if gw:
            targets.append(("gateway", gw, None))
        for h in ctx.profile.public_ping:
            targets.append((h, h, None))
    for h in ctx.profile.monitor_targets + [validate.hostname(x) for x in args.hosts]:
        targets.append((h, h, None))
    if not targets:
        raise UsageError("nothing to monitor (no gateway found and no hosts given)")
    interval = args.interval or ctx.profile.monitor_interval
    try:
        return monitor.run(con, targets, ctx.profile.public_hostname, max(1.0, interval), args.duration,
                           Path(args.csv) if args.csv else None, timeout=min(ctx.options.timeout, interval))
    finally:
        if args.csv and Path(args.csv).is_file():
            destinations.register("results", args.csv)


def cmd_baseline(args, con: Console) -> int:
    from nethelper.report import baseline as bl

    if args.action == "list":
        names = bl.list_names()
        if names:
            con.table(["name", "saved"], [[n, t] for n, t in names])
        else:
            con.print("no baselines saved yet - create one with: nethelper baseline save <name>")
        return 0
    if args.action == "save":
        args.save_baseline, args.compare = args.name, None
    else:
        args.compare, args.save_baseline = args.name, None
        try:
            bl.load(args.name)
        except FileNotFoundError as exc:
            raise UsageError(f"no baseline named '{args.name}' - see 'nethelper baseline list'") from exc
    return run_suite(args, f"baseline {args.action} ({'full' if args.full else 'quick'})",
                     mode="full" if args.full else "quick")


def cmd_fix(args, con: Console) -> int:
    """Run a repair action after showing the plan and getting confirmation."""
    from nethelper.net import remediate
    from nethelper.system.facts import collect_snapshot

    if not args.action or args.action not in remediate.ACTIONS:
        if args.action:
            con.print(con.c(f"unknown action '{args.action}'", "red"))
        con.print("Available repair actions:")
        for a in remediate.ACTIONS.values():
            flags = [x for x, on in (("needs admin", a.admin), ("disconnects", a.disruptive),
                                     ("reboot needed", a.reboot), ("needs -i IFACE", a.needs_iface)) if on]
            con.print(f"  {a.name:<16} {a.description}" + (con.c(f"  [{', '.join(flags)}]", "grey") if flags else ""))
        return 0 if not args.action else EXIT_USAGE
    action = remediate.ACTIONS[args.action]
    caps = detect()
    iface = None
    names = _interface_names(args)
    if names:
        if len(names) > 1 or names == ["all"]:
            raise UsageError("repairs act on one interface at a time (-i NAME)")
        iface = check_interfaces(names, collect_snapshot(caps, light=True))[0].name
    if action.needs_iface and not iface:
        raise UsageError(f"{action.name} needs an interface: add -i NAME (see 'nethelper interfaces')")
    plan = action.commands(iface)
    con.print(con.c(f"{action.name}: {action.description}", "bold"))
    con.print("Will run:")
    for argv in plan:
        con.print("   " + " ".join(argv))
    if action.admin and not caps.elevated:
        con.print(con.c(f"This usually needs elevation. {elevation_hint('nethelper fix ' + action.name)}", "yellow"))
    if action.disruptive:
        con.print(con.c("WARNING: this briefly disconnects the network.", "yellow", "bold"))
        if runcmd.in_remote_session():
            con.print(con.c("You appear to be connected remotely (SSH/RDP) - you may lose this session!", "red", "bold"))
    if action.reboot:
        con.print(con.c("A reboot is required afterwards.", "yellow"))
    if not args.yes:
        try:
            answer = input("Type 'yes' to proceed: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "yes":
            con.print("Cancelled - nothing was changed.")
            log.info("fix %s cancelled by user", action.name)
            return 0
    log.warning("fix %s confirmed; running %s", action.name, plan)
    rc = 0
    for argv in plan:
        res = runcmd.run(argv, timeout=120)
        con.print(f"{con.badge(Status.PASS if res.ok else Status.FAIL)} {' '.join(argv)}")
        out = (res.stdout + res.stderr).strip() or (res.error or "")
        if out:
            con.print(con.c("   " + out[:800].replace("\n", "\n   "), "grey"))
        if not res.ok:
            rc = 2
            break
    return rc


def cmd_config(args, con: Console) -> int:
    """Show or change .env settings."""
    st = _settings()
    path = st.path
    if args.action == "path":
        con.print(str(path) + ("" if path.exists() else "   (not created yet - defaults in use)"))
        return 0
    if args.action == "edit":
        from nethelper.menu import settings_menu

        settings_menu(con, path)
        return 0
    if args.action == "init":
        from nethelper.menu import settings_init

        return settings_init(con, path)
    if args.action == "validate":
        if st.problems:
            for p in st.problems:
                con.print(f"{con.badge(Status.WARN)} {p}")
            return 1
        con.print(f"{con.badge(Status.PASS)} {path} is valid" + ("" if path.exists() else " (file not created; defaults)"))
        return 0
    if args.action in ("set", "unset"):
        if not args.key:
            raise UsageError(f"usage: nethelper config {args.action} KEY" + (" VALUE" if args.action == "set" else ""))
        key = args.key.upper()
        if key not in settings_mod.SPEC_BY_KEY:
            raise UsageError(f"unknown setting {key}; run 'nethelper config show' for the list")
        values = settings_mod.current_file_values(path)
        if args.action == "set":
            if args.value is None:
                raise UsageError("usage: nethelper config set KEY VALUE")
            try:
                values[key] = settings_mod.validate_value(key, args.value)
            except ValueError as exc:
                raise UsageError(f"{key}: {exc}") from exc
        else:
            values[key] = settings_mod.SPEC_BY_KEY[key].default
        backup = settings_mod.save(path, values)
        shown = settings_mod.MASK if settings_mod.SPEC_BY_KEY[key].secret else values[key]
        con.print(f"{con.badge(Status.PASS)} {key}={shown} saved to {path}" + (f" (previous: {backup.name})" if backup else ""))
        log.info("config %s %s", args.action, key)
        if os.environ.get(key):
            con.print(con.c(f"  note: the environment variable {key} is set and overrides the file", "yellow"))
        return 0
    # show
    if args.json:
        print(json.dumps({"file": str(path), "settings": {k: {"value": st.display(k), "source": st.source[k]}
                                                         for k in st.values}, "problems": st.problems}, indent=2))
        return 0
    con.print(f"Settings file: {path}" + ("" if path.exists() else "  (not created yet - run 'nethelper config init')"))
    group = None
    for spec in settings_mod.SPECS:
        if spec.group != group:
            group = spec.group
            con.heading(group)
        src = st.source[spec.key]
        con.print(f"  {spec.key:<36} {st.display(spec.key) or con.c('(empty)', 'grey'):<30} "
                  + con.c(f"[{src}] {spec.help}", "grey"))
    for p in st.problems:
        con.print(con.c(f"warning: {p}", "yellow"))
    return 0


def cmd_logs(args, con: Console) -> int:
    """List / show / locate / clear run logs."""
    from nethelper.core import logsetup

    folder = logsetup.log_dir(_settings().get("NETHELPER_LOG_DIR"))
    # Leave out this very run's own (still open) log, so "1" means the latest finished run.
    runs = [r for r in logsetup.list_runs(folder) if r["path"] != current_log()]
    if args.action == "path":
        con.print(str(folder))
        return 0
    if args.action == "clear":
        try:
            answer = input(f"Delete all {len(runs)} run logs in {folder}? Type 'yes': ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "yes":
            con.print("Cancelled.")
            return 0
        current = current_log()
        removed = 0
        for r in runs:
            if current and r["path"] == current:
                continue
            try:
                r["path"].unlink()
                removed += 1
            except OSError:
                pass
        con.print(f"{removed} log(s) deleted (this run's log kept).")
        return 0
    if args.action == "show":
        if not 1 <= args.number <= len(runs):
            raise UsageError(f"there are {len(runs)} run logs; choose 1..{len(runs)}")
        path = runs[args.number - 1]["path"]
        con.print(con.c(f"--- {path} ---", "grey"))
        con.print(path.read_text(encoding="utf-8", errors="replace"))
        return 0
    keep = _settings().get("NETHELPER_LOG_KEEP")
    if args.json:
        print(json.dumps([{**r, "path": str(r["path"])} for r in runs], indent=2))
        return 0
    con.print(f"Run logs in {folder} (newest first; the last {keep} runs are kept):")
    con.table(["#", "started", "command", "exit", "size"],
              [[n, r["started"], r["command"], r["exit"], f"{r['size'] // 1024} KB"] for n, r in enumerate(runs, 1)])
    con.print("View one with: nethelper logs show <#>")
    return 0


def cmd_caps(args, con: Console) -> int:
    """Show privilege level, tools, capture methods and which checks are limited."""
    ctx = _context(args)
    caps = ctx.caps
    load_all()
    rows = []
    for spec in REGISTRY.values():
        g = gate(spec, ctx)
        if g is None:
            state = "runs (more detail when elevated)" if spec.admin is Admin.PARTIAL and not caps.elevated else "runs"
        else:
            state = g.summary.split(" - ")[0]
        rows.append([spec.id, spec.title, state])
    if args.json:
        print(json.dumps({"os": caps.os_detail, "elevated": caps.elevated, "python": caps.python,
                          "tools": caps.tools, "capture_backends": caps.capture_backends(),
                          "checks": {r[0]: r[2] for r in rows}}, indent=2))
        return 0
    con.print(con.c(f"{APP_NAME} {__version__} on {caps.os_detail}", "bold"))
    con.kv("elevated", "yes" if caps.elevated else "no  (" + elevation_hint() + ")")
    con.kv("python", caps.python)
    con.kv("helper tools", ", ".join(sorted(caps.tools)) or "none")
    con.kv("settings file", str(_settings().path))
    con.heading("Packet capture methods")
    backends = caps.capture_backends()
    if not backends:
        con.print("  none installed - " + ("install Wireshark/Npcap or run elevated (pktmon)" if caps.os == "windows"
                                           else "install tcpdump or run with sudo"))
    for name, ok, note in backends:
        con.print(f"  {con.badge(Status.PASS if ok else Status.SKIP)} {name:<10} {note}")
    con.heading("Checks at this privilege level")
    con.table(["check", "title", "status"], rows)
    return 0


def cmd_list(args, con: Console) -> int:
    load_all()
    order = {key: n for n, (key, _) in enumerate(SECTIONS)}
    specs = sorted(REGISTRY.values(), key=lambda s: (order[s.section], s.id))
    if args.json:
        print(json.dumps([{"id": s.id, "title": s.title, "section": s.section, "modes": sorted(s.modes),
                           "admin": s.admin.value, "platforms": sorted(s.platforms) if s.platforms else "all",
                           "intrusive": s.intrusive, "external": s.external, "description": s.description}
                          for s in specs], indent=2))
        return 0
    con.table(["id", "section", "modes", "admin", "flags", "description"],
              [[s.id, SECTION_TITLES[s.section], ",".join(sorted(s.modes)) or "on demand", s.admin.value,
                ("intrusive " if s.intrusive else "") + ("external" if s.external else ""), s.description] for s in specs])
    con.print(f"{len(specs)} checks")
    return 0


def cmd_report(args, con: Console) -> int:
    from nethelper.report.export import write_report

    try:
        doc = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UsageError(f"{args.input} is not a NetHelper JSON report ({exc})") from exc
    if not isinstance(doc, dict) or "results" not in doc:
        raise UsageError(f"{args.input} is not a NetHelper JSON report")
    red = _redactor(args, None)
    path = write_report(args.output, red.walk(doc) if red else doc)
    destinations.register("reports", path)
    con.print(f"{con.badge(Status.PASS)} wrote {path}")
    return 0


def cmd_oui(args, con: Console) -> int:
    from nethelper.net import oui

    if args.action == "update":
        con.print(f"Downloading {oui.IEEE_URL} ...")
        path, count = oui.update()
        con.print(f"{con.badge(Status.PASS)} {count} vendor prefixes saved to {path}")
    else:
        count = oui.database_size()
        con.print(f"{con.badge(Status.PASS if count else Status.WARN)} {count} vendor prefixes loaded"
                  + ("" if count else " - run 'nethelper oui update'"))
    return 0


def cmd_upload(args, con: Console) -> int:
    """Copy arbitrary files to one or more destinations."""
    files = []
    for f in args.files:
        p = Path(f).expanduser()
        if not p.is_file():
            raise UsageError(f"not a file: {f}")
        files.append(p)
    targets = args.to or destinations.configured(_settings())
    if not targets:
        raise UsageError("no destination: use --to DEST or set NETHELPER_OUTPUT_DESTINATIONS (nethelper dest add ...)")
    failures = upload_files(files, targets, args.subdir)
    return 2 if failures else 0


def cmd_dest(args, con: Console) -> int:
    """List, test, add or remove output destinations."""
    st = _settings()
    configured = destinations.configured(st)
    insecure = st.get("NETHELPER_DEST_ALLOW_INSECURE")
    if args.action in ("add", "remove"):
        if not args.destination:
            raise UsageError(f"usage: nethelper dest {args.action} DEST")
        if args.action == "add":
            try:
                destinations.parse(args.destination, allow_insecure=insecure)
            except destinations.DestinationError as exc:
                raise UsageError(str(exc)) from exc
            new = list(dict.fromkeys(configured + [args.destination]))
        else:
            if args.destination not in configured:
                raise UsageError(f"'{args.destination}' is not configured; current: {'; '.join(configured) or 'none'}")
            new = [d for d in configured if d != args.destination]
        values = settings_mod.current_file_values(st.path)
        values["NETHELPER_OUTPUT_DESTINATIONS"] = "; ".join(new)
        settings_mod.save(st.path, values)
        con.print(f"{con.badge(Status.PASS)} destinations now: {'; '.join(new) or '(none)'}")
        if args.action == "add":
            con.print(con.c(f"  test it with: nethelper dest test \"{args.destination}\"", "grey"))
        return 0
    if args.action == "test":
        targets = [args.destination] if args.destination else configured
        if not targets:
            raise UsageError("nothing to test - give a destination or add one with 'nethelper dest add DEST'")
        rc = 0
        sub = destinations.expand_subdir(st.get("NETHELPER_OUTPUT_SUBDIR"))
        for raw in targets:
            try:
                dest = destinations.parse(raw, allow_insecure=insecure)
            except destinations.DestinationError as exc:
                con.print(f"{con.badge(Status.FAIL)} {raw}: {exc}")
                rc = 2
                continue
            con.print(f"Testing {dest.label} {raw} ...")
            r = destinations.test(dest, st, sub)
            if r.ok:
                # Email and syslog don't write a file anywhere, so say what was actually sent.
                what = {"email": "sent a test email -", "syslog": "sent a test event via"}.get(dest.kind, "wrote test file")
                con.print(f"{con.badge(Status.PASS)} {what} {r.remote}")
            else:
                con.print(f"{con.badge(Status.FAIL)} {r.error}")
                rc = 2
        return rc
    # list
    if args.json:
        print(json.dumps({"destinations": configured, "include": sorted(_include()),
                          "subdir": st.get("NETHELPER_OUTPUT_SUBDIR")}, indent=2))
        return 0
    if not configured:
        con.print("No output destinations configured - outputs stay local.")
    for raw in configured:
        try:
            d = destinations.parse(raw, allow_insecure=insecure)
            con.print(f"  {con.badge(Status.INFO)} {d.label:<20} {raw}")
        except destinations.DestinationError as exc:
            con.print(f"  {con.badge(Status.WARN)} {raw}: {exc}")
    con.print(con.c(f"  copies: {', '.join(sorted(_include()))} -> sub-folder "
                    f"'{destinations.expand_subdir(st.get('NETHELPER_OUTPUT_SUBDIR'))}'", "grey"))
    con.print(con.c("  add with: nethelper dest add <dest>   test with: nethelper dest test", "grey"))
    return 0


def cmd_help(args, con: Console) -> int:
    if not args.topic:
        con.print(helptext.overview())
        return 0
    page = helptext.lookup(args.topic)
    if page is None:
        raise UsageError(f"no help for '{args.topic}'. Commands: {', '.join(helptext.COMMANDS)}; "
                         f"topics: {', '.join(helptext.TOPICS)}")
    con.print(page)
    return 0


# ---------------------------------------------------------------------------
# Dispatch, error handling and entry point
# ---------------------------------------------------------------------------

HANDLERS = {
    "ping": cmd_ping, "trace": cmd_trace, "dns": cmd_dns, "port": cmd_port, "http": cmd_http, "tls": cmd_tls,
    "mtu": cmd_mtu, "check": cmd_check, "capture": cmd_capture, "monitor": cmd_monitor, "baseline": cmd_baseline,
    "fix": cmd_fix, "caps": cmd_caps, "list": cmd_list, "report": cmd_report, "oui": cmd_oui,
    "interfaces": cmd_interfaces, "wifi": cmd_wifi, "speed": cmd_speed, "throughput": cmd_throughput,
    "serve": cmd_serve, "config": cmd_config, "logs": cmd_logs, "help": cmd_help,
    "upload": cmd_upload, "dest": cmd_dest,
}

SUITES = {
    "quick": ("quick check", {"mode": "quick"}),
    "full": ("full diagnostic", {"mode": "full"}),
    "info": ("local configuration", {"sections": ["local"]}),
    "switchport": ("switchport", {"ids": ["l2.link", "l2.switchport", "l2.vlan_validation"]}),
    "vlan": ("VLAN", {"sections": ["layer2"]}),
    "dhcp": ("DHCP", {"ids": ["local.dhcp", "lan.dhcp_servers"]}),
}


def dispatch(args: argparse.Namespace) -> int:
    """Route a parsed command to its handler (may raise; see execute())."""
    c = args.command
    if c in HANDLERS:
        return HANDLERS[c](args, _console(args))
    if c == "lan":
        if args.net:
            return cmd_lan_net(args, _console(args))
        if args.sweep:
            args.allow_intrusive = True
        return run_suite(args, "local network", sections=["lan"])
    if c in SUITES:
        title, sel = SUITES[c]
        return run_suite(args, title, **sel)
    raise UsageError(f"unknown command {c!r} - see 'nethelper help'")


def execute(args: argparse.Namespace) -> int:
    """
    Run a command with uniform error handling: every failure becomes a clear
    message and exit code, with full details (traceback) in the run log.
    Used by both the command line and the interactive menu.
    """
    log.info("command: %s", vars(args))
    destinations.reset()
    try:
        code = dispatch(args)
        # Copy this command's outputs (reports, captures, results) to the destinations now;
        # the run log follows when the process finishes (main/_finish).
        if args.command not in ("upload", "dest"):
            _upload_run_outputs(args, include_logs=False)
    except (validate.ValidationError, ProfileError, UsageError) as exc:
        log.warning("usage error: %s", exc)
        print(f"error: {exc}", file=sys.stderr)
        code = EXIT_USAGE
    except FileNotFoundError as exc:
        log.warning("file not found: %s", exc)
        print(f"error: file not found: {exc.filename or exc}", file=sys.stderr)
        code = EXIT_USAGE
    except PermissionError as exc:
        log.warning("permission denied: %s", exc)
        print(f"error: permission denied ({exc}). {elevation_hint()}", file=sys.stderr)
        code = EXIT_USAGE
    except OSError as exc:
        log.exception("OS/network error")
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        code = 2
    except (KeyboardInterrupt, BrokenPipeError):
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort handler: report, log traceback, don't dump a stack on the user
        log.exception("unexpected error")
        where = current_log()
        print(f"error: unexpected {type(exc).__name__}: {exc}" + (f"\n       details: {where}" if where else ""),
              file=sys.stderr)
        code = EXIT_INTERNAL
    log.info("command finished with exit code %s", code)
    return code


def _finish(code: int, args: argparse.Namespace | None = None) -> int:
    """
    Close the run log (then copy it to the destinations, if logs are
    included); if worker threads are still busy 2 s later (a check that
    timed out, or Ctrl+C mid-run), exit immediately instead of waiting for them.
    """
    runcmd.stop_all()
    log_path = current_log()
    end_run(code)
    if args is not None and log_path and "logs" in _include() and getattr(args, "command", None) not in ("upload", "dest"):
        targets = _upload_targets(args)
        if targets:
            try:
                upload_files([Path(log_path)], targets, quiet=True, auto=True)
            except Exception as exc:  # noqa: BLE001 - log upload must never change the exit code
                print(f"upload: run log not copied ({exc})", file=sys.stderr)
    lingering = [t for t in threading.enumerate() if t is not threading.main_thread() and not t.daemon and t.is_alive()]
    # Idle thread-pool workers take a few milliseconds to exit after a run, so give
    # threads up to 2 s in total to finish before treating them as stuck. Only a
    # thread still running after that (a check hung past its timeout, or Ctrl+C
    # mid-run) triggers the immediate exit below.
    deadline = time.monotonic() + 2.0
    for t in lingering:
        t.join(max(0.0, deadline - time.monotonic()))
    lingering = [t for t in lingering if t.is_alive()]
    if lingering:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(code)
    return code


def main(argv: list[str] | None = None) -> int:
    """Program entry point: settings, logging, parse, run, clean up, return an exit code."""
    global SETTINGS
    for stream in (sys.stdout, sys.stderr):  # survive odd console encodings instead of crashing on a character
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits for --help/--version (0) and bad usage (2)
        return EXIT_USAGE if exc.code not in (0, None) else 0
    SETTINGS = settings_mod.load(getattr(args, "env", None))
    start_run(args.command or "menu", argv, SETTINGS, verbose=getattr(args, "verbose", False))
    code = EXIT_INTERNAL
    try:
        if not args.command:
            from nethelper.menu import interactive

            code = interactive(parser)
        else:
            code = execute(args)
    except KeyboardInterrupt:
        log.warning("interrupted by user (Ctrl+C)")
        print("\ninterrupted", file=sys.stderr)
        code = EXIT_INTERRUPTED
    except BrokenPipeError:
        # Output was piped into something that stopped reading (e.g. `| head`).
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 0
    return _finish(code, args)
