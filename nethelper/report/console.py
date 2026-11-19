"""
Prints a run's results and verdict to the terminal.

Layout:
  header (host, OS, privilege level, profile)
  one block per section, one line per check:  [ OK ] Title ........ summary
      followed by "-> advice" lines for WARN/FAIL
  "Diagnosis" block from the verdict engine
  a footer noting privilege-limited checks and how to re-run elevated

Privilege-limited checks (skipped or reduced because we're not elevated) are
shown by default with a short note; --hide-limited removes them from the
listing and leaves a one-line count instead.
"""

from __future__ import annotations

import json

from nethelper import APP_NAME, __version__
from nethelper.core.console import Console
from nethelper.core.privileges import Capabilities, elevation_hint
from nethelper.core.registry import SECTIONS
from nethelper.core.result import CheckResult, Status
from nethelper.report.verdict import Finding

SEV_STYLE = {"critical": ("red", "!!"), "warning": ("yellow", "! "), "info": ("cyan", "i ")}


def header(con: Console, caps: Capabilities, profile_source: str, mode: str) -> None:
    """Print the run banner."""
    level = con.c("elevated", "green") if caps.elevated else con.c("standard user (some checks limited)", "yellow")
    con.print(con.c(f"{APP_NAME} {__version__}", "bold") + f"  -  {mode}")
    con.print(con.c(f"{caps.os_detail} | Python {caps.python} | ", "grey") + level)
    con.print(con.c(f"profile: {profile_source}", "grey"))


def results(con: Console, items: list[CheckResult], hide_limited: bool = False, verbose: bool = False) -> None:
    """Print results grouped by section."""
    title_w = max((len(r.title) for r in items), default=20)
    title_w = min(max(title_w, 18), 30)
    for key, section_title in SECTIONS:
        group = [r for r in items if r.section == key and not (hide_limited and r.limited and r.status is Status.SKIP)]
        if not group:
            continue
        con.heading(section_title)
        for r in group:
            summary = r.summary
            if r.limited and r.status is not Status.SKIP:
                summary += con.c("  (limited: not elevated)", "grey")
            line = f"  {con.badge(r.status)} {r.title:<{title_w}}  {summary}"
            con.print(line)
            if r.status in (Status.FAIL, Status.WARN, Status.ERROR):
                for tip in r.advice[:3]:
                    con.print(con.c(f"         -> {tip}", "dim"))
            if verbose and r.status not in (Status.SKIP,):
                details = {k: v for k, v in r.details.items() if k != "privilege_note"}
                if details:
                    text = json.dumps(details, indent=2, default=str)
                    for ln in text.splitlines()[:40]:
                        con.print(con.c("         " + ln, "grey"))


def verdict(con: Console, findings: list[Finding]) -> None:
    """Print the diagnosis block."""
    con.heading("Diagnosis")
    for f in findings:
        color, mark = SEV_STYLE[f.severity]
        con.print(f"  {con.c(mark, color, 'bold')} {con.c(f.title, 'bold')}")
        con.print(f"     {f.explanation}")
        for step in f.next_steps[:3]:
            con.print(con.c(f"     -> {step}", "dim"))


def footer(con: Console, items: list[CheckResult], caps: Capabilities, hide_limited: bool) -> None:
    """Print totals and the privilege note."""
    counts = {s: sum(1 for r in items if r.status is s) for s in Status}
    parts = [f"{counts[s]} {s.value}" for s in (Status.PASS, Status.WARN, Status.FAIL, Status.ERROR, Status.INFO, Status.SKIP) if counts[s]]
    con.print("")
    con.print(con.c("Totals: " + ", ".join(parts), "grey"))
    limited = [r for r in items if r.limited]
    if limited and not caps.elevated:
        names = ", ".join(r.title for r in limited[:6]) + (" ..." if len(limited) > 6 else "")
        if hide_limited:
            con.print(con.c(f"({len(limited)} privilege-limited check(s) hidden; run elevated for full results)", "grey"))
        else:
            con.print(con.c(f"Limited without elevation: {names}", "yellow"))
            con.print(con.c(f"  {elevation_hint()}", "yellow"))
