"""
Framework tests: the runner's privilege/OS/intrusive/offline gating, error
containment, the verdict engine, baselines, and the command-line interface.
"""

from __future__ import annotations

import json
import socket
import sys
import threading

import pytest

from nethelper import cli
from nethelper.core.config import parse_profile
from nethelper.core.registry import Admin, CheckSpec, load_all, select
from nethelper.core.result import CheckResult, Outcome, Status
from nethelper.core.runner import gate, run_checks, run_one
from nethelper.report import baseline
from nethelper.report.verdict import diagnose
from tests.conftest import make_caps


def _spec(func, admin=Admin.NO, platforms=None, intrusive=False, external=False, timeout=5.0) -> CheckSpec:
    return CheckSpec(id=f"test.{func.__name__}", title=func.__name__, section="local", func=func,
                     modes=frozenset({"quick"}), admin=admin, platforms=platforms, intrusive=intrusive,
                     external=external, description="", timeout=timeout)


def _ok(ctx):
    return Outcome(Status.PASS, "fine")


def test_admin_only_check_is_skipped_and_marked_limited_when_not_elevated(ctx):
    """Privilege gating: an Admin.YES check never runs non-elevated, and is flagged as limited."""
    res = run_one(_spec(_ok, admin=Admin.YES), ctx)
    assert res.status is Status.SKIP and res.limited
    ctx.caps = make_caps(elevated=True)
    assert run_one(_spec(_ok, admin=Admin.YES), ctx).status is Status.PASS


def test_platform_intrusive_and_external_gating(ctx):
    """OS mismatch, intrusive checks without consent, and external lookups with --offline are all skipped."""
    assert "not supported" in gate(_spec(_ok, platforms=frozenset({"macos"})), ctx).summary
    assert "allow-intrusive" in gate(_spec(_ok, intrusive=True), ctx).summary
    ctx.options.external = False
    assert "external" in gate(_spec(_ok, external=True), ctx).summary


def test_crashing_check_becomes_error_not_crash(ctx):
    """One broken check yields an ERROR result; the rest of the run continues."""
    def boom(_):
        raise RuntimeError("kaboom")
    results = run_checks([_spec(boom), _spec(_ok)], ctx)
    assert results[0].status is Status.ERROR and "kaboom" in results[0].summary
    assert results[1].status is Status.PASS


def test_hung_check_times_out(ctx):
    """A check that hangs past its timeout is reported as ERROR instead of blocking the run forever."""
    release = threading.Event()

    def hang(_):
        release.wait(30)
        return Outcome(Status.PASS, "late")
    spec = _spec(hang, timeout=0.1)
    results = run_checks([spec], ctx)
    release.set()
    assert results[0].status is Status.ERROR and "timed out" in results[0].summary


def test_registry_selection_and_unique_ids():
    """All checks register with unique ids; quick is a subset of full plus nothing intrusive."""
    reg = load_all()
    assert len(reg) >= 40
    quick = {s.id for s in select(mode="quick")}
    full = {s.id for s in select(mode="full")}
    assert quick <= full
    assert not any(s.intrusive for s in select(mode="quick"))
    assert {s.id for s in select(ids=["dns."])} == {i for i in reg if i.startswith("dns.")}


def _r(cid: str, status: Status, summary: str = "") -> CheckResult:
    return CheckResult(cid, cid, "local", status, summary or status.value)


def test_verdict_prioritises_root_cause():
    """The verdict leads with the most fundamental failure (no IP) rather than downstream symptoms."""
    findings = diagnose([_r("local.interfaces", Status.FAIL, "Wi-Fi has only a self-assigned 169.254.x.x address"),
                         _r("conn.ladder", Status.FAIL, "breaks at 'Gateway': no reply"),
                         _r("app.http", Status.FAIL, "all failed")])
    assert findings[0].title.startswith("DHCP failed")
    assert findings[0].severity == "critical"


def test_verdict_dns_and_all_clear():
    """DNS failure is named as such; an all-PASS run yields 'No problems found'."""
    assert diagnose([_r("dns.resolvers", Status.FAIL, "configured DNS server(s) not answering")])[0].title == "DNS resolution failure"
    assert diagnose([_r("x.y", Status.PASS)])[0].title == "No problems found"


def test_verdict_never_drops_unexplained_failures():
    """A FAIL with no dedicated rule still appears in the verdict."""
    titles = [f.title for f in diagnose([_r("custom.thing", Status.FAIL, "broke")])]
    assert any("custom.thing" in t for t in titles)


def test_baseline_save_load_diff():
    """Baselines round-trip, and diff reports status changes, fact changes and latency jumps."""
    old = {"generated": "t0", "results": [
        {"check_id": "lan.gateway_mac", "title": "GW", "status": "PASS", "summary": "", "details": {"mac": "aa:aa:aa:aa:aa:aa"}},
        {"check_id": "conn.gateway_ping", "title": "GP", "status": "PASS", "summary": "", "details": {"avg_ms": 2.0}}]}
    new = {"generated": "t1", "results": [
        {"check_id": "lan.gateway_mac", "title": "GW", "status": "WARN", "summary": "changed", "details": {"mac": "bb:bb:bb:bb:bb:bb"}},
        {"check_id": "conn.gateway_ping", "title": "GP", "status": "PASS", "summary": "", "details": {"avg_ms": 40.0}}]}
    baseline.save("office", old)
    assert baseline.load("office")["generated"] == "t0"
    d = baseline.diff(baseline.load("office"), new)
    assert d["status_changes"][0]["after"] == "WARN"
    assert d["fact_changes"][0]["fact"] == "Gateway MAC"
    assert d["latency"][0]["after_ms"] == 40.0


def test_example_profile_parses():
    """The shipped example profile is valid."""
    import tomllib
    from pathlib import Path

    raw = tomllib.loads((Path(__file__).parent.parent / "profiles" / "example.toml").read_text(encoding="utf-8"))
    p = parse_profile(raw)
    assert p.site_name and p.targets and p.vlans


# --- CLI ------------------------------------------------------------------

def run_cli(args, capsys):
    code = cli.main(args + ["--no-color"])
    return code, capsys.readouterr()


def test_cli_rejects_injection_with_usage_exit_code(capsys):
    """Malicious input on the command line is refused with exit code 3 and a clear message."""
    code, out = run_cli(["ping", "-S 1.2.3.4"], capsys)
    assert code == 3 and "error" in out.err
    code, out = run_cli(["port", "127.0.0.1", "22;reboot"], capsys)
    assert code == 3


def test_cli_list_and_caps(capsys):
    """`list` and `caps` run without elevation and describe privilege requirements."""
    code, out = run_cli(["list"], capsys)
    assert code == 0 and "l2.switchport" in out.out
    code, out = run_cli(["caps"], capsys)
    assert code == 0 and "elevated" in out.out


def test_cli_port_and_ping_against_localhost(capsys):
    """`port` and `ping` work end-to-end against a real local listener."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    code, out = run_cli(["port", "127.0.0.1", str(port)], capsys)
    srv.close()
    assert code == 0 and "open" in out.out
    code, out = run_cli(["ping", "127.0.0.1", "-c", "2"], capsys)
    assert code == 0


def test_cli_fix_lists_actions_and_cancels_without_yes(capsys, monkeypatch):
    """`fix` lists actions; an action is NOT executed unless the user types 'yes'."""
    code, out = run_cli(["fix"], capsys)
    assert code == 0 and "flush-dns" in out.out
    ran = []
    monkeypatch.setattr("nethelper.core.cmd.run", lambda argv, **k: ran.append(argv))
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    code, out = run_cli(["fix", "flush-dns"], capsys)
    assert "Cancelled" in out.out and ran == []


def test_cli_report_conversion_with_redaction(tmp_path, capsys):
    """`report` converts a saved JSON report to HTML, applying redaction."""
    doc = {"tool": "NetHelper", "version": "x", "generated": "now", "host": "h", "verdict": [],
           "results": [{"check_id": "app.public_ip", "title": "Public IP", "section": "app", "status": "INFO",
                        "summary": "203.0.113.50 - ISP", "details": {}}]}
    src = tmp_path / "r.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    out_file = tmp_path / "r.html"
    code, _ = run_cli(["report", str(src), "-o", str(out_file), "--redact"], capsys)
    assert code == 0 and "203.0.113.50" not in out_file.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform != "win32" and not sys.platform.startswith("linux"), reason="collector tested on Windows/Linux")
def test_cli_info_runs_on_this_machine(capsys):
    """`info` (local section) completes on the real machine without errors."""
    code, out = run_cli(["info", "--json"], capsys)
    data = json.loads(out.out)
    assert not [r for r in data["results"] if r["status"] == "ERROR"]
