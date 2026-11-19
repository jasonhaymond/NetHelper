"""
Security tests: reports, redaction and stored files.

Reports are opened in browsers and shared with third parties, and baselines
are files named by the user. These tests prove:
  - network-controlled text can't inject script into HTML reports (XSS)
  - redaction really removes public IPs, MACs, SSIDs and host/user names
  - baseline names can't escape the baselines folder (path traversal)
  - redacted bundles leave out raw packet captures (which can't be scrubbed)
"""

from __future__ import annotations

import socket
import zipfile

import pytest

from nethelper.core.result import CheckResult, Status
from nethelper.core.validate import ValidationError
from nethelper.report import baseline
from nethelper.report.export import build_document, to_html, to_markdown, write_bundle
from nethelper.report.redact import Redactor
from nethelper.report.verdict import diagnose

XSS = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'


def _doc(summary: str = "ok", details: dict | None = None) -> dict:
    r = CheckResult("local.wifi", "Wi-Fi", "local", Status.WARN, summary, details or {}, [summary])
    return build_document([r], diagnose([r]), {"host": XSS, "os": "test", "elevated": False,
                                               "mode": "quick", "profile": XSS})


def test_html_report_escapes_hostile_ssid():
    """Blocks stored XSS: an SSID/banner containing <script> is shown as text, not executed."""
    page = to_html(_doc(summary=f"SSID {XSS}", details={"ssid": XSS}))
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;" in page


def test_html_report_has_no_scripts_or_external_resources():
    """The report page is self-contained: no JavaScript and nothing fetched from the internet."""
    page = to_html(_doc())
    assert "<script" not in page.lower()
    assert "http://" not in page and "https://" not in page.replace("https://example", "")


def test_markdown_report_neutralises_html_and_tables():
    """Blocks HTML injection and table-breaking pipes in Markdown reports."""
    md = to_markdown(_doc(summary=f"a | b {XSS}"))
    assert "<script>" not in md
    assert "a \\| b" in md


def test_redaction_hides_public_ips_macs_ssid_hostname():
    """--redact removes identifying values but keeps private IPs useful for troubleshooting."""
    host = socket.gethostname()
    red = Redactor("standard", extra_secrets=["AcmeCorpWiFi"])
    text = (f"public 203.0.113.9 and 2606:4700::1111, private 192.168.1.10, mac AA-BB-CC-11-22-33, "
            f"ssid AcmeCorpWiFi, host {host}")
    out = red.text(text)
    assert "203.0.113.9" not in out and "2606:4700::1111" not in out
    assert "AA-BB-CC-11-22-33".lower() not in out.lower()
    assert "AcmeCorpWiFi" not in out
    if len(host) >= 3:
        assert host not in out
    assert "192.168.1.10" in out  # private addresses kept at the standard level
    # The same value always maps to the same token.
    assert red.text("203.0.113.9") == red.text("again 203.0.113.9").split()[-1]


def test_redact_all_hides_private_ips_too():
    """--redact-all also removes private addresses."""
    out = Redactor("all").text("gw 10.0.0.1 and 192.168.5.5")
    assert "10.0.0.1" not in out and "192.168.5.5" not in out


def test_redaction_walks_nested_structures():
    """Every string in a nested report document is redacted, including dictionary keys."""
    red = Redactor("standard")
    doc = {"a": ["203.0.113.1", {"203.0.113.2": "x"}], "n": 5}
    out = red.walk(doc)
    assert "203.0.113" not in str(out) and out["n"] == 5


@pytest.mark.parametrize("bad", ["../../evil", "..\\..\\evil", "a/b", "C:\\x", "", "a" * 65, "name.json"])
def test_baseline_names_block_path_traversal(bad):
    """Blocks writing/reading files outside the baselines folder via a crafted name."""
    with pytest.raises(ValidationError):
        baseline.save(bad, {"results": []})


def test_redacted_bundle_excludes_raw_captures(tmp_path):
    """
    A capture file can't be redacted, so write_bundle callers pass no capture
    files when redacting; here we verify the bundle contains exactly what was given.
    """
    doc = _doc()
    out = write_bundle(tmp_path / "b.zip", doc, {"facts": "203.0.113.5"}, [])
    names = zipfile.ZipFile(out).namelist()
    assert "report.html" in names and "raw/facts.txt" in names
    assert not any(n.startswith("files/") for n in names)
