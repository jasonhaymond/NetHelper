# NetHelper development guide

[README](../README.md) · [User guide](user-guide.md) · [Changelog](../CHANGELOG.md)

## Contents

1. [Principles](#1-principles)
2. [Code layout](#2-code-layout)
3. [How a run works](#3-how-a-run-works)
4. [Adding a check](#4-adding-a-check)
5. [Adding a setting, command or menu item](#5-adding-a-setting-command-or-menu-item)
6. [Setting up and running tests](#6-setting-up-and-running-tests)
7. [Security review gate](#7-security-review-gate)
8. [Releasing a version](#8-releasing-a-version)
9. [Known limitations and untested paths](#9-known-limitations-and-untested-paths)

## 1. Principles

- **Standard library only at runtime.** NetHelper must run on any machine with Python 3.11+. The dev tools in `requirements-dev.txt` are never imported by the app.
- **Works as a standard user; elevated runs add detail.** Every check declares its privilege needs, and the runner enforces them. Prefer the non-elevated route wherever one exists: the Windows ICMP API, unprivileged ICMP sockets, `lldpctl`, SendARP, WlanScan.
- **External programs go through `nethelper/core/cmd.py` only.** That means list arguments, no shell, a `which()`-resolved path and a timeout. Every call is logged, and background tools are tracked so `stop_all()` can stop them on Ctrl+C. User input goes through `core/validate.py` first.
- **Network data is untrusted.** Parsers bounds-check everything, displayed text goes through `validate.safe_text()`, and HTML output escapes everything.
- **Checks never print.** They return an `Outcome`, which feeds the console, reports, baselines and the verdict.
- **Bandwidth-heavy checks are `exclusive=True`.** They run alone after the parallel batch, so they can't distort latency measurements.
- **Every failure becomes a message and an exit code.** `cli.execute()` handles this, and the traceback goes into the run log.
- **Commenting standard:** every file has a header and every function a docstring. Explain jargon and regexes (with an example), and state what security-relevant code protects against. The audience is an IT engineer who doesn't read Python daily.

## 2. Code layout

```
nethelper/
  __init__.py        version (single source of truth, mirrored in pyproject.toml)
  cli.py             argument parsing, command handlers, execute() error handling, upload of outputs
  menu.py            interactive menu (data-driven tree), settings editor, logs + help browsers
  helptext.py        every command's description + examples, topic pages
  monitor.py         connection monitor + Wi-Fi monitor
  core/              result, registry, runner, context, privileges, cmd, validate,
                     config (profiles), settings (.env), logsetup (per-run logs),
                     destinations (local/SMB/SFTP/WebDAV/HTTPS/FTPS/S3/email/syslog outputs), console, paths
  net/               protocol building blocks: icmp (with source binding), traceroute, mtu,
                     dnswire, tcp, httpcheck, x509, tlscheck, ntp, publicip, bandwidth
                     (speed + bufferbloat + iperf3), throughput (server/client), wifi,
                     discovery (mDNS/SSDP), dhcp, arp, oui, pcap, l2proto, capture, remediate
  system/            local facts: model + windows/linux/macos collectors (Windows "light" mode)
  checks/            the checks: local, connectivity, dns_checks, app, lan, layer2, interfaces
  report/            verdict, console renderer, export (JSON/MD/HTML/zip), redaction, baselines
profiles/example.toml       every profile option
.env.example                every setting (generated: python scripts/gen_env_example.py)
scripts/build.py            builds dist/nethelper.pyz
scripts/gen_env_example.py  regenerates .env.example from core/settings.py
scripts/security-check.ps1  full security suite + report
tests/                      pytest suite
```

## 3. How a run works

1. **Start-up.** `cli.main()` parses the arguments, loads the settings (`.env` plus the environment) and opens this run's log file. That log is pruned to the newest `NETHELPER_LOG_KEEP` runs.
2. **Execute.** `execute()` calls the command handler and catches every error class. Each error becomes a clear message, exit code 3 for usage or 4 for internal errors, and a log traceback. It then uploads this command's registered outputs (`destinations.register(...)`) to the destinations.
3. **Suite runs** (`run_suite`):
   - builds a `Context` (capabilities, profile on top of the settings, options including `-i` interfaces, which are checked against the real adapter list)
   - selects the checks
   - runs them with `runner.run_checks()`: parallel checks first, then exclusive ones one at a time, with gating for OS, admin, intrusive and offline
   - produces the verdict, prints the results, and writes the report, bundle, results and baseline
4. **Shared work** happens once per run through `ctx.memo()`. That covers the system snapshot (`ctx.facts`) and LLDP/CDP discovery (`layer2.discover_switch`, per wired interface).
5. **Finish.** `_finish()` stops any background tools, closes the log, uploads the log if logs are included, and exits immediately if worker threads are still stuck.

Privilege notes: a check that lost detail because the run wasn't elevated
adds `privilege_note` to its details, and the runner then marks it `limited`.

## 4. Adding a check

1. Pick the section module in `nethelper/checks/`.
2. Write the check:
   ```python
   @check("app.myservice", "My service", "app", modes=("full",), admin=Admin.NO, timeout=30)
   def myservice(ctx: Context) -> Outcome:
       """One-sentence description - shown by `nethelper list`."""
       res = tcp.connect("svc.acme.local", 8443, timeout=ctx.options.timeout)
       if res.state != "open":
           return Outcome(Status.FAIL, f"TCP/8443 {res.state}", {"result": vars(res)}, ["Plain-English next step."])
       return Outcome(Status.PASS, f"open in {res.connect_ms} ms", {"result": vars(res)})
   ```
   - The id is permanent, because baselines and verdict rules refer to it.
   - Use `ctx.facts`, `ctx.threshold`, `ctx.profile`, `ctx.options.interfaces` and `ctx.setting(KEY)`.
   - Add `exclusive=True` if the check moves a lot of data.
3. If it deserves a headline, add a rule to `report/verdict.py` `RULES`.
4. Add tests in the same change.

## 5. Adding a setting, command or menu item

- **Setting:**
  1. Add a `Spec` to `core/settings.py` `SPECS` (key, default, validator, help, group, and `secret=True` if it is one).
  2. Run `python scripts/gen_env_example.py`. A test fails if `.env.example` is stale.
  3. Read the setting with `_settings().get(KEY)` in the CLI, or `ctx.setting(KEY)` in checks.
- **Command:**
  1. Add the parser in `cli.build_parser()` with `add("name")`.
  2. Add the handler to `HANDLERS`.
  3. Add a `helptext.COMMANDS` entry with at least 2 examples. A test checks that every command has help and that every example parses.
- **Menu item:** add an `Item(label, argv, prompts)` to `menu.build_tree()`. A test builds every item's command line with sample answers and parses it.

## 6. Setting up and running tests

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest                     # Windows - expect 197 passed
wsl -e bash -lc "cd '/mnt/c/.../NetHelper' && PYTHONPATH=.venv/Lib/site-packages python3 -m pytest -q -p no:cacheprovider"
```

| File | Covers |
|---|---|
| `test_security_input.py` | Injection via hosts/ports/interfaces/BPF/URLs/profiles; `cmd.run` uses no shell; timeouts |
| `test_security_parsers.py` | DNS pointer loops, spoofed ids, truncation; fuzzing of every parser; corrupt pcap; escape sequences |
| `test_security_output.py` | HTML XSS, Markdown escaping, redaction levels, baseline path traversal, bundle contents |
| `test_protocols.py` | Real local DNS (UDP + TC→TCP), HTTP, TCP, SMTP banner, TLS self-signed, NTP, ICMP |
| `test_layer2.py` | LLDP/CDP decode, pcap/pcapng, VLAN tags, ARP conflicts, DHCP, VLAN validation |
| `test_system_parsers.py` | Windows/Linux/macOS command output samples (run on any OS) |
| `test_framework.py` | Runner gating, crash/timeout containment, verdict, baselines, CLI basics |
| `test_settings_logs_help.py` | `.env` parsing/precedence/validation/backup/masking, `.env.example` in sync, keeping the last N run logs, secret masking in logs, every command has examples that parse, every menu item parses, menu input validation, `config` CLI, exit code 4 on unexpected errors |
| `test_throughput_wifi_dest.py` | Throughput up/down/parallel/UDP; key auth; server limits (oversized handshake, length, mode, rate); ICMP fallback; Wi-Fi parsers, channel analysis and evil twins; every destination type parsed; rejections (passwords in URL, insecure transports, path/host injection); local copy never overwrites; WebDAV and HTTPS uploads against a local server; SFTP batch mode without a shell; smbclient keeps the password off the command line; `dest`/`upload` CLI; source-address binding |
| `test_build.py` | The `.pyz` build is byte-for-byte repeatable (file times don't matter); fixed entry metadata (date, Unix mode, no compression, sorted, no bytecode); LF line endings; the `.pyz` passes exit codes to the OS (0 for `--version`, 3 for a usage error) |
| `test_dest_s3_email_syslog.py` | S3/mailto/syslog parsing and rejections (several recipients, mailto `?bcc=`, bad bucket, credentials in URL, key-prefix traversal, unencrypted syslog, option-like host); new settings validated (header injection in the sender address); SigV4 against AWS's published example signature; S3 path-style PUT with payload hash against a fake server, S3 error hints, refusal of an http endpoint, addressing styles; email: one message, attachments, a hostile diagnosis title can't add a Bcc header, size limit, plain SMTP needs the insecure opt-in, STARTTLS enforced; automatic log uploads don't email; syslog event mapping, RFC 5424 escaping, newline (log-injection) flattening, JSON format, UDP datagrams and TCP octet-counted framing; new secrets masked; uploads never follow a redirect (the bearer token is not sent to the redirect target); URL-encoded trailing newlines rejected |

**Manual verification before a release:**
- `quick`, `full -i all --report`, `interfaces --test`, every `wifi` subcommand, `speed`
- `serve` plus `throughput` (TCP and UDP, `--once`, a key), `throughput gateway`
- `dest test` and an `--upload` run to each destination type you can reach
- a scripted walk through the menu
- HTML report screenshots at desktop width and at 375 px

## 7. Security review gate

Run `pwsh scripts/security-check.ps1`, which runs ruff, bandit (with a
listing of suppressions), semgrep and PSScriptAnalyzer if installed,
pip-audit, gitleaks, and pytest on Windows and on Linux via WSL. The report
goes to `security-reports/` (gitignored). The developer approves every run.

**`# nosec` suppressions.** Each has a "Security note" on the line above it.
These need your explicit approval:

| Where | Rule | Why it's acceptable |
|---|---|---|
| `core/cmd.py` (import, `run`, `Background`) | B404/B603 | The single audited subprocess wrapper: list argv, no shell, path from `which()`, timeout |
| `net/tlscheck.py` diagnostic context | B501 | Only re-reads an already-rejected certificate to explain the failure; no data is sent |
| `net/*.py` `urlopen` calls | B310 | URLs are validated http(s), from fixed values or validated settings/destinations |
| `net/dhcp.py` `ANY_ADDRESS` | B104 | A DHCP client must listen on all interfaces to receive broadcast offers; the socket lives 5 s and only accepts our transaction id |
| `net/throughput.py` `ANY_ADDRESS` | B104 | `nethelper serve` is a LAN test server the user starts explicitly. `--bind` narrows it; limits and HMAC key auth apply to every client |
| `core/destinations.py` `import ftplib` | B402 | Needed for FTPS (`FTP_TLS`, encrypted control and data channels, certificate verified). Plain `ftp://` is refused unless the user explicitly allows insecure transports |
| `core/destinations.py` `ftplib.FTP(...)` | B321 | Only reachable for `ftp://` with `NETHELPER_DEST_ALLOW_INSECURE=true` |
| `core/result.py` `Status.PASS` | B105 | A test-outcome label, not a password (false positive) |

## 8. Releasing a version

1. Confirm the batch is complete.
2. Bump the version in `nethelper/__init__.py` **and** `pyproject.toml`, and add a `CHANGELOG.md` entry.
3. Run `pwsh scripts/security-check.ps1`, show the report, and get approval.
4. Commit, then re-run the suite against the commit.
5. Tag: `git tag -a vX.Y.Z -m "... Security review: approved <date>, report <file>, accepted risks: <n|none>"`.
6. Push the commit and the tag:

   ```bash
   git push origin main
   git push origin vX.Y.Z
   ```

7. Publish the GitHub Release. **Every release gets one**, with `nethelper.pyz` and `nethelper.pyz.sha256` attached. A tag without the download is an incomplete release.

   ```powershell
   pwsh scripts/release.ps1 -DryRun   # build + verify only; shows the files and release notes
   pwsh scripts/release.ps1           # publish
   ```

   The script needs PowerShell 7.3+, git, Python 3.11+ and the GitHub CLI signed in (`gh auth login`). It:

   - refuses unless `vX.Y.Z` is an annotated tag containing `Security review: approved` and has been pushed to origin
   - builds the `.pyz` from a temporary checkout of that exact tag, never from your working folder
   - checks that the built file reports `NetHelper X.Y.Z`
   - writes the checksum
   - creates the release with download instructions and the version's `CHANGELOG.md` section

   It refuses an existing release unless you pass `-Replace` (re-upload the files). Expected end of a real run:

   ```text
     build OK: NetHelper X.Y.Z
     sha256: <64 hex characters>

   Published: https://github.com/jasonhaymond/NetHelper/releases/tag/vX.Y.Z
   ```

8. Check the published download:

   ```bash
   gh release download vX.Y.Z -D /tmp/nh-check
   cd /tmp/nh-check && sha256sum -c nethelper.pyz.sha256 && python3 -I nethelper.pyz --version
   ```

   Expected: `nethelper.pyz: OK` and `NetHelper X.Y.Z`.

For a local-only build (testing, a one-off copy), run `python scripts/build.py`. The output goes to `dist/nethelper.pyz`. `dist/` is gitignored; never commit the `.pyz`.

**The build is repeatable.** The same commit gives a byte-identical `.pyz` on Windows, Linux and macOS, with any Python 3.11+, so anyone can rebuild a tag and match the published SHA-256. `scripts/build.py` achieves this by fixing every machine-dependent detail:

- fixed entry dates and sorted entry order
- Unix mode 0644 on every entry
- LF line endings
- no compression, because Windows and Linux Pythons ship different zlib libraries that compress differently

Its header comment has the details, and `tests/test_build.py` guards them. Don't switch to `zipapp.create_archive` or turn compression on without keeping that property.

## 9. Known limitations and untested paths

| Area | Status |
|---|---|
| Windows 11, standard user | Tested live: every command, the menu, `.pyz`, Wi-Fi (scan/channels/monitor/profiles/status), interfaces, `speed`, `serve`/`throughput` (TCP, parallel, UDP, `--once`, key), `throughput gateway` (ICMP fallback) |
| Output destinations | **Tested live:** <ul><li>local folder (as a mapped/external drive would be)</li><li>SFTP/SCP with real OpenSSH and key auth in strict host-key mode (temporary Debian container)</li><li>S3 against the Versity S3 gateway (real SigV4 verification, over HTTPS, with a private CA through `NETHELPER_DEST_CA_FILE`), including the wrong-secret and missing-bucket errors</li><li>email through Mailpit with STARTTLS required and SMTP login</li><li>syslog over TLS to a local TLS receiver (RFC 5425 framing checked), including the untrusted-certificate error</li></ul> **Tested against local test servers:** WebDAV (MKCOL/PUT, Basic auth), HTTPS upload (PUT, Bearer), plain SMTP, UDP and TCP syslog. **Not tested live:** a real UNC share or mapped network drive (no share available; this uses ordinary Windows file copy), Nextcloud, `smbclient` on Linux/macOS, FTPS, real AWS S3 / Backblaze / Wasabi (virtual-host addressing is only covered by a unit test), Microsoft 365 / Gmail SMTP, a real SIEM (Splunk, Graylog, Wazuh...), TLS syslog with client certificates (not supported) |
| Linux (Ubuntu 24.04 in WSL) | Full test suite; earlier live runs as user and root (raw-socket capture, DHCP probe). New interface/Wi-Fi/throughput commands not yet run live on Linux (WSL has no Wi-Fi) |
| Windows elevated: pktmon capture and LLDP via pktmon | **Not yet tested live**; verify on a wired port from an Administrator terminal |
| dumpcap/tshark, tcpdump, iperf3 | **Not yet tested live** (not installed on the dev box); iperf3 JSON parsing follows its documented format |
| macOS | Parsers tested against sample output only; **not run on a Mac** |
| LLDP/CDP | Tested with synthetic frames only; verify against real switches |
| Per-interface tests with two real uplinks | Logic tested with one Wi-Fi uplink plus loopback binding; verify on a machine with Ethernet and Wi-Fi both connected |
| Windows connection refused | Windows retries a refused SYN for about 2 s, so "refused" results take about 2 s there |
