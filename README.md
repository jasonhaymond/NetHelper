# NetHelper

Cross-platform network troubleshooting in one tool. NetHelper checks a
machine's network from the adapter up to the application, works out where
things break, and says what to do in plain English. It runs on Windows, Linux
and macOS, as a standard user or elevated.

**Current version: 1.0.0** (first release, 2026-11-19). See [CHANGELOG.md](CHANGELOG.md).

## Documentation

| Doc | For |
|---|---|
| [User guide](docs/user-guide.md) | Installing, the menu, every command, interfaces, Wi-Fi, throughput, capture, switchport/VLAN, settings, logs, output destinations |
| [Development guide](docs/development.md) | Code layout, adding a check, tests, the security gate, releases, untested paths |
| [Example site profile](profiles/example.toml) | Every profile option, commented |
| [Example settings (.env)](.env.example) | Every app setting, commented |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

Built-in help: `nethelper help`, `nethelper help <command|topic>`, `nethelper <command> -h`.

## Highlights

- **Interactive menu** covering every feature (run `nethelper` with no
  arguments). Each action shows the equivalent command, so it doubles as a
  way to learn the CLI.
- **48 checks in six sections:**
  - **Local host:** adapters, IPs, routes, DNS, DHCP, proxy, VPN, firewall, Wi-Fi, hosts file, listening ports.
  - **Connectivity:** the connectivity ladder, latency/jitter/loss, traceroute, egress filtering, MTU black holes, IPv6.
  - **DNS:** resolver comparison, records, hijacking, DNSSEC, DoT/DoH, captive portals.
  - **Applications:** site targets, HTTP timing, TLS trust/interception, public IP, clock skew, speed and bufferbloat, LAN throughput.
  - **LAN:** ARP spoofing, rogue DHCP, mDNS/UPnP, subnet sweep.
  - **Switchport & VLAN:** LLDP/CDP switch, port, access and voice VLAN, PoE; VLAN/subnet validation.
- **Plain-English diagnosis** that puts the root cause first.
- **Multiple interfaces:** `-i NAME`, `-i a,b` or `-i all`, and per-adapter path tests (`interfaces --test`).
- **Wi-Fi:** status, fresh scans, channel congestion with recommendations, evil-twin detection, a roaming/signal monitor, saved profiles.
- **Throughput:** a built-in server/client (TCP up/down, parallel streams, UDP loss/jitter) to any host or to `gateway`, with iperf3 and ICMP-load fallbacks.
- **Packet capture** with presets, using dumpcap/tshark, tcpdump, pktmon or Linux raw sockets.
- **Outputs and history:**
  - reports (HTML/MD/JSON), zip bundles, and redaction
  - baselines with diffs, and monitor mode with an outage log
  - per-run detailed logs, keeping the last 40 runs
- **Output destinations:** copy reports, captures, results and logs to a local, external or mapped drive, a Windows/SMB share, SFTP/SCP, WebDAV (Nextcloud), an HTTPS endpoint, FTPS or S3-compatible storage. You can also email them, or send the results as events to a syslog server or SIEM.
- **Settings in `.env`**, editable from the menu or with `nethelper config`.
- **Elevation handling:** checks that need Administrator or root are skipped with a note on how to elevate (or hidden with `--hide-limited`).

## Quick start

NetHelper uses only Python's standard library. You need Python 3.11 or newer; there is nothing to install.

```bash
python -m nethelper                 # interactive menu
python -m nethelper quick           # 10-30 s health check
python -m nethelper full --report site.html
python -m nethelper check fileserver01 -p 445
python -m nethelper wifi channels
python -m nethelper throughput gateway
python -m nethelper switchport      # run elevated: which switch/port/VLAN?

# One portable file for USB sticks and client PCs:
python scripts/build.py             # -> dist/nethelper.pyz
python nethelper.pyz quick
```

To install it as a `nethelper` command, run `pip install .`

Exit codes: `0` all good · `1` warnings · `2` failures · `3` usage/config error · `4` internal error · `130` Ctrl+C.

## Development

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt    # Windows (.venv/bin/pip elsewhere)
.venv\Scripts\python -m pytest                        # test suite (Windows + Linux via WSL: see dev guide)
pwsh scripts/security-check.ps1                       # full security suite + report
```

See the [development guide](docs/development.md).
