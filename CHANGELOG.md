# Changelog

All notable changes to NetHelper are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

[Back to README](README.md)

## [Unreleased]

## [1.0.0] - 2026-11-19

First version. It was developed under the working name "Netsleuth" and
renamed to NetHelper before release.

### Added
- **Checks:** 48 diagnostic checks in six sections (local host, connectivity, DNS, applications, LAN, switchport & VLAN).
  - They run in parallel with privilege/OS gating.
  - Bandwidth-heavy checks (speed test, throughput, Wi-Fi scan, sweep) run alone afterwards, so they can't distort latency results.
  - A plain-English verdict engine summarises the findings.
- **Elevation:** runs as a standard user or elevated. Limited checks are noted with how to elevate, or hidden with `--hide-limited`; `nethelper caps` shows what works.
- **Interactive menu** covering every feature. It has sub-menus, validated prompts with defaults, an interface picker, and shows the equivalent command for every action.
- **Built-in help:** `nethelper help`, per-command pages with worked examples, topic pages, and `-h` epilogs. A Help browser is included in the menu.
- **Multiple interfaces:**
  - `-i NAME`, `-i a,b`, `-i all`; `nethelper interfaces` (list) and `interfaces --test` (gateway/internet/DNS through each adapter, using source-address binding, plus `SO_BINDTODEVICE` as root on Linux)
  - per-interface monitor
  - switchport discovery on several wired adapters
- **Wi-Fi:**
  - `wifi status` (including adapter capabilities), `scan` (fresh scan via WlanScan on Windows), `channels` (congestion analysis that excludes your own AP's extra SSIDs, plus recommendations), `monitor` (signal, roams, drop-outs, CSV) and `profiles`
  - Wi-Fi environment check with evil-twin detection
- **Speed and throughput:**
  - Internet speed test with latency-under-load (bufferbloat) grading.
  - Built-in throughput server/client (`serve` / `throughput`): TCP upload/download, parallel streams, UDP loss/jitter/reordering, optional HMAC key auth, strict server limits.
  - Targets can be a host or `gateway`, with iperf3 and ICMP-load fallbacks.
  - Optional LAN throughput check in full runs.
- **Settings in a `.env` file:** 50 documented settings with validation, `.env.bak` backups and masked secrets. Managed with `nethelper config show|set|unset|edit|init|path|validate`, a menu editor and a guided setup. `.env.example` is generated from the definitions.
- **Logging:** a detailed log per run (settings, checks, every external command, tracebacks, exit code). The newest 40 runs are kept (configurable), each file is capped at 10 MB, and secrets are masked. Browse with `nethelper logs` or the Logs menu.
- **Output destinations:** reports, bundles, captures, results JSON and run logs can be copied to:
  - local folders, external or mapped drives
  - Windows/SMB shares (native, or `smbclient`)
  - SFTP/SCP (OpenSSH, key auth, strict host keys)
  - WebDAV (e.g. Nextcloud)
  - HTTPS upload endpoints (PUT/POST, bearer token)
  - FTPS
  - S3-compatible object storage (AWS S3, MinIO, Backblaze B2, Wasabi...), signed with AWS Signature Version 4 and needing no extra libraries
  - email over SMTP (STARTTLS/SSL): one message per run, with the diagnosis in the subject and the files attached, plus a size limit
  - syslog/SIEM over TLS (RFC 5425), UDP or TCP: one event per check result and diagnosis finding, each WARNING/ERROR log line, and a "file produced" record

  Configure with `--upload`, `NETHELPER_OUTPUT_DESTINATIONS`, `nethelper dest add|test|list|remove` or `nethelper upload`. Files go into a per-machine `{host}/{date}` folder. Passwords in URLs are refused, insecure transports are blocked by default, and local copies never overwrite. Servers using an internal CA are trusted with `NETHELPER_DEST_CA_FILE`; certificate checks can't be switched off.
- **Error handling:** uniform across the CLI and menu (exit code 3 for usage errors, 4 for internal errors with the log path). Ctrl+C stops capture tools (tcpdump, pktmon) cleanly. Clear errors for unknown interface names, bad profiles and bad settings.
- **Core diagnostics:**
  - unprivileged ICMP everywhere (Windows ICMP API, datagram sockets, system ping), with source-address support
  - a dependency-free DNS client (UDP/TCP/DoT/DoH/DNSSEC), X.509 reader, TLS inspection, HTTP phase timing, SNTP
  - LLDP/CDP decoding and VLAN validation
  - packet capture via dumpcap/tshark, tcpdump, pktmon or a Linux raw socket, with a summary
  - rogue DHCP, ARP spoofing, mDNS/SSDP discovery, subnet sweep
- **Reports and tooling:** monitor mode, baselines with diffs, HTML/Markdown/JSON reports, zip bundles, redaction, and opt-in repairs with typed confirmation.
- **Packaging and quality:** TOML site profiles; single-file build (`scripts/build.py` → `dist/nethelper.pyz`); a test suite of 193 tests including security tests (Windows and Linux); and the security suite (`scripts/security-check.ps1`).

### Fixed (found during development)
- **Speed test distorting latency:** it ran in parallel with the latency checks, which reported a falsely "unstable" gateway link.
- **`serve --once`:** it stopped after the first parallel stream, cutting the others off.
- **Throughput server rejections:** a rejected request (for example an oversized handshake) could reach the client as "connection reset" instead of the reason, because the server closed with unread data. It now closes gracefully.
- **Premature forced exit:** at the end of a run, idle worker threads that were still shutting down were mistaken for hung checks, and the process was force-exited. This was harmless from the command line, but it killed in-process callers such as the test suite. Threads now get 2 seconds to finish first.
- **DNS servers given by name** (in profiles) never matched their replies and always timed out.
- **ARP-spoofing headline:** the verdict raised it when the gateway MAC merely couldn't be resolved.
- **Redaction:** it kept documentation-range public IPs, because Python counts them as "private".
- **macOS `arp`:** MACs without leading zeros failed to parse.
- **URL validation:** it accepted `javascript:` URLs.
- **Credentials on redirect (security):** HTTPS, WebDAV and S3 uploads followed HTTP redirects with the Authorization header still attached, so a server could send it to another host. Uploads now never follow redirects.
- **Destination checks (security hardening):** a URL-encoded trailing newline (`%0A`) could slip past the remote-path, bucket and email checks. They now require an exact full match.
