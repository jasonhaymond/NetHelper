# NetHelper user guide

[README](../README.md) · [Development guide](development.md) · [Example profile](../profiles/example.toml) · [Example settings](../.env.example) · [Changelog](../CHANGELOG.md)

This guide covers installing NetHelper, the menu, every command, multiple
interfaces, Wi-Fi, throughput testing, packet capture, switchport/VLAN
discovery, settings, logs, output destinations, and reports.

You can read the same material in the app itself: `nethelper help`,
`nethelper help <command|topic>`, `nethelper <command> -h`, or the menu's
**Help** section.

## Contents

1. [Requirements and installation](#1-requirements-and-installation)
2. [First run and the menu](#2-first-run-and-the-menu)
3. [Standard user vs. elevated](#3-standard-user-vs-elevated)
4. [Command reference](#4-command-reference)
5. [Reading the results](#5-reading-the-results)
6. [Multiple interfaces](#6-multiple-interfaces)
7. [Wi-Fi](#7-wi-fi)
8. [Speed and throughput](#8-speed-and-throughput)
9. [Site profiles](#9-site-profiles)
10. [Switchport and VLAN discovery](#10-switchport-and-vlan-discovery)
11. [Packet capture](#11-packet-capture)
12. [Monitor mode](#12-monitor-mode)
13. [Baselines](#13-baselines)
14. [Reports, bundles and redaction](#14-reports-bundles-and-redaction)
15. [Output destinations (local and remote)](#15-output-destinations-local-and-remote)
16. [Settings (.env)](#16-settings-env)
17. [Logs](#17-logs)
18. [Repair actions](#18-repair-actions)
19. [Privacy: what leaves the machine](#19-privacy-what-leaves-the-machine)
20. [Troubleshooting NetHelper itself](#20-troubleshooting-nethelper-itself)

---

## 1. Requirements and installation

**Needed:** Python 3.11 or newer. Nothing else is required; NetHelper uses
only Python's standard library.

1. Check Python:
   ```bash
   python --version        # Windows
   python3 --version       # Linux/macOS
   ```
   Expected: `Python 3.11.x` or higher.
2. Get NetHelper in **one** of these ways:
   - **Portable single file.** Copy `nethelper.pyz` (built with `python scripts/build.py`), then run `python nethelper.pyz --version`.
   - **From the source folder.** Run `python -m nethelper --version`.
   - **As a command.** Run `pip install .` in the source folder, then `nethelper --version`.

   Expected output: `NetHelper 1.0.0`.

Below, `nethelper` stands for whichever form you used.

**Optional helpers.** These are not required; each one unlocks extra features:

| Tool | Unlocks | Install |
|---|---|---|
| Wireshark + Npcap (Windows), Wireshark (macOS) | Non-admin packet capture via dumpcap, if permitted | wireshark.org |
| tcpdump (Linux/macOS) | Packet capture with sudo | `apt install tcpdump` (built into macOS) |
| lldpd (Linux) | Switch/port info **without** root | `apt install lldpd` |
| iperf3 | Throughput to iperf3 servers (e.g. the pfSense iperf package) | `apt install iperf3`, iperf.fr |
| OpenSSH client | `sftp://` / `scp://` output destinations | Built into Windows 10+, Linux, macOS |
| smbclient (Linux/macOS) | `smb://` destinations without mounting | `apt install smbclient` |
| NetworkManager / iw (Linux) | Wi-Fi status and scans | Usually preinstalled |
| arping (Linux) | Active duplicate-IP probe (root) | `apt install arping` |

Run `nethelper caps` to see what was detected.

## 2. First run and the menu

Run `nethelper` with no arguments to open the menu:

```
NetHelper 1.0.0 - network troubleshooting
   1) Quick health check
   2) Full diagnostic (a few minutes)
   3) Test a host, website or port
   4) Interfaces (multiple adapters)  >
   5) Wi-Fi  >
   6) Connectivity tools  >
   7) Speed & throughput  >
   8) LAN & switch  >
   9) Packet capture  >
  10) Monitoring  >
  11) Baselines & reports  >
  12) Repair actions  >
  13) Output destinations (copy reports/captures/logs elsewhere)  >
  14) Settings (.env)
  15) Logs (last runs)
  16) Help & command reference
  17) What can I run at this privilege level?
   0) Exit     (q = quit, Ctrl+C = cancel)
```

How it works:
- Entries marked `>` open a sub-menu.
- Each action asks only for what it needs. Defaults appear in `[brackets]`, so press Enter to accept them. Bad input (an invalid host, or a number out of range) is explained and you're asked again.
- Interfaces are picked from a numbered list. For multi-choice prompts, type `1,3` or `a` for all.
- Before running, the menu prints the **equivalent command** (for example `nethelper ping 8.8.8.8 -c 10`), so you can learn the shortcut.
- To navigate: `0` or Enter goes back, `q` quits from anywhere, and Ctrl+C cancels the current action and returns to the menu. Any capture running at the time is stopped cleanly.

**First check:** choose `1` and press Enter at the report question. You
should see results grouped by section, then a **Diagnosis**:
```
Connectivity
  [ OK ] Connectivity ladder       loopback, own IP, gateway, internet IP and internet name all OK
...
Diagnosis
  i  No problems found
```

## 3. Standard user vs. elevated

NetHelper works without elevation. These features need Administrator
(Windows) or root (`sudo`):

| Needs elevation (or capture permissions) | Why |
|---|---|
| Switchport (LLDP/CDP), tagged-frame check | Must capture frames sent by the switch |
| `capture` command | Packet capture |
| Rogue-DHCP probe on Linux (usually unelevated on Windows/macOS) | Must bind UDP port 68 |
| Pinning per-interface tests to an adapter on Linux | `SO_BINDTODEVICE` |
| Process names of other users' sockets; firewall rule detail (Linux/macOS) | OS restriction |

When not elevated, these show as `[SKIP] ... requires Administrator` or
`(limited: not elevated)`, and the footer says how to elevate. Use
`--hide-limited` (or `NETHELPER_HIDE_LIMITED=true`) to hide them.

**How to elevate**
- **Windows:** right-click Windows Terminal or PowerShell, choose **Run as administrator**, and run NetHelper again.
- **Linux/macOS:** run `sudo nethelper ...`.

`nethelper caps` shows the current privilege level, the capture methods available, and the status of every check.

## 4. Command reference

Common options go **after** the command, for example `nethelper quick --report x.html`.
`nethelper help <command>` shows the full page and examples for any command.

| Command | What it does |
|---|---|
| `quick` | Core health check (10–30 s); per-adapter tests when several are active |
| `full` | Every check. Heavy tests (speed test, throughput, Wi-Fi scan, sweep) run **alone at the end**, so they can't distort latency results |
| `check TARGET [-p PORTS] [--trace]` | Step-by-step test of one host, URL, `host:port` or `gateway` |
| `interfaces [--all] [--test]` | List adapters; `--test` checks each adapter's own path |
| `wifi [status\|scan\|channels\|monitor\|profiles]` | Wi-Fi tools ([section 7](#7-wi-fi)) |
| `ping HOST [-c N] [-s BYTES]` | Ping with statistics; `HOST` may be `gateway`; `-i` picks the adapter |
| `trace HOST` · `mtu [HOST]` | Traceroute · path-MTU discovery |
| `dns NAME [-t TYPE] [-s SERVER]` | Compare answers from the system, local and public DNS |
| `port HOST PORTS` · `http URL` · `tls HOST[:PORT]` | TCP ports · HTTP timing breakdown · certificate inspection |
| `info` | Local configuration only |
| `lan [--sweep] [--net CIDR]` · `dhcp` | LAN devices, ARP spoofing, rogue DHCP · DHCP checks |
| `switchport [--wait SEC]` · `vlan` | LLDP/CDP switch, port and VLAN · all VLAN checks |
| `speed [--no-latency]` | Internet speed with bufferbloat grade |
| `throughput TARGET [...]` · `serve` | LAN/WAN throughput · throughput server ([section 8](#8-speed-and-throughput)) |
| `capture [...]` | Packet capture plus summary |
| `monitor [HOSTS]` | Continuous monitoring with an outage log |
| `baseline save\|diff\|list` · `report IN.json -o OUT` | Baselines · convert/redact reports |
| `upload FILES --to DEST` · `dest list\|test\|add\|remove` | Output destinations ([section 15](#15-output-destinations-local-and-remote)) |
| `config show\|set\|unset\|edit\|init\|path\|validate` | Settings ([section 16](#16-settings-env)) |
| `logs [list\|show N\|path\|clear]` | Run logs ([section 17](#17-logs)) |
| `fix [ACTION]` | Opt-in repairs |
| `caps` · `list` · `oui update` · `help [TOPIC]` | Capabilities · all checks · MAC vendor database · help |

**Common options**

| Option | Meaning |
|---|---|
| `--profile FILE` | Site profile ([section 9](#9-site-profiles)) |
| `-i, --interface NAME[,NAME]` | Adapter(s): one name, a comma list, repeated `-i`, or `all` |
| `--target X` | Extra host, `host:port` or URL to test (repeatable) |
| `--report FILE` / `--bundle FILE.zip` | Save a report / a zip with raw outputs and captures |
| `--redact` / `--redact-all` | Scrub identifying data from reports |
| `--upload DEST` / `--no-upload` | Copy outputs to DEST / skip the configured destinations |
| `--json` | JSON output for scripts |
| `--hide-limited` | Hide elevation-limited checks |
| `--offline` | No third-party lookups (public IP, internet speed) |
| `--allow-intrusive` | Allow the subnet sweep |
| `--timeout SEC` | Per-probe timeout (default from settings, 3) |
| `--env FILE` | Use a different settings file |
| `-v` | Show check details and echo the log to the screen |
| `--no-color` | Plain output |

**Exit codes:** `0` all good · `1` warnings · `2` failures · `3` usage/configuration error · `4` unexpected internal error (see the log) · `130` Ctrl+C.

## 5. Reading the results

| Badge | Meaning |
|---|---|
| `[ OK ]` | Worked as expected |
| `[WARN]` | Works, but something looks degraded or misconfigured |
| `[FAIL]` | Broken; very likely part of the problem |
| `[INFO]` | Information only |
| `[SKIP]` | Not run: wrong OS, not configured, needs elevation, or intrusive |
| `[ERR ]` | The check itself failed (the log has details) |

The **Diagnosis** puts the most fundamental problem first. For example,
"DHCP failed" outranks "websites fail", because it causes it.

**The connectivity ladder** pinpoints where a connection breaks:

| First failing step | Look at |
|---|---|
| Loopback | The OS network stack (Winsock reset on Windows) |
| Own IP | Adapter, cable or Wi-Fi association, DHCP |
| Gateway | Cable, patch, switch port, VLAN, Wi-Fi, gateway address |
| Internet IP | Router WAN link, ISP, upstream firewall |
| Internet name | DNS, or blocked HTTPS |

## 6. Multiple interfaces

1. List the adapters:
   ```bash
   nethelper interfaces            # active adapters (* = carries the default route)
   nethelper interfaces --all      # include disconnected and virtual adapters
   nethelper interfaces -v         # plus MAC, vendor and every address
   ```
2. Test each adapter's **own** path. Traffic is sent out of each adapter by binding to its address:
   ```bash
   nethelper interfaces --test
   nethelper interfaces --test -i "Ethernet,Wi-Fi"
   ```
   Expected output:
   ```
   [ OK ] Per-interface paths  Ethernet: OK (internet 6 ms); Wi-Fi: OK (internet 9 ms)
   ```
   If an adapter shows `no connectivity`, its own link, gateway or DHCP is at fault, even when the other adapter works.
3. Use `-i` with other commands:
   ```bash
   nethelper quick -i all                      # adds per-adapter tests to a quick run
   nethelper ping 1.1.1.1 -i "Wi-Fi"           # ping out of one adapter
   nethelper throughput gateway -i Ethernet    # throughput over the cable only
   nethelper monitor -i "Ethernet,Wi-Fi"       # watch both links side by side
   nethelper switchport -i all                 # LLDP/CDP on every wired adapter
   ```

Names must match `nethelper interfaces`; quote names that contain spaces. A
wrong name stops with the list of valid names. To set a default, use
`nethelper config set NETHELPER_INTERFACES all`.

*Linux note:* without root, source binding picks the address, but the kernel
may still route by its table. With root, `SO_BINDTODEVICE` pins the adapter
exactly.

## 7. Wi-Fi

| Command | Shows |
|---|---|
| `nethelper wifi` | SSID, AP (BSSID), signal in dBm/% with a rating, band/channel, radio, link rate, security, and the adapter's driver, radio types and WPA3/PMF support |
| `nethelper wifi scan` | Every nearby AP: SSID, BSSID, band, channel, signal, security, radio, BSS load (`*` marks yours). Windows requests a **fresh** scan first |
| `nethelper wifi channels` | APs per channel, congestion scores (stronger neighbours weigh more; 2.4 GHz overlap counted), how crowded your channel is, the least-congested channels, and "evil twin" warnings. Your own AP's extra SSIDs (Guest, IoT...) aren't counted as interference |
| `nethelper wifi monitor [-n 2] [--duration 300] [--csv walk.csv]` | Signal, AP, channel and rate every few seconds. Highlights roams (BSSID change) and drop-outs; prints a min/avg/max summary |
| `nethelper wifi profiles` | Saved networks (names only; passwords are never read) |

**Walk-around survey:** run `nethelper wifi monitor --csv survey.csv` and
walk the site. The CSV has timestamp, SSID, BSSID, dBm, % and channel for
every sample.

**Signal guide:** −30 to −60 dBm is excellent; −60 to −67 is good (VoIP OK);
−67 to −70 is fair; below −70 is poor. On 2.4 GHz use channels 1, 6 and 11
only.

**Permissions:** Windows 11 needs **Location** enabled for desktop apps
(Settings › Privacy & security › Location). macOS needs Location Services for
your terminal app; otherwise SSIDs show as hidden.

A full run includes a **Wi-Fi environment** check (congestion and evil
twins). It runs alone at the end, because a scan briefly takes the radio
off-channel.

## 8. Speed and throughput

### Internet speed
```bash
nethelper speed
```
This downloads 25 MB and uploads 5 MB over HTTPS while pinging the gateway
and 1.1.1.1. Expected output:
```
[INFO] download: 51.6 Mb/s (25.0 MB in 3.9 s)
         latency to 192.168.1.1: idle 1.1 ms -> loaded 1.2 ms ..., +0.1 ms
         [ OK ] bufferbloat grade A
```
Grades C–F mean **bufferbloat**: latency jumps whenever the link is busy, and
calls stutter. Fix it with SQM on the router (fq_codel/CAKE; on pfSense,
Limiters with FQ-CoDel), set slightly below the line speed. You can change
the test URLs and sizes in settings.

### LAN or gateway throughput
1. On the far machine (a server, NAS host, another laptop), start the server:
   ```bash
   nethelper serve                      # TCP/UDP 5202, until Ctrl+C
   nethelper serve --key S3cret --once  # require a key, exit after one test
   ```
   Allow the port in its firewall if prompted.
2. On this machine:
   ```bash
   nethelper throughput 10.0.0.50                           # upload + download, 10 s each
   nethelper throughput 10.0.0.50 -P 4 --direction download # 4 parallel streams
   nethelper throughput 10.0.0.50 --udp --rate 50           # VoIP-style loss/jitter at 50 Mb/s
   nethelper throughput 10.0.0.50 --key S3cret -i "Wi-Fi"   # keyed server, over Wi-Fi
   ```
   Expected output:
   ```
   [INFO] upload: 941.2 Mb/s via nethelper
   [INFO] download: 938.7 Mb/s via nethelper
   ```
3. **To the gateway** (`nethelper throughput gateway`), NetHelper tries these in order:
   1. A NetHelper server on the gateway.
   2. **iperf3**, if iperf3 is installed here and the router runs an iperf3 server. pfSense: *System › Package Manager › iperf*, then *Diagnostics › iPerf › Server*.
   3. An **ICMP load test**: large pings from 8 threads. This is an approximate **lower bound**, because routers rate-limit pings to themselves. It also reports latency under load.

To include a throughput test in every full run, set
`NETHELPER_THROUGHPUT_TARGET=gateway` (or a host). In a profile, use
`[bandwidth] throughput_target`.

**Server safety:** the server runs only while `nethelper serve` is running.
It enforces a 60 s limit per test and at most 8 concurrent sessions. With a
key, clients prove they know it using an HMAC challenge, so the key never
crosses the network. It only sends zero-filled test data back.

## 9. Site profiles

A profile describes one site, so checks can report "wrong VLAN" or "file
server unreachable".

1. Copy the example: `copy profiles\example.toml acme-hq.toml` (or use `cp` on Linux/macOS).
2. Edit it. Every option is commented in [example.toml](../profiles/example.toml):
   - `[[targets]]`: the servers that must work
   - `[expected]`: VLAN, subnet, gateway, gateway MAC, DNS/DHCP servers, switch/port, minimum link speed
   - `[vlans.N]`: the VLAN plan
   - `[thresholds]`: warning limits
   - `[bandwidth]`: speed-test settings and `throughput_target`
3. Run with it: `nethelper full --profile acme-hq.toml`. Invalid values stop with exit code 3 and name the key.
4. To make it the default, save it as `profile.toml` in the data folder, or run `nethelper config set NETHELPER_PROFILE C:\path\acme-hq.toml`.

A profile overrides the matching `.env` settings for that site.

## 10. Switchport and VLAN discovery

1. Connect by **cable**.
2. Run elevated (or with lldpd on Linux): `nethelper switchport`.
3. Wait up to 35 s. The run stops as soon as an LLDP or CDP frame arrives. Expected output:
   ```
   [ OK ] Switchport (LLDP/CDP)  LLDP: core-sw-01, port Gi1/0/12 (Office 2.14 desk), VLAN 20 'DATA', voice VLAN 30, mgmt 10.0.0.2, PoE class 3 15.4 W
   ```
4. For CDP-only switches, run `nethelper switchport --wait 65`. To listen on every wired adapter, add `-i all`.
5. To validate against the site plan, run `nethelper vlan --profile site.toml`. It FAILs on the wrong VLAN, the wrong subnet for that VLAN, the wrong gateway, or a speed/duplex mismatch.

If nothing is heard, the cause is usually one of: an unmanaged switch,
LLDP/CDP disabled, an IP phone or hub in between, or NIC firmware consuming
LLDP (on Intel NICs, disable the "FW LLDP agent").

## 11. Packet capture

```bash
nethelper capture -f dns -d 30
nethelper capture -f host:10.0.0.5 -c 500 -o host.pcapng
nethelper capture --bpf "tcp port 445 and host 10.0.0.9"
nethelper capture --read old.pcap
```

- **Presets:** `all dns dhcp arp icmp lldp cdp l2discovery vlan tcp udp host:IP port:N`.
- **Backends,** tried in order: dumpcap/tshark, tcpdump, pktmon (Windows, admin), then a Linux raw socket (root).
- **Ctrl+C** always stops the capture tool cleanly.
- **Where files go:** `NETHELPER_CAPTURE_DIR` (default `<data dir>/captures`), unless you pass `-o`.

> Captures can contain other people's traffic. Capture only where you're
> authorised, and treat the files as sensitive.

## 12. Monitor mode

```bash
nethelper monitor                              # gateway + 1.1.1.1 + 8.8.8.8 + DNS every 5 s
nethelper monitor fs01 rdgw -n 10 --csv drops.csv
nethelper monitor -i "Ethernet,Wi-Fi"          # per-adapter gateway + internet
```
Ctrl+C (or `--duration`) prints the loss, average/max latency and every
outage. Exit code 1 means an outage happened. For Wi-Fi roaming and signal,
use `nethelper wifi monitor`.

## 13. Baselines

```bash
nethelper baseline save office [--full]
nethelper baseline diff office
nethelper full --compare office
```
A diff shows the checks that changed status, changed facts (gateway and its
MAC, DNS, public IP/ISP, switchport, VLAN, link, Wi-Fi, VPN, MTU), and
latency increases over 50%.

## 14. Reports, bundles and redaction

```bash
nethelper full --report site.html          # self-contained page (light/dark, works offline)
nethelper full --report site.md            # for tickets
nethelper full --bundle escalation.zip     # reports + raw outputs + this run's log + captures
nethelper full --report site.html --redact # safe to send to a vendor
nethelper report site.json -o vendor.html --redact
```

| Level | Hides | Keeps |
|---|---|---|
| `--redact` | Public IPs, MACs, SSIDs, host name, user name | Private (RFC 1918/CGNAT/ULA) IPs |
| `--redact-all` | All of the above plus private IPs | — |

Redacted bundles leave out packet captures, because raw packets can't be
scrubbed. The menu saves reports into `NETHELPER_REPORT_DIR` when it is set.
Set `NETHELPER_SAVE_RESULTS=true` to keep every run's results as JSON in the
results folder.

## 15. Output destinations (local and remote)

NetHelper can copy its outputs anywhere: reports and bundles, captures,
results JSON, and run logs. It can also email them, or send the results as
events to a syslog server or SIEM.

| Destination | Write it as | Credentials |
|---|---|---|
| Local folder, external or mapped drive | `D:\NetHelper`, `Z:\Reports`, `/mnt/usb`, `~/out`, `file:///srv/out` | — |
| Windows share | `\\fileserver\it\nethelper` | Your Windows logon |
| SMB (any OS) | `smb://fileserver/it/nethelper` or `smb://user@fileserver/...` | Windows: native. Linux/macOS: `smbclient` with `NETHELPER_DEST_PASSWORD` |
| SSH | `sftp://tech@backup01/srv/nethelper` (absolute), `scp://tech@backup01:2222/~/nethelper` (home-relative) | SSH key: ssh-agent, default keys, or `NETHELPER_SSH_KEY` |
| WebDAV (Nextcloud etc.) | `webdavs://jason@cloud.example.com/remote.php/dav/files/jason/NetHelper` | `NETHELPER_DEST_PASSWORD` (use a Nextcloud app password) |
| HTTPS upload endpoint | `https://intake.example.com/upload` | `NETHELPER_DEST_TOKEN` (Bearer), or user + password |
| FTPS | `ftps://tech@ftp.example.com/nethelper` | `NETHELPER_DEST_PASSWORD` |
| S3-compatible storage (AWS, MinIO, Backblaze B2, Wasabi...) | `s3://bucket-name/prefix` | `NETHELPER_S3_ACCESS_KEY` + `NETHELPER_S3_SECRET_KEY` (or the `AWS_*` environment variables); server in `NETHELPER_S3_ENDPOINT` |
| Email | `mailto:helpdesk@example.com` (one address per entry) | `NETHELPER_SMTP_SERVER`, plus `NETHELPER_SMTP_USER` / `NETHELPER_SMTP_PASSWORD` if it needs a login |
| Syslog / SIEM | `syslog+tls://siem.example.com` (TLS, port 6514), `syslog://siem` (UDP 514), `syslog+tcp://siem:514` | None (TLS server certificate verified) |

**Steps**
1. Add a destination. It is checked before it is saved:
   ```bash
   nethelper dest add "\\fileserver\it\nethelper"
   nethelper dest add sftp://tech@backup01/srv/nethelper
   ```
2. Set credentials if the destination needs them. Never put passwords in a URL; NetHelper refuses them.
   ```bash
   nethelper config set NETHELPER_DEST_PASSWORD "app-password-here"
   ```
3. Test it. This writes a small, clearly named probe file:
   ```bash
   nethelper dest test
   ```
   Expected output: `[ OK ] wrote test file .../PC-042/2026-11-18/nethelper-test-....txt`
4. From now on, every run copies its outputs to every configured destination, into `{host}/{date}/` (see `NETHELPER_OUTPUT_SUBDIR`). After the results you'll see a line like:
   ```
   upload: 3/3 file(s) -> SSH/SFTP backup01:/srv/nethelper/PC-042/2026-11-18
   ```

**One-off uses**
```bash
nethelper full --report site.html --upload Z:\Reports   # an extra destination for one run
nethelper quick --no-upload                             # skip the configured destinations once
nethelper upload old-capture.pcapng --to webdavs://...  # send any file
```

**Choosing what's copied:** `NETHELPER_OUTPUT_INCLUDE=reports,captures,logs,results`.
A failed upload is reported and logged, but never fails the diagnostic. Local
destinations never overwrite: a second file with the same name gets `-1`, `-2`, and so on.

**SSH host keys:** by default the server must already be in your
`known_hosts`, so connect once with `ssh user@host` to verify its
fingerprint. You can set `NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS=true` to trust a
host on first use. `NETHELPER_SSH_KNOWN_HOSTS` points to a separate file,
which is handy for a USB stick. On Windows the private key file must be
readable only by you:
```powershell
icacls C:\path\key /inheritance:r /grant:r "$env:USERNAME:R"
```

### S3-compatible storage

Files are uploaded as objects under `<prefix>/<host>/<date>/<file>`. The
requests are signed with AWS Signature Version 4, so the secret key is never
sent.

1. Create a bucket, and an access key that may write to it (it needs
   `s3:PutObject` only; it doesn't need to list or delete anything).
2. Tell NetHelper where the service is and which keys to use. For AWS, leave
   the endpoint empty and set the region:
   ```bash
   nethelper config set NETHELPER_S3_REGION eu-west-1
   ```
   For anything else, set the endpoint. MinIO and most self-hosted stores use
   region `us-east-1`:
   ```bash
   nethelper config set NETHELPER_S3_ENDPOINT https://minio.example.com:9000
   nethelper config set NETHELPER_S3_ENDPOINT https://s3.us-west-004.backblazeb2.com
   ```
   Then set the keys:
   ```bash
   nethelper config set NETHELPER_S3_ACCESS_KEY AKIA...
   nethelper config set NETHELPER_S3_SECRET_KEY "the-secret-key"
   ```
3. Add and test the destination:
   ```bash
   nethelper dest add s3://acme-netlogs/nethelper
   nethelper dest test
   ```
   Expected output: `[ OK ] wrote test file s3://acme-netlogs/nethelper/PC-042/2026-11-19/nethelper-test-....txt`

If the test fails, the message names the S3 error and the likely cause:
- `SignatureDoesNotMatch`: wrong secret key
- `InvalidAccessKeyId`: wrong access key
- `AccessDenied`: the key may not write here
- `NoSuchBucket`
- `PermanentRedirect` or `AuthorizationHeaderMalformed`: wrong region
- `RequestTimeTooSkewed`: this PC's clock is more than 15 minutes off

`NETHELPER_S3_ADDRESSING` is normally left on `auto`. Set it to `path` if a
self-hosted store complains about the bucket name in the host name.

### Email

Each run that produces a report, results or a capture sends **one** email.
The subject carries the diagnosis headline (for example `NetHelper results
from PC-042: Gateway unreachable`), the body summarises the findings, and the
files are attached.

1. Point NetHelper at your mail server:
   ```bash
   nethelper config set NETHELPER_SMTP_SERVER smtp.office365.com
   nethelper config set NETHELPER_SMTP_USER alerts@example.com
   nethelper config set NETHELPER_SMTP_PASSWORD "app-password"
   ```
   The default security is `starttls` (port 587). Use
   `NETHELPER_SMTP_SECURITY=ssl` for port 465. For an internal relay that
   accepts mail without a login, leave the user and password empty. A relay
   with no TLS at all needs `NETHELPER_SMTP_SECURITY=none` plus
   `NETHELPER_DEST_ALLOW_INSECURE=true`.
2. Optionally set the sender. By default it is the SMTP login, or
   `nethelper@<computer name>`:
   ```bash
   nethelper config set NETHELPER_SMTP_FROM nethelper@example.com
   ```
3. Add and test it:
   ```bash
   nethelper dest add mailto:helpdesk@example.com
   nethelper dest test
   ```
   Expected output: `[ OK ] sent a test email - email to helpdesk@example.com`

Notes:
- **One address per entry.** Add several `mailto:` destinations to email several people.
- **Size limit:** files that would take the email over `NETHELPER_EMAIL_MAX_MB` (default 20) are listed in the body but not attached. Large captures are better sent to a share or S3 as well.
- **Run logs are not emailed automatically.** That would mean an email for every command, even `nethelper ping`. To email one, run `nethelper upload <log file> --to mailto:...`.
- **Microsoft 365 and Gmail** usually need an app password or an SMTP relay connector; your normal password is refused.

### Syslog / SIEM

A syslog destination doesn't receive files. It receives **events** in the
standard RFC 5424 format:

| From | Events sent |
|---|---|
| Results JSON | One per diagnosis finding, plus one per check (`check=`, `status=`, `section=`) |
| Run log | One per WARNING/ERROR line |
| Any other file (report, capture...) | One "file produced" event with its name, size and SHA-256, as an audit trail |

Severity follows the result: FAIL and critical findings are *error*, WARN is
*warning*, everything else is *informational*.

1. Add the server. Prefer TLS (port 6514 by default):
   ```bash
   nethelper dest add syslog+tls://siem.example.com
   ```
   Plain UDP or TCP syslog is unencrypted, so it is refused unless you allow it:
   ```bash
   nethelper config set NETHELPER_DEST_ALLOW_INSECURE true
   nethelper dest add syslog://siem.example.com          # UDP 514
   nethelper dest add syslog+tcp://siem.example.com:514
   ```
2. Optionally change the facility (`NETHELPER_SYSLOG_FACILITY`, default
   `local0`). If your SIEM parses JSON more easily than RFC 5424 structured
   data, set `NETHELPER_SYSLOG_FORMAT=json`.
3. Test it:
   ```bash
   nethelper dest test
   ```
   Expected output: `[ OK ] sent a test event via syslog tls siem.example.com:6514 (1 events)`. Then find the event in your SIEM. Its MSGID is `test`.

Example event (RFC 5424 format):
```
<131>1 2026-11-19T10:15:02.123-08:00 PC-042 NetHelper 4242 check [nethelper@32473 check="conn.gateway_ping" status="FAIL" section="connectivity"] Gateway ping: 100% loss
```

### Security

- **Certificates:** TLS certificates are always verified, for WebDAV, HTTPS, FTPS, S3, SMTP and syslog over TLS. If a server uses a certificate from your company's own CA, set `NETHELPER_DEST_CA_FILE` to that CA's certificate (a PEM file). There is no option to switch verification off.
- **Unencrypted transports:** these are refused unless `NETHELPER_DEST_ALLOW_INSECURE=true`:
  - `http://`, `webdav://` and `ftp://`
  - `syslog://` and `syslog+tcp://`
  - an `http://` S3 endpoint
  - SMTP security `none`
- **Network text:** text that came from the network (Wi-Fi names, server banners) is flattened to one line before it goes into an email or syslog event, so a hostile name can't add email headers or fake extra syslog lines.

## 16. Settings (.env)

App-wide defaults live in a `.env` file:
- Windows: `%LOCALAPPDATA%\NetHelper\.env`
- Linux/macOS: `~/.local/share/nethelper/.env`

`nethelper config path` shows where yours is. Every setting is documented in
[.env.example](../.env.example).

| Task | Command |
|---|---|
| See everything, with each value's source | `nethelper config show` |
| Change one | `nethelper config set NETHELPER_TIMEOUT 5` |
| Reset one | `nethelper config unset NETHELPER_TIMEOUT` |
| Interactive editor | `nethelper config edit` (or menu › Settings) |
| Guided setup of all settings | `nethelper config init` (asks before overwriting) |
| Check the file | `nethelper config validate` |

- **Validation:** values are checked when you save them. An invalid hand-edit is reported, and the default is used instead.
- **Backups:** the previous file is kept as `.env.bak`.
- **Secrets:** the throughput key, destination password and token, S3 secret key and SMTP password are always shown as `********` and are never logged.

**Precedence:** command-line flag > site profile > environment variable >
`.env` > built-in default. Use `--env FILE` to run with a different settings
file.

## 17. Logs

Every run writes its own detailed log, named
`logs/run-<date>-<time>-<ms>-p<pid>-<command>.log`. It records:
- the settings in use
- every check with its result and details
- every external command, with its arguments, exit code, duration and output
- warnings and full error tracebacks
- the final exit code

Only the newest **40** runs are kept (`NETHELPER_LOG_KEEP`). Each file is
capped at 10 MB, and secrets are masked.

```bash
nethelper logs            # list recent runs with exit codes
nethelper logs show       # print the latest finished run
nethelper logs show 3     # third most recent
nethelper logs path       # folder location
```
You can also browse them from the menu: **Logs (last runs)**, then type `t5`
to see the last 60 lines of run 5. When a command hits an unexpected error,
the message names the log file to look at.

## 18. Repair actions

```bash
nethelper fix                      # list actions
nethelper fix flush-dns
nethelper fix renew-dhcp -i "Wi-Fi"
nethelper fix restart-adapter -i eth0
```
Each action shows the exact commands it will run, warns about disconnects
(louder over SSH or RDP), and waits for you to type `yes`. Most actions need
elevation.

## 19. Privacy: what leaves the machine

- **Normal checks** talk only to your network, your DNS servers, and well-known public endpoints. You can change those endpoints in a profile.
- **Third-party lookups** (public IP, internet speed test) can be turned off with `--offline` or `NETHELPER_EXTERNAL_LOOKUPS=false`.
- **Outputs** are copied only to the destinations **you** configure ([section 15](#15-output-destinations-local-and-remote)).

## 20. Troubleshooting NetHelper itself

| Symptom | Fix |
|---|---|
| `error: no interface named ...` | Use a name from `nethelper interfaces`, quoted if it has spaces |
| Wi-Fi shows "Location permission" (Windows 11) | Settings › Privacy & security › Location: allow desktop apps |
| macOS SSIDs hidden | Allow Location Services for the terminal app |
| `sftp` upload: "host key isn't trusted" | Run `ssh user@host` once, or set `NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS=true` |
| `sftp` upload: "key authentication failed" | Load the key into ssh-agent or set `NETHELPER_SSH_KEY`; on Windows, restrict the key file's permissions (see [section 15](#15-output-destinations-local-and-remote)) |
| WebDAV "authentication failed" | Check the user in the URL and `NETHELPER_DEST_PASSWORD` (Nextcloud: app password) |
| Upload: "TLS certificate isn't trusted" | The server uses an internal CA (or a self-signed or wrong-name certificate): set `NETHELPER_DEST_CA_FILE` to the CA's PEM file |
| S3: `SignatureDoesNotMatch` / `AuthorizationHeaderMalformed` | Wrong secret key / wrong `NETHELPER_S3_REGION` |
| Email: "doesn't offer STARTTLS" | Use `NETHELPER_SMTP_SECURITY=ssl` with port 465, or check the server and port |
| Email: "SMTP login refused" | Check `NETHELPER_SMTP_USER` and `NETHELPER_SMTP_PASSWORD`; Microsoft 365/Gmail need an app password or a relay |
| `throughput`: "no NetHelper server" | Run `nethelper serve` on the target, or let it fall back to iperf3/ICMP |
| Capture: "pktmon already has packet filters" | Someone else configured pktmon: check `pktmon filter list` |
| `[ERR ]` or exit code 4 | Look at `nethelper logs show` and send it along with a `--bundle` |
| `settings warning: ...` | Run `nethelper config validate`, then fix the named key |
