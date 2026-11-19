"""
Built-in help: a detailed description and worked examples for every command,
plus topic pages explaining concepts (elevation, interfaces, Wi-Fi,
throughput, capture, switchport, profiles, settings, logs...).

Used by:
  nethelper help                 overview of all commands and topics
  nethelper help <command>       full page for one command
  nethelper help <topic>         full page for one topic
  nethelper <command> -h         argparse help + the same examples
  the interactive menu           "Help" section

Keeping all help text here (rather than scattered through the parser) means
the CLI, menu and docs stay consistent. A test verifies that every command
has a help entry with at least two examples, and that every example parses.
"""

from __future__ import annotations

# command -> {"summary", "description", "examples": [(command line, what it does)]}
COMMANDS: dict[str, dict] = {
    "quick": {
        "summary": "Fast health check of this machine and its connection (10-30 s)",
        "description": (
            "Runs the core checks in parallel: adapters and IP addresses, default gateway, DNS settings, "
            "the connectivity ladder (loopback -> own IP -> gateway -> internet IP -> internet name), "
            "gateway and internet latency/loss, resolver comparison, captive portal, web fetches, public IP, "
            "gateway identity (ARP), Wi-Fi signal, link speed and - when several adapters are active - each "
            "adapter's own path. Ends with a plain-English diagnosis. Start here for any 'the network is "
            "broken' call."),
        "examples": [
            ("nethelper quick", "standard health check"),
            ("nethelper quick --report site.html", "also save a shareable HTML report"),
            ("nethelper quick -i all", "include per-adapter path tests for every active interface"),
            ("nethelper quick --profile acme.toml --target fs01:445", "use a site profile and test an extra server port"),
            ("nethelper quick --json > result.json", "machine-readable output for scripts"),
        ],
    },
    "full": {
        "summary": "Every check - adds traceroute, MTU, egress ports, DNS deep checks, TLS, NTP, speed, LAN, Wi-Fi scan, switchport/VLAN",
        "description": (
            "Runs all 48 checks: everything in quick plus traceroute, path MTU, outbound port filtering, IPv6, "
            "DNS records/reverse/hijacking/DNSSEC/encrypted DNS, TLS certificates, clock skew, internet speed "
            "with bufferbloat grading, LAN throughput (if a target is configured), ARP table, duplicate IP, "
            "rogue DHCP, mDNS/UPnP discovery, Wi-Fi environment scan, and switchport/VLAN discovery (LLDP/CDP "
            "needs a wired link and capture rights). Typically 30-90 s plus up to 35 s listening for the switch."),
        "examples": [
            ("nethelper full --report acme-hq.html", "complete diagnostic with an HTML report"),
            ("nethelper full --profile acme.toml --bundle escalation.zip", "site profile + zip of report, raw outputs and captures"),
            ("nethelper full --offline", "skip third-party lookups (public IP, internet speed test)"),
            ("nethelper full --compare office", "also show what changed since the saved 'office' baseline"),
            ("nethelper full --wait 65 --allow-intrusive", "CDP-friendly switch wait, and include the subnet sweep"),
        ],
    },
    "check": {
        "summary": "Focused, step-by-step test of one host, URL or host:port",
        "description": (
            "Resolves the name (system and public DNS, to spot internal-only names or broken local DNS), pings it, "
            "tests the TCP ports (default 80,443 or what you give with -p), fetches it over HTTP(S) with a timing "
            "breakdown, inspects its TLS certificate, and traces the route when something fails. Ideal for 'I "
            "can't reach X' tickets."),
        "examples": [
            ("nethelper check fs01.acme.local -p 445", "can I reach the file server's SMB port?"),
            ("nethelper check https://erp.acme.com/login", "is the web app slow - DNS, network, TLS or server?"),
            ("nethelper check 10.0.40.10:3389 --trace", "RDP port test with the route shown"),
            ("nethelper check mail.acme.com -p 25,465,587,993", "mail ports in one go"),
        ],
    },
    "interfaces": {
        "summary": "List every network adapter; --test runs gateway/internet/DNS through each one separately",
        "description": (
            "Shows each adapter's type (Ethernet, Wi-Fi, VPN, virtual), state, MAC and vendor, IPv4/IPv6 "
            "addresses, its gateway and DNS servers, speed/duplex, MTU, VLAN tag and Wi-Fi network. With "
            "--test, traffic is sent out of each adapter (by binding to its address) to test its own gateway, "
            "internet ping, HTTPS port and DNS - answering 'is it the Wi-Fi or the cable?' or 'does the backup "
            "link work?'. Use -i to limit to specific adapters, or --all to include down/virtual ones in the list."),
        "examples": [
            ("nethelper interfaces", "table of active adapters"),
            ("nethelper interfaces --all", "include disconnected and virtual adapters"),
            ("nethelper interfaces --test", "test every active adapter's own path"),
            ('nethelper interfaces --test -i "Ethernet,Wi-Fi"', "compare just the cable and the Wi-Fi"),
        ],
    },
    "wifi": {
        "summary": "Wi-Fi tools: status, scan, channels, monitor, profiles",
        "description": (
            "status (default) - current network, BSSID, signal (dBm and %), band/channel, link rate, security, and "
            "adapter capabilities.\n"
            "scan - every access point nearby with signal, channel, security and BSS load (Windows triggers a "
            "fresh scan).\n"
            "channels - congestion per channel (stronger neighbours weigh more; 2.4 GHz overlap counted), how "
            "crowded your channel is, recommended channels, and same-name/different-security 'evil twin' warnings. "
            "Your own AP's extra SSIDs are excluded.\n"
            "monitor - samples signal/BSSID/rate every few seconds; logs roams and drop-outs with a summary.\n"
            "profiles - saved Wi-Fi networks on this machine (names only; passwords are never read).\n"
            "Windows 11 needs Location permission for SSID/BSSID details; macOS needs Location Services for the "
            "terminal app."),
        "examples": [
            ("nethelper wifi", "current connection details"),
            ("nethelper wifi scan", "nearby networks, strongest first"),
            ("nethelper wifi channels", "which channel is least congested?"),
            ("nethelper wifi monitor -n 2 --duration 300", "watch signal and roaming for 5 minutes"),
            ("nethelper wifi monitor --csv walk.csv", "log a walk-around survey to CSV"),
            ("nethelper wifi profiles", "saved networks"),
        ],
    },
    "ping": {
        "summary": "Ping with live replies and statistics (loss, min/avg/max, jitter)",
        "description": (
            "Uses the Windows ICMP API or unprivileged ICMP sockets, so no admin rights are needed. -s sets the "
            "payload size, -c the count, and -i/--source sends from a specific interface or IP."),
        "examples": [
            ("nethelper ping 8.8.8.8", "10 pings with statistics"),
            ("nethelper ping gateway -c 100", "100 pings to the default gateway (keyword 'gateway')"),
            ("nethelper ping 10.0.0.1 -s 1400", "large packets (finds fragmentation/MTU trouble)"),
            ('nethelper ping 1.1.1.1 -i "Wi-Fi"', "ping out of the Wi-Fi adapter specifically"),
        ],
    },
    "trace": {
        "summary": "Traceroute with hop names and timings",
        "description": (
            "Maps each router between here and the target. On Windows (and Linux/macOS as root) all hops are "
            "probed in parallel, so it finishes in seconds. '*' hops are routers that ignore probes - normal."),
        "examples": [
            ("nethelper trace 1.1.1.1", "path to Cloudflare DNS"),
            ("nethelper trace erp.acme.com --max-hops 20", "path to an app server, 20 hops max"),
        ],
    },
    "dns": {
        "summary": "Look up a name (or IP) via the system resolver, configured and public DNS servers side by side",
        "description": (
            "Compares answers and response times so you can see at a glance whether the local DNS server, a public "
            "resolver, or the name itself is the problem. Any record type: A AAAA MX TXT NS SOA CNAME PTR SRV CAA. "
            "An IP address does a reverse (PTR) lookup."),
        "examples": [
            ("nethelper dns intranet.acme.local", "does the internal name resolve, and where?"),
            ("nethelper dns acme.com -t MX", "mail servers for a domain"),
            ("nethelper dns _ldap._tcp.acme.local -t SRV", "find domain controllers"),
            ("nethelper dns www.google.com -s 10.0.0.10 -s 1.1.1.1", "ask two specific servers"),
            ("nethelper dns 8.8.8.8", "reverse lookup"),
        ],
    },
    "port": {
        "summary": "Test TCP ports on a host (open / refused / filtered)",
        "description": (
            "'open' = something accepted; 'refused' = host is up but nothing listens there; 'timeout' = filtered by "
            "a firewall or host down. Ranges up to 1024 ports."),
        "examples": [
            ("nethelper port 10.0.0.5 22,80,443,3389", "common admin ports"),
            ("nethelper port printer01 9100,631,515", "printer protocols"),
            ("nethelper port 192.168.1.20 8000-8010", "a small range"),
        ],
    },
    "http": {
        "summary": "Fetch a URL with a DNS / connect / TLS / server-response timing breakdown",
        "description": "Follows redirects and shows each hop, so you can see exactly which phase is slow.",
        "examples": [
            ("nethelper http https://www.microsoft.com", "timing breakdown"),
            ("nethelper http http://intranet.acme.local/login", "internal site, plain HTTP"),
        ],
    },
    "tls": {
        "summary": "Inspect a TLS certificate: trust, chain, expiry, names, protocol, interception",
        "description": (
            "Reads the certificate even when it isn't trusted (to explain why). Flags TLS-inspection products "
            "re-signing traffic (Fortinet, Zscaler, Palo Alto, ...)."),
        "examples": [
            ("nethelper tls github.com", "standard HTTPS"),
            ("nethelper tls mail.acme.com:993", "IMAPS certificate"),
            ("nethelper tls 10.0.0.1:8443", "firewall admin page"),
        ],
    },
    "mtu": {
        "summary": "Discover the path MTU and detect MTU black holes",
        "description": (
            "Binary-searches the largest unfragmented ping. Below 1500 is normal for PPPoE (1492) and VPNs; a "
            "'black hole' (big packets silently dropped) explains half-loading pages and stalling transfers."),
        "examples": [
            ("nethelper mtu", "to the default trace target (1.1.1.1)"),
            ("nethelper mtu 10.20.0.1", "across a site-to-site VPN"),
        ],
    },
    "info": {
        "summary": "Local configuration only: adapters, routes, DNS, DHCP, proxy, VPN, firewall, Wi-Fi, listening ports",
        "description": "Sends almost no network traffic - safe to run anywhere for a configuration snapshot.",
        "examples": [
            ("nethelper info", "local configuration"),
            ("nethelper info --report config.md", "save it as Markdown for a ticket"),
        ],
    },
    "lan": {
        "summary": "Devices on the LAN: gateway identity, ARP table, mDNS/UPnP, duplicate IP, rogue DHCP; optional sweep",
        "description": (
            "Checks the gateway's MAC/vendor (ARP-spoofing detection), lists recent neighbours with vendors, "
            "detects IP conflicts, finds rogue DHCP servers and lists devices announcing themselves (printers, "
            "TVs, NAS). --sweep or --net actively probes every address (may trip IDS alerts - use with permission)."),
        "examples": [
            ("nethelper lan", "passive LAN overview + rogue DHCP check"),
            ("nethelper lan --sweep", "also sweep the local subnet"),
            ("nethelper lan --net 10.0.40.0/24", "sweep a specific network"),
        ],
    },
    "switchport": {
        "summary": "Which switch, port and VLAN this jack connects to (LLDP/CDP), plus link speed/duplex",
        "description": (
            "Listens for the switch's LLDP (every 30 s) or CDP (every 60 s) announcement and decodes switch name, "
            "port, access VLAN, voice VLAN, PoE and management IP. Needs a cable connection and capture rights "
            "(run elevated, or install lldpd on Linux). Stops as soon as a frame arrives. -i all listens on every "
            "wired adapter."),
        "examples": [
            ("nethelper switchport", "listen up to 35 s on the primary wired adapter"),
            ("nethelper switchport --wait 65", "for CDP-only (Cisco) switches"),
            ('nethelper switchport -i "Ethernet 2"', "a specific adapter"),
            ("nethelper switchport -i all", "every wired adapter (e.g. a two-port server)"),
        ],
    },
    "vlan": {
        "summary": "All VLAN checks: switch VLAN, subnet/gateway validation, tagged frames, inter-VLAN reachability",
        "description": (
            "Combines switchport discovery with the site profile's VLAN plan ([expected] and [vlans.N]) to FAIL on "
            "wrong VLAN, wrong subnet for the VLAN, wrong gateway, or speed/duplex mismatch with the switch, and "
            "pings each VLAN's gateway/targets."),
        "examples": [
            ("nethelper vlan --profile acme.toml", "validate this port against the site VLAN plan"),
            ("nethelper vlan --profile acme.toml --report vlan.html", "same, with a report"),
        ],
    },
    "dhcp": {
        "summary": "DHCP lease details and rogue DHCP server detection",
        "description": (
            "Broadcasts a DHCP DISCOVER (never a REQUEST - no lease is taken) and lists every server that offers an "
            "address. More than one server, or one not in [expected] dhcp_servers, is flagged."),
        "examples": [
            ("nethelper dhcp", "lease info + rogue check"),
            ("nethelper dhcp --profile acme.toml", "flag servers not on the approved list"),
        ],
    },
    "speed": {
        "summary": "Internet download/upload speed with bufferbloat (latency under load) grading",
        "description": (
            "Downloads/uploads a known amount over HTTPS (Cloudflare by default; change in settings) while pinging "
            "the gateway and a public IP. A big latency rise under load (grade C-F) means bufferbloat - fix with "
            "SQM/fq_codel on the router. For LAN or gateway throughput use 'throughput'."),
        "examples": [
            ("nethelper speed", "internet speed + bufferbloat grade"),
            ("nethelper speed --no-latency", "speed only"),
        ],
    },
    "throughput": {
        "summary": "LAN/WAN throughput to a host or the gateway (NetHelper server, iperf3, or ICMP-load fallback)",
        "description": (
            "Measures real TCP throughput (upload, download or both; -P parallel streams) or UDP loss/jitter at a "
            "chosen rate, against a machine running 'nethelper serve'. TARGET may be an IP/hostname or the word "
            "'gateway' (the default gateway, or the gateway of the -i interface). If the target runs no NetHelper "
            "server it tries iperf3 (if installed here) and finally an ICMP load test - an approximate lower bound "
            "that works against any router. -i sends the test out of a specific adapter."),
        "examples": [
            ("nethelper throughput 10.0.0.50", "upload + download to a PC running 'nethelper serve'"),
            ("nethelper throughput gateway", "to the default gateway (iperf3 on pfSense, or ICMP load)"),
            ("nethelper throughput 10.0.0.50 -P 4 -t 20 --direction download", "4 parallel streams, 20 s, download only"),
            ("nethelper throughput 10.0.0.50 --udp --rate 50", "VoIP-style test: 50 Mb/s UDP, report loss and jitter"),
            ('nethelper throughput gateway -i "Wi-Fi"', "Wi-Fi-only throughput to the router"),
            ("nethelper throughput nas01 --key S3cret", "server protected with a shared key"),
        ],
    },
    "serve": {
        "summary": "Run a NetHelper throughput server so other machines can test against this one",
        "description": (
            "Listens on TCP/UDP 5202 (NETHELPER_THROUGHPUT_PORT) until Ctrl+C. Each client test is printed and "
            "logged. Use --key (or NETHELPER_THROUGHPUT_KEY) to require a shared secret, --bind to listen on one "
            "address only, --once to exit after a single test. Allow the port in the host firewall (Windows will "
            "prompt). Limits: 60 s per test, 8 concurrent sessions."),
        "examples": [
            ("nethelper serve", "listen on all addresses, port 5202"),
            ("nethelper serve --key S3cret --bind 10.0.0.50", "require a key, listen on one address"),
            ("nethelper serve --once", "exit after one test"),
        ],
    },
    "capture": {
        "summary": "Packet capture with presets and an automatic summary",
        "description": (
            "Presets: all dns dhcp arp icmp lldp cdp l2discovery vlan tcp udp host:IP port:N, or a raw BPF filter "
            "(dumpcap/tcpdump). Uses dumpcap/tshark, tcpdump, Windows pktmon or a Linux raw socket - usually needs "
            "elevation. The summary shows protocols, top talkers/ports, DNS names, DHCP, ARP conflicts, resets, "
            "VLAN tags and any LLDP/CDP. --read summarises an existing file."),
        "examples": [
            ("nethelper capture -f dns -d 30", "30 s of DNS"),
            ("nethelper capture -f host:10.0.0.5 -c 500 -o host.pcapng", "500 packets to/from a host, kept for Wireshark"),
            ('nethelper capture --bpf "tcp port 445 and host 10.0.0.9"', "raw BPF (dumpcap/tcpdump only)"),
            ("nethelper capture -f dhcp -d 120", "watch DHCP for two minutes"),
            ("nethelper capture --read old.pcap", "summarise an existing capture"),
        ],
    },
    "monitor": {
        "summary": "Continuous monitoring of gateway, internet, DNS and extra hosts with an outage log",
        "description": (
            "Prints one line per round; state changes (down/up) are highlighted and logged. Ctrl+C or --duration "
            "ends with per-target loss, latency and every outage. -i monitors through specific adapters."),
        "examples": [
            ("nethelper monitor", "every 5 s until Ctrl+C"),
            ("nethelper monitor fs01 rdgw -n 10 --csv drops.csv", "extra hosts, every 10 s, CSV log"),
            ("nethelper monitor --duration 3600", "one hour then summarise"),
            ('nethelper monitor -i "Ethernet,Wi-Fi"', "compare both adapters side by side"),
        ],
    },
    "baseline": {
        "summary": "Save a known-good state, or compare the current state with one",
        "description": "Diffs status changes, key facts (gateway/MAC, DNS, public IP, switchport, VLAN, link, Wi-Fi) and latency.",
        "examples": [
            ("nethelper baseline save office", "save a quick-run baseline named 'office'"),
            ("nethelper baseline save office --full", "full-run baseline"),
            ("nethelper baseline diff office", "what changed?"),
            ("nethelper baseline list", "saved baselines"),
        ],
    },
    "report": {
        "summary": "Convert a saved JSON report to HTML/Markdown (optionally redacted)",
        "description": "Useful to redact a report after the fact before sending it to a vendor.",
        "examples": [
            ("nethelper report site.json -o site.html", "JSON -> HTML"),
            ("nethelper report site.json -o vendor.html --redact", "redacted copy to share"),
        ],
    },
    "fix": {
        "summary": "Opt-in repairs: flush-dns, renew-dhcp, restart-adapter, reset-winsock, reset-tcpip",
        "description": (
            "Shows the exact commands, warns about disconnects (especially over SSH/RDP) and waits for you to type "
            "'yes'. Most need elevation."),
        "examples": [
            ("nethelper fix", "list actions"),
            ("nethelper fix flush-dns", "clear the DNS cache"),
            ('nethelper fix renew-dhcp -i "Wi-Fi"', "new DHCP lease for one adapter"),
        ],
    },
    "config": {
        "summary": "View or change NetHelper's settings (.env file)",
        "description": (
            "show - every setting with its value and where it came from (default/.env/environment).\n"
            "set KEY VALUE / unset KEY - change one setting (validated; previous file kept as .env.bak).\n"
            "edit - interactive settings menu.  init - guided setup of every setting (asks before overwriting).\n"
            "path - where the file is.  validate - check the file for problems."),
        "examples": [
            ("nethelper config show", "all settings"),
            ("nethelper config set NETHELPER_TIMEOUT 5", "change the probe timeout"),
            ("nethelper config set NETHELPER_INTERFACES all", "always test every adapter"),
            ("nethelper config set NETHELPER_LOG_KEEP 100", "keep the last 100 run logs"),
            ("nethelper config edit", "interactive editor"),
        ],
    },
    "logs": {
        "summary": "Browse the per-run logs (last 40 runs kept by default)",
        "description": (
            "Every run writes a detailed log (settings, every check with details, every external command and its "
            "output, errors with tracebacks). list - recent runs with exit codes; show [N] - print run N "
            "(1 = latest); path - log folder; clear - delete all logs (asks first)."),
        "examples": [
            ("nethelper logs", "list recent runs"),
            ("nethelper logs show", "print the latest run's log"),
            ("nethelper logs show 3", "print the third most recent"),
            ("nethelper logs path", "where logs are stored"),
        ],
    },
    "upload": {
        "summary": "Copy files (reports, captures, logs...) to a folder, share, SFTP, WebDAV, HTTPS, FTPS, S3, email or syslog",
        "description": (
            "Sends the given files to each --to destination (or the configured NETHELPER_OUTPUT_DESTINATIONS), into "
            "the per-machine sub-folder (default {host}/{date}). Never overwrites at a local destination. "
            "See 'nethelper help destinations' for every destination type and its credentials."),
        "examples": [
            ("nethelper upload site.html --to Z:\\Reports", "to a mapped drive"),
            ("nethelper upload capture.pcapng --to \\\\fs01\\it\\captures", "to a Windows share"),
            ("nethelper upload site.html --to sftp://tech@backup01/srv/nethelper", "over SSH (key auth)"),
            ("nethelper upload site.html --to webdavs://jason@cloud.example.com/remote.php/dav/files/jason/NetHelper",
             "to Nextcloud (app password in NETHELPER_DEST_PASSWORD)"),
            ("nethelper upload site.html capture.pcapng --to s3://acme-netlogs/nethelper", "to an S3/MinIO/Backblaze bucket"),
            ("nethelper upload site.html --to mailto:helpdesk@example.com", "email it (SMTP server in NETHELPER_SMTP_SERVER)"),
            ("nethelper upload results.json --to syslog+tls://siem.example.com", "send each check result to a SIEM"),
            ("nethelper upload a.json b.html --subdir acme-hq", "to the configured destinations, custom sub-folder"),
        ],
    },
    "dest": {
        "summary": "Manage output destinations: list, test, add, remove",
        "description": (
            "Configured destinations receive every run's outputs automatically (types chosen by "
            "NETHELPER_OUTPUT_INCLUDE: reports, captures, logs, results). 'test' writes a small, clearly named probe "
            "file to prove access. Any command can also send to an extra destination with --upload DEST, or skip "
            "the configured ones with --no-upload."),
        "examples": [
            ("nethelper dest", "show configured destinations"),
            ("nethelper dest add D:\\NetHelper", "always copy outputs to an external drive"),
            ("nethelper dest add sftp://tech@backup01/srv/nethelper", "and to an SSH server"),
            ("nethelper dest add mailto:helpdesk@example.com", "email every run's report and results"),
            ("nethelper dest add syslog+tls://siem.example.com", "stream results and warnings to a syslog server/SIEM"),
            ("nethelper dest test", "test every configured destination"),
            ("nethelper full --upload \\\\fs01\\it\\reports --report site.html", "one-off extra destination for one run"),
        ],
    },
    "caps": {
        "summary": "What works at the current privilege level (elevation, tools, capture methods, per-check status)",
        "description": "Run this first on a new machine to see which checks will be limited and why.",
        "examples": [("nethelper caps", "privilege and capability report"), ("nethelper caps --json", "as JSON")],
    },
    "list": {
        "summary": "Every check with its section, mode, privilege needs and description",
        "description": "Check ids can be used with baselines and appear in reports and logs.",
        "examples": [("nethelper list", "all checks"), ("nethelper list --json", "as JSON")],
    },
    "oui": {
        "summary": "Manage the MAC vendor database used to name devices",
        "description": "update downloads the IEEE registry (~4 MB); status shows how many vendors are known.",
        "examples": [("nethelper oui update", "download the vendor list"), ("nethelper oui status", "vendor count")],
    },
    "help": {
        "summary": "This help: overview, a command's page, or a topic page",
        "description": "Pages are also reachable from the menu's Help section and with '<command> -h'.",
        "examples": [("nethelper help", "overview"), ("nethelper help throughput", "a command page"),
                     ("nethelper help elevation", "a topic page")],
    },
}

TOPICS: dict[str, tuple[str, str]] = {
    "elevation": ("Standard user vs. elevated", (
        "NetHelper works without admin rights. A few features need Administrator (Windows) or root (sudo):\n"
        "  - switchport/VLAN discovery and tagged-frame checks (packet capture)\n"
        "  - the capture command\n"
        "  - the rogue-DHCP probe on Linux (binding UDP 68)\n"
        "  - process names for other users' sockets, firewall details (Linux/macOS)\n"
        "  - pinning per-interface tests to an adapter on Linux (SO_BINDTODEVICE)\n"
        "Limited checks show '[SKIP] requires Administrator' or '(limited: not elevated)'; --hide-limited (or "
        "NETHELPER_HIDE_LIMITED=true) hides them. Elevate: Windows - right-click Terminal/PowerShell > Run as "
        "administrator; Linux/macOS - prefix with sudo. 'nethelper caps' shows the current state.")),
    "interfaces": ("Multiple interfaces", (
        "Most commands accept -i/--interface: one name, a comma list, repeated -i, or 'all'.\n"
        "  nethelper interfaces            list adapters\n"
        "  nethelper interfaces --test     test each adapter's own path (gateway, internet, DNS)\n"
        "  nethelper quick -i all          include per-adapter tests in a quick run\n"
        "  nethelper ping 1.1.1.1 -i Wi-Fi send out of one adapter\n"
        "  nethelper throughput gateway -i Ethernet   throughput over the cable only\n"
        "Names must match 'nethelper interfaces' (quote names with spaces). Set a default with "
        "NETHELPER_INTERFACES. Tests bind to the adapter's IP; on Linux, root additionally pins the device.")),
    "wifi": ("Wi-Fi", (
        "nethelper wifi [status|scan|channels|monitor|profiles] - see 'nethelper help wifi'.\n"
        "Signal guide: -30 to -60 dBm excellent; -60 to -67 good (VoIP OK); -67 to -70 fair; below -70 poor; "
        "below -80 unusable. 2.4 GHz: use only channels 1, 6, 11. 5 GHz: 36-48 and 149-165 avoid radar (DFS) "
        "interruptions. A full run includes a Wi-Fi environment scan (congestion, evil twins).")),
    "throughput": ("Bandwidth & throughput", (
        "Internet speed:    nethelper speed            (HTTPS test + bufferbloat grade)\n"
        "LAN throughput:    nethelper serve            on machine A, then\n"
        "                   nethelper throughput A     on machine B\n"
        "To the gateway:    nethelper throughput gateway\n"
        "Fallbacks when the target runs no NetHelper server: iperf3 (port 5201) if iperf3 is installed here - "
        "e.g. the iperf package on pfSense/OPNsense - else an ICMP load test (approximate lower bound; routers "
        "rate-limit ICMP). UDP mode (--udp --rate N) reports loss and jitter for voice/video planning. Protect "
        "a server with --key / NETHELPER_THROUGHPUT_KEY. Defaults (port, seconds, streams, target) are settings.")),
    "capture": ("Packet capture", (
        "Backends in order: dumpcap/tshark (Wireshark), tcpdump, pktmon (Windows, admin), Linux raw socket "
        "(root). NetHelper never disturbs someone else's pktmon session. Captures go to the captures folder "
        "(NETHELPER_CAPTURE_DIR) unless -o is given. Captures can contain other people's traffic - capture only "
        "where you're authorised and treat files as sensitive.")),
    "switchport": ("Switchport & VLAN discovery", (
        "Needs a cable (not Wi-Fi) and capture rights or lldpd. No LLDP/CDP heard usually means: unmanaged switch, "
        "LLDP/CDP disabled, an IP phone/hub in between, or NIC firmware swallowing LLDP (Intel: disable the "
        "'FW LLDP agent'). CDP repeats every 60 s - use --wait 65. Validation compares against [expected] and "
        "[vlans] in a site profile.")),
    "profiles": ("Site profiles", (
        "A TOML file describing one site: targets (servers/ports/URLs), services (SMTP/LDAP...), expected VLAN, "
        "subnet, gateway, DNS/DHCP servers, switch/port, VLAN plan, thresholds. See profiles/example.toml. Use "
        "--profile FILE, or set NETHELPER_PROFILE to make one the default. A profile overrides the matching .env "
        "settings for that site.")),
    "settings": ("Settings (.env)", (
        "App-wide defaults live in a .env file (nethelper config path shows where): timeout, default interfaces, "
        "colour, log level/retention/folder, report and capture folders, speed-test URLs/sizes, throughput "
        "target/port/seconds/streams/key, iperf port. Edit with 'nethelper config edit', the menu's Settings, or "
        "any text editor. Precedence: command-line flag > site profile > environment variable > .env > built-in. "
        "Every key is documented in .env.example.")),
    "logs": ("Logs", (
        "Each run writes logs/run-<date>-<time>-...-<command>.log with full detail (DEBUG by default). Only the "
        "newest 40 are kept (NETHELPER_LOG_KEEP); each file is capped at 10 MB. Secrets are masked. Browse with "
        "'nethelper logs' or the Logs menu. When something errors, the message tells you which log to look at.")),
    "reports": ("Reports, bundles & redaction", (
        "--report FILE.html|.md|.json saves a report; --bundle FILE.zip adds raw command outputs and captures. "
        "--redact hides public IPs, MACs, SSIDs, host and user names (private IPs kept); --redact-all hides "
        "private IPs too. Redacted bundles omit packet captures.")),
    "destinations": ("Output destinations (local & remote)", (
        "Outputs (reports, bundles, captures, results JSON, run logs) can be copied anywhere:\n"
        "  D:\\NetHelper  Z:\\Reports  /mnt/usb  ~/out    local folder, external or mapped drive\n"
        "  \\\\server\\share\\path                        Windows share (your logon credentials)\n"
        "  smb://server/share/path                     Windows: native; Linux/macOS: smbclient\n"
        "                                              (user in URL, password = NETHELPER_DEST_PASSWORD)\n"
        "  sftp://user@host/abs/path  scp://user@host:2222/~/rel   OpenSSH key auth only (ssh-agent or\n"
        "                                              NETHELPER_SSH_KEY); the host key must be known\n"
        "                                              (or NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS=true)\n"
        "  webdavs://user@host/path                    WebDAV over HTTPS, e.g. Nextcloud:\n"
        "      webdavs://jason@cloud.example.com/remote.php/dav/files/jason/NetHelper  (use an app password)\n"
        "  https://host/endpoint                       HTTP PUT (or POST) with NETHELPER_DEST_TOKEN bearer token\n"
        "  ftps://user@host/path                       FTP over TLS\n"
        "  s3://bucket/prefix                          S3-compatible storage (AWS, MinIO, Backblaze B2, Wasabi):\n"
        "                                              NETHELPER_S3_ENDPOINT (empty = AWS), _REGION, _ACCESS_KEY,\n"
        "                                              _SECRET_KEY (or the AWS_* environment variables)\n"
        "  mailto:helpdesk@example.com                 one email per run with the files attached, via\n"
        "                                              NETHELPER_SMTP_SERVER (STARTTLS default); one address per\n"
        "                                              entry; run logs are not emailed automatically\n"
        "  syslog+tls://siem:6514  syslog://siem  syslog+tcp://siem:514\n"
        "                                              sends events, not files: one per check result and diagnosis,\n"
        "                                              each WARNING/ERROR log line, and a 'file produced' record\n"
        "Passwords never go in URLs. Unencrypted http/webdav/ftp/syslog/syslog+tcp, an http:// S3 endpoint and\n"
        "SMTP security 'none' need NETHELPER_DEST_ALLOW_INSECURE=true. Servers using an internal CA: set\n"
        "NETHELPER_DEST_CA_FILE to that CA's certificate (verification is never switched off).\n"
        "Set defaults with 'nethelper dest add ...'; choose what's copied with NETHELPER_OUTPUT_INCLUDE; files go "
        "into NETHELPER_OUTPUT_SUBDIR (default {host}/{date}). A failed upload is reported but never fails the run.")),
    "exitcodes": ("Exit codes", (
        "0 all good | 1 warnings | 2 failures found | 3 usage/configuration error | 4 unexpected internal error "
        "(see the log) | 130 interrupted (Ctrl+C).")),
    "privacy": ("Privacy", (
        "Normal checks talk to your network, your DNS servers and well-known public endpoints. Third-party "
        "lookups (public IP, internet speed test) can be disabled with --offline or NETHELPER_EXTERNAL_LOOKUPS="
        "false. Nothing is uploaded unless you configure output destinations (see 'nethelper help destinations'); "
        "otherwise reports, logs and captures stay on disk until you share them.")),
}


def overview() -> str:
    """The 'nethelper help' page: grouped command list + topics."""
    groups = [
        ("Start here", ["quick", "full", "check", "caps"]),
        ("Interfaces & Wi-Fi", ["interfaces", "wifi", "info"]),
        ("Connectivity tools", ["ping", "trace", "dns", "port", "http", "tls", "mtu"]),
        ("Speed & throughput", ["speed", "throughput", "serve"]),
        ("LAN & switch", ["lan", "dhcp", "switchport", "vlan"]),
        ("Capture & monitoring", ["capture", "monitor"]),
        ("Baselines, reports, repairs", ["baseline", "report", "fix"]),
        ("Outputs & destinations", ["upload", "dest"]),
        ("NetHelper itself", ["config", "logs", "list", "oui", "help"]),
    ]
    lines = ["NetHelper - network troubleshooting. Run 'nethelper' alone for the interactive menu.", "",
             "Usage: nethelper <command> [options]      (common options go AFTER the command)", ""]
    for title, cmds in groups:
        lines.append(f"{title}:")
        for c in cmds:
            lines.append(f"  {c:<12} {COMMANDS[c]['summary']}")
        lines.append("")
    lines.append("Topics:  " + ", ".join(TOPICS))
    lines += ["", "More:  nethelper help <command|topic>     e.g. nethelper help throughput, nethelper help elevation"]
    return "\n".join(lines)


def command_page(name: str) -> str:
    """Full help page for one command."""
    c = COMMANDS[name]
    lines = [f"nethelper {name} - {c['summary']}", "", *c["description"].split("\n"), "", "Examples:"]
    width = max(len(cmd) for cmd, _ in c["examples"])
    for cmd, what in c["examples"]:
        lines.append(f"  {cmd:<{width}}   # {what}")
    lines += ["", f"All options: nethelper {name} -h"]
    return "\n".join(lines)


def topic_page(name: str) -> str:
    """Full help page for one topic."""
    title, body = TOPICS[name]
    return f"{title}\n{'=' * len(title)}\n\n{body}"


def epilog(name: str) -> str:
    """Examples block appended to argparse's '<command> -h' output."""
    c = COMMANDS.get(name)
    if not c:
        return ""
    width = max(len(cmd) for cmd, _ in c["examples"])
    return "examples:\n" + "\n".join(f"  {cmd:<{width}}   # {what}" for cmd, what in c["examples"])


def lookup(word: str) -> str | None:
    """Help page for a command or topic name (case-insensitive), or None."""
    w = word.lower().strip()
    if w in COMMANDS:
        return command_page(w)
    if w in TOPICS:
        return topic_page(w)
    return None
