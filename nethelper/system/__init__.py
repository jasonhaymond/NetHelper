"""
Local system information ("facts"): interfaces, IP addresses, routes, DNS
settings, DHCP leases, proxy, firewall, Wi-Fi, ARP neighbours, connections,
hosts-file entries and local VLAN configuration.

  model.py    OS-independent data classes everything else uses
  windows.py  collector for Windows (one PowerShell call returning JSON + winreg)
  linux.py    collector for Linux (ip -j, /proc, /sys, resolv.conf, nmcli, ss...)
  macos.py    collector for macOS (ifconfig, netstat, scutil, ipconfig...)
  facts.py    picks the right collector and adds cross-platform extras
"""
