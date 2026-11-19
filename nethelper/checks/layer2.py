"""
"Switchport & VLAN" checks: Layer 2 - the physical link and the switch port
this machine is plugged into.

  l2.link            negotiated speed/duplex of wired adapters (a gigabit port
                     linking at 100 Mb/s usually means a damaged cable)
  l2.local_vlan      802.1Q VLAN tagging configured on this machine itself
  l2.switchport      LLDP/CDP from the switch: switch name, port, access VLAN,
                     voice VLAN, PoE, management IP, speed/duplex
  l2.vlan_validation compares what the switch says / what IP we got against the
                     site profile: right VLAN? right subnet? duplex mismatch?
  l2.tagged_frames   are 802.1Q-tagged frames reaching this port (trunk/misconfig)?
  l2.intervlan       can we reach each VLAN's gateway/hosts (inter-VLAN routing/ACLs)?

Privileges: hearing LLDP/CDP and tagged frames requires packet capture, which
needs Administrator/root (or Wireshark's capture driver/group permissions).
The non-elevated alternative is lldpctl (from the lldpd package) when its
daemon is running. Without either, these checks say exactly what's needed.
"""

from __future__ import annotations

import ipaddress
import json

from pathlib import Path

from nethelper.checks._util import first_ipv4, selected_interfaces, wired_interface, wired_interfaces
from nethelper.core import cmd
from nethelper.core.context import Context
from nethelper.core.privileges import elevation_hint
from nethelper.core.registry import Admin, check
from nethelper.core.result import Outcome, Status
from nethelper.core.runner import PRIVILEGE_NOTE
from nethelper.net import capture, icmp, l2proto, pcap, tcp


def parse_lldpctl_json(text: str, iface_name: str | None = None) -> list[dict]:
    """
    Convert `lldpctl -f json` output into the same neighbour dict shape that
    l2proto produces. lldpd's JSON varies between versions (objects vs lists),
    so every level is handled defensively.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    ifaces = data.get("lldp", {}).get("interface", {})
    items = []
    if isinstance(ifaces, dict):
        items = list(ifaces.items())
    elif isinstance(ifaces, list):
        for entry in ifaces:
            if isinstance(entry, dict):
                items.extend(entry.items())
    out = []
    for name, body in items:
        if iface_name and name != iface_name:
            continue
        info: dict = {"protocol": str(body.get("via", "LLDP")), "local_interface": name,
                      "mgmt_addresses": [], "vlan_names": {}}
        chassis = body.get("chassis", {})
        if isinstance(chassis, dict) and chassis:
            sysname, cdata = next(iter(chassis.items()))
            if isinstance(cdata, dict) and "id" not in chassis:
                info["system_name"] = sysname
            else:
                cdata = chassis
            info["chassis_id"] = (cdata.get("id") or {}).get("value") if isinstance(cdata.get("id"), dict) else cdata.get("id")
            info["system_description"] = cdata.get("descr")
            mgmt = cdata.get("mgmt-ip")
            info["mgmt_addresses"] = mgmt if isinstance(mgmt, list) else ([mgmt] if mgmt else [])
        port = body.get("port", {})
        if isinstance(port, dict):
            pid = port.get("id")
            info["port_id"] = pid.get("value") if isinstance(pid, dict) else pid
            info["port_description"] = port.get("descr")
        vlans = body.get("vlan")
        for v in (vlans if isinstance(vlans, list) else [vlans] if vlans else []):
            if isinstance(v, dict):
                vid = int(v.get("vlan-id", 0) or 0)
                if v.get("pvid") in (True, "yes") and vid:
                    info["native_vlan"] = vid
                if vid and v.get("value"):
                    info["vlan_names"][vid] = v["value"]
        out.append(info)
    return out


def _discover_one(ctx: Context, iface) -> dict:
    """LLDP/CDP discovery on ONE wired interface (lldpctl first, else packet capture)."""
    result: dict = {"interface": iface.name, "method": None, "neighbors": [], "error": None,
                    "limited": False, "waited": 0, "notes": []}
    # Option 1: lldpd daemon (works without elevation when lldpctl is permitted).
    if ctx.caps.has("lldpctl"):
        res = cmd.run(["lldpctl", "-f", "json"], timeout=15)
        neigh = parse_lldpctl_json(res.stdout, iface.name if ctx.caps.os != "windows" else None)
        if neigh:
            result.update(method="lldpctl", neighbors=neigh)
            return result
    # Option 2: listen for LLDP/CDP frames.
    if not ctx.caps.can_capture():
        result["limited"] = True
        result["error"] = f"listening for LLDP/CDP needs packet capture - {elevation_hint()}"
        return result
    wait = ctx.switchport_wait()
    spec = capture.CaptureSpec(interface=iface.name, duration=wait, count=1, preset="l2discovery",
                               outdir=Path(ctx.setting("NETHELPER_CAPTURE_DIR")) if ctx.setting("NETHELPER_CAPTURE_DIR") else None)
    cap = capture.run_capture(spec, ctx.caps, stop_when=lambda p: pcap.decode(p).l3 in ("lldp", "cdp"))
    result["waited"] = wait
    result["method"] = cap.backend
    result["notes"] = cap.notes
    if not cap.ok:
        result["error"] = cap.error
        result["limited"] = not ctx.caps.elevated
        return result
    for n in l2proto.find_neighbors(cap.packets):
        n.setdefault("local_interface", iface.name)
        result["neighbors"].append(n)
    result["capture_file"] = str(cap.file) if cap.file else None
    return result


def discover_switch(ctx: Context) -> dict:
    """
    Learn about the attached switch port(s) once per run (cached via ctx.memo).
    With several wired interfaces selected (-i eth0,eth1 or -i all) each is
    listened on in turn. Returns {"interface", "interfaces", "method",
    "neighbors" (each tagged with local_interface), "error", "limited", "waited"}.
    """
    def run() -> dict:
        ifaces = wired_interfaces(ctx)
        if not ifaces:
            return {"interface": None, "interfaces": [], "method": None, "neighbors": [], "limited": False,
                    "waited": 0, "notes": [],
                    "error": "no active wired (Ethernet) interface - switch discovery needs a cable connection"}
        per = [_discover_one(ctx, i) for i in ifaces]
        merged = {
            "interface": ", ".join(i.name for i in ifaces),
            "interfaces": per,
            "method": next((p["method"] for p in per if p["method"]), None),
            "neighbors": [n for p in per for n in p["neighbors"]],
            "error": "; ".join(f"{p['interface']}: {p['error']}" for p in per if p["error"]) or None,
            "limited": all(p["limited"] for p in per),
            "waited": max(p["waited"] for p in per),
            "notes": [n for p in per for n in p["notes"]],
            "capture_file": next((p.get("capture_file") for p in per if p.get("capture_file")), None),
        }
        if len(per) == 1 and per[0]["error"]:
            merged["error"] = per[0]["error"]
        return merged

    return ctx.memo("l2discovery", run)


@check("l2.link", "Link speed & duplex", "layer2", modes=("quick", "full"))
def link(ctx: Context) -> Outcome:
    """Negotiated speed and duplex of wired adapters; flags half duplex and suspiciously slow links."""
    chosen = selected_interfaces(ctx)
    wired = [i for i in (chosen if chosen is not None else ctx.facts.interfaces)
             if i.up and i.kind == "ethernet" and i.vlan_parent is None]
    if not wired:
        return Outcome(Status.SKIP, "no active wired interface")
    rows, warns, advice = [], [], []
    min_speed = ctx.profile.expected.min_link_mbps
    for i in wired:
        rows.append({"name": i.name, "speed_mbps": i.speed_mbps, "duplex": i.duplex, "mtu": i.mtu})
        if i.duplex == "half":
            warns.append(f"{i.name} is half duplex")
            advice.append("Half duplex on a modern switch port almost always means a duplex mismatch (one side "
                          "hard-set, the other auto). Set both sides to auto-negotiate. Symptoms: slow transfers, "
                          "late collisions, CRC errors.")
        if i.speed_mbps and min_speed and i.speed_mbps < min_speed:
            warns.append(f"{i.name} linked at {i.speed_mbps:g} Mb/s (expected >= {min_speed})")
        elif i.speed_mbps and i.speed_mbps <= 100 and not min_speed:
            warns.append(f"{i.name} linked at only {i.speed_mbps:g} Mb/s")
        if i.speed_mbps and i.speed_mbps <= 100:
            advice.append("Gigabit needs all 4 wire pairs; a link stuck at 100 Mb/s typically means a damaged "
                          "cable/keystone/patch lead, or an old switch port. Try another cable/port.")
    summary = ", ".join(f"{r['name']} {r['speed_mbps']:g} Mb/s {r['duplex'] or ''}".strip()
                        if r["speed_mbps"] else f"{r['name']} speed unknown" for r in rows)
    return Outcome(Status.WARN if warns else Status.PASS, "; ".join(warns) or summary, {"links": rows},
                   list(dict.fromkeys(advice)))


@check("l2.local_vlan", "Local VLAN configuration", "layer2", modes=("full",))
def local_vlan(ctx: Context) -> Outcome:
    """VLAN tags configured on this machine (adapter VLAN ID property, eth0.20-style sub-interfaces, macOS vlanN)."""
    tagged = [i for i in ctx.facts.interfaces if i.vlan_id]
    rows = [{"name": i.name, "vlan_id": i.vlan_id, "parent": i.vlan_parent, "up": i.up,
             "ipv4": [f"{a.ip}/{a.prefix}" for a in i.ipv4]} for i in tagged]
    if not rows:
        return Outcome(Status.INFO, "no VLAN tagging on this host (traffic is untagged; the switch port decides the VLAN)",
                       {"tagged_interfaces": []})
    return Outcome(Status.INFO, "tagged: " + ", ".join(f"{r['name']} VLAN {r['vlan_id']}" for r in rows),
                   {"tagged_interfaces": rows},
                   ["Host-side tagging only works if the switch port is a trunk carrying that VLAN; on an access "
                    "port tagged frames are dropped."])


def _describe(n: dict) -> str:
    """One-line description of a switch neighbour."""
    parts = [n.get("system_name") or n.get("chassis_id") or "unknown switch"]
    port, desc = n.get("port_id"), n.get("port_description")
    if port or desc:
        parts.append(f"port {port or ''}" + (f" ({desc})" if desc and desc != port else ""))
    vlan = n.get("native_vlan")
    if vlan:
        name = n.get("vlan_names", {}).get(vlan)
        parts.append(f"VLAN {vlan}" + (f" '{name}'" if name else ""))
    if n.get("voice_vlan"):
        parts.append(f"voice VLAN {n['voice_vlan']}")
    if n.get("mgmt_addresses"):
        parts.append(f"mgmt {n['mgmt_addresses'][0]}")
    return ", ".join(parts)


@check("l2.switchport", "Switchport (LLDP/CDP)", "layer2", modes=("full",), admin=Admin.PARTIAL, timeout=200)
def switchport(ctx: Context) -> Outcome:
    """Listens for LLDP/CDP from the attached switch: which switch, which port, access & voice VLAN, PoE."""
    info = discover_switch(ctx)
    details = dict(info)
    if info["error"] and not info["neighbors"]:
        if info["limited"]:
            details[PRIVILEGE_NOTE] = info["error"]
            return Outcome(Status.SKIP, info["error"], details)
        return Outcome(Status.SKIP if "no active wired" in info["error"] else Status.WARN, info["error"], details)
    if not info["neighbors"]:
        return Outcome(Status.WARN, f"no LLDP/CDP received on {info['interface']} in {info['waited']} s", details,
                       ["No discovery frames: the switch is unmanaged or has LLDP/CDP disabled, an IP phone/hub "
                        "sits in between, or the NIC firmware consumes LLDP (some Intel NICs - disable the "
                        "'FW LLDP agent'). CDP is sent every 60 s: retry with '--wait 65'."])
    status, advice = Status.PASS, []
    exp = ctx.profile.expected
    mismatch, parts = [], []
    multi = len({n.get("local_interface") for n in info["neighbors"]}) > 1
    for n in info["neighbors"]:
        # Expected switch/port only apply to the first (primary) wired interface.
        if n is info["neighbors"][0]:
            if exp.switch_name and exp.switch_name.lower() not in (n.get("system_name") or "").lower():
                mismatch.append(f"switch is '{n.get('system_name')}', expected '{exp.switch_name}'")
            ports = {str(n.get("port_id", "")).lower(), str(n.get("port_description", "")).lower()}
            if exp.switch_port and exp.switch_port.lower() not in ports:
                mismatch.append(f"port is '{n.get('port_id')}', expected '{exp.switch_port}'")
        text = f"{n['protocol']}: {_describe(n)}"
        if n.get("poe"):
            poe = n["poe"]
            text += f", PoE class {poe.get('class')}" + (f" {poe['allocated_w']} W" if poe.get("allocated_w") else "")
        parts.append(f"{n.get('local_interface')} -> {text}" if multi else text)
    if mismatch:
        status = Status.FAIL
        advice.append("This jack is patched to a different switch/port than documented: update the patching "
                      "records or re-patch.")
    silent = [p["interface"] for p in info.get("interfaces", []) if not p["neighbors"]]
    if silent and multi is False and len(info.get("interfaces", [])) > 1:
        parts.append(f"nothing heard on {', '.join(silent)}")
    summary = " | ".join(parts) + (" - " + "; ".join(mismatch) if mismatch else "")
    return Outcome(status, summary, details, advice)


@check("l2.vlan_validation", "VLAN validation", "layer2", modes=("full",), admin=Admin.PARTIAL, timeout=200)
def vlan_validation(ctx: Context) -> Outcome:
    """Compares the switch-reported VLAN, this host's subnet and gateway, and duplex against the site profile."""
    exp = ctx.profile.expected
    snap = ctx.facts
    iface = wired_interface(ctx) or snap.primary_interface()
    ip = first_ipv4(iface)
    addr = next((a for a in (iface.ipv4 if iface else []) if a.ip == ip), None)
    info = discover_switch(ctx) if (iface and iface.kind == "ethernet") else {"neighbors": [], "limited": False}
    neighbor = info["neighbors"][0] if info.get("neighbors") else {}
    observed_vlan = neighbor.get("native_vlan")
    checks: list[dict] = []

    def add(name: str, ok: bool | None, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    if exp.vlan is not None:
        if observed_vlan is None:
            add("access VLAN", None, f"expected VLAN {exp.vlan}; switch didn't report a VLAN")
        else:
            add("access VLAN", observed_vlan == exp.vlan, f"switch says VLAN {observed_vlan}, expected {exp.vlan}")
    if exp.voice_vlan is not None and neighbor:
        add("voice VLAN", neighbor.get("voice_vlan") == exp.voice_vlan,
            f"switch advertises voice VLAN {neighbor.get('voice_vlan')}, expected {exp.voice_vlan}")
    # Subnet: from the explicit expectation, or from the profile's definition of the observed VLAN.
    spec = ctx.profile.vlans.get(observed_vlan) if observed_vlan else None
    want_subnet = exp.subnet or (spec.subnet if spec else None)
    if want_subnet and addr:
        inside = ipaddress.ip_address(addr.ip) in ipaddress.ip_network(want_subnet)
        add("subnet", inside, f"host IP {addr.ip}/{addr.prefix} vs expected {want_subnet}"
            + (f" (VLAN {observed_vlan})" if spec else ""))
    if spec and spec.gateway:
        gw = snap.default_gateway()
        add("gateway", gw == spec.gateway, f"gateway {gw}, VLAN {observed_vlan} expects {spec.gateway}")
    if not exp.subnet and not spec and addr and ctx.profile.vlans:
        # Which configured VLAN does our IP belong to? Useful even without switch data.
        match = [v for v in ctx.profile.vlans.values() if v.subnet and ipaddress.ip_address(addr.ip) in ipaddress.ip_network(v.subnet)]
        add("subnet->VLAN", bool(match), f"IP {addr.ip} belongs to " + (
            f"VLAN {match[0].vlan_id} '{match[0].name}'" if match else "no VLAN defined in the profile"))
    if neighbor.get("duplex") and iface and iface.duplex and neighbor["duplex"] != iface.duplex:
        add("duplex", False, f"switch reports {neighbor['duplex']} duplex, this host {iface.duplex}")
    if neighbor.get("link_type") and iface and iface.speed_mbps:
        speed_map = {"10BASE-T": 10, "100BASE-TX": 100, "1000BASE-T": 1000}
        sw = speed_map.get(neighbor["link_type"])
        if sw and abs(sw - iface.speed_mbps) > 1:
            add("speed", False, f"switch reports {neighbor['link_type']}, host linked at {iface.speed_mbps:g} Mb/s")

    details = {"checks": checks, "observed_vlan": observed_vlan, "host_ip": ip}
    if not checks:
        if info.get("limited"):
            details[PRIVILEGE_NOTE] = "switch VLAN unknown without packet capture"
        return Outcome(Status.SKIP, "nothing to validate (set [expected] vlan/subnet or [vlans] in a profile; "
                       "switch data needs a wired link + capture rights)", details)
    bad = [c for c in checks if c["ok"] is False]
    unknown = [c for c in checks if c["ok"] is None]
    if bad:
        advice = []
        if any(c["check"] in ("access VLAN", "subnet", "gateway") for c in bad):
            advice.append("Wrong VLAN or subnet: the switch port is assigned to the wrong VLAN, the jack is "
                          "patched to the wrong port, or the DHCP scope/relay for this VLAN is wrong.")
        if any(c["check"] in ("duplex", "speed") for c in bad):
            advice.append("Speed/duplex disagreement between host and switch: set both to auto-negotiate and "
                          "check the cable.")
        return Outcome(Status.FAIL, "; ".join(c["detail"] for c in bad), details, advice)
    if unknown:
        return Outcome(Status.WARN, "; ".join(c["detail"] for c in unknown), details)
    return Outcome(Status.PASS, "; ".join(c["detail"] for c in checks), details)


@check("l2.tagged_frames", "Tagged frames on port", "layer2", modes=("full",), admin=Admin.PARTIAL, timeout=60)
def tagged_frames(ctx: Context) -> Outcome:
    """Listens briefly for 802.1Q-tagged traffic; tags arriving on an access port suggest a trunk or misconfiguration."""
    iface = wired_interface(ctx)
    if not iface:
        return Outcome(Status.SKIP, "no active wired interface")
    if not ctx.caps.can_capture():
        return Outcome(Status.SKIP, f"needs packet capture - {elevation_hint()}",
                       {PRIVILEGE_NOTE: "tagged-frame probe needs packet capture"})
    cap = capture.run_capture(capture.CaptureSpec(interface=iface.name, duration=10, preset="vlan"), ctx.caps)
    if not cap.ok:
        return Outcome(Status.SKIP, cap.error or "capture failed",
                       {PRIVILEGE_NOTE: cap.error} if not ctx.caps.elevated else {"error": cap.error})
    seen: dict[int, int] = {}
    for p in cap.packets:
        for v in pcap.decode(p).vlans:
            seen[v] = seen.get(v, 0) + 1
    details = {"interface": iface.name, "backend": cap.backend, "vlans_seen": seen, "notes": cap.notes}
    if not seen:
        return Outcome(Status.PASS, "no tagged frames seen in 10 s (normal for an access port)", details,
                       cap.notes)
    voice = ctx.profile.expected.voice_vlan
    others = {v: c for v, c in seen.items() if v != voice}
    if others:
        return Outcome(Status.WARN, "tagged traffic for VLAN(s) " + ", ".join(map(str, sorted(others))), details,
                       ["Tagged frames reach this host: the port is a trunk (or has extra tagged VLANs). Desktop "
                        "ports should normally be access ports (plus a voice VLAN at most) - check the switch config."])
    return Outcome(Status.PASS, f"only the voice VLAN {voice} is tagged on this port", details)


@check("l2.intervlan", "Inter-VLAN reachability", "layer2", modes=("full",), timeout=90)
def intervlan(ctx: Context) -> Outcome:
    """Pings each profile VLAN's gateway and listed hosts to test inter-VLAN routing and ACLs."""
    vlans = [v for v in ctx.profile.vlans.values() if v.gateway or v.targets]
    if not vlans:
        return Outcome(Status.SKIP, "no [vlans] with gateways/targets in the profile")
    rows, fails = [], []
    for v in vlans:
        for host in ([v.gateway] if v.gateway else []) + v.targets:
            reply = icmp.echo(host, timeout=ctx.options.timeout)
            ok = reply.status == icmp.OK
            how = f"ping {reply.rtt_ms:g} ms" if ok else reply.status
            if not ok:
                res = tcp.connect(host, 443, timeout=ctx.options.timeout)
                if res.state in ("open", "refused"):
                    ok, how = True, f"ICMP blocked; TCP answered ({res.state})"
            rows.append({"vlan": v.vlan_id, "name": v.name, "host": host, "ok": ok, "detail": how})
            if not ok:
                fails.append(f"VLAN {v.vlan_id} {host}")
    details = {"results": rows}
    if fails:
        return Outcome(Status.WARN if len(fails) < len(rows) else Status.FAIL,
                       f"unreachable: {', '.join(fails[:5])}", details,
                       ["Blocked inter-VLAN traffic may be intentional (ACLs/firewall policy). Otherwise check "
                        "the routing between VLANs (layer-3 switch/firewall interface for that VLAN)."])
    return Outcome(Status.PASS, f"all {len(rows)} VLAN host(s) reachable", details)
