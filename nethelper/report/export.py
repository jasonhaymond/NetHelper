"""
Report files: JSON (machine-readable), Markdown (tickets/wikis), HTML (a
self-contained page to email or attach), and a zip "bundle" with all three
plus the raw command outputs and any capture files, for escalation.

SECURITY: results contain text from the network that we don't control
(Wi-Fi names, server banners, LLDP strings sent by a switch, HTTP headers). In
HTML every such value is escaped with html.escape(), so a hostile SSID like
"<script>..." is displayed as text instead of running as code when the report
is opened in a browser (cross-site scripting). The HTML has no external
resources or JavaScript of its own; detail sections use <details> elements.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import zipfile
from pathlib import Path
from typing import Any

from nethelper import APP_NAME, __version__
from nethelper.core.registry import SECTIONS
from nethelper.core.result import CheckResult, Status
from nethelper.report.verdict import Finding


def build_document(results: list[CheckResult], findings: list[Finding], meta: dict[str, Any]) -> dict:
    """Assemble the complete report as one dictionary (the JSON report format)."""
    return {
        "tool": APP_NAME,
        "version": __version__,
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        **meta,
        "verdict": [f.to_dict() for f in findings],
        "results": [r.to_dict() for r in results],
    }


def to_json(doc: dict) -> str:
    """Pretty-printed JSON text. `default=str` turns sets/paths/etc. into strings."""
    return json.dumps(doc, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o))


def _md_escape(text: Any) -> str:
    """Neutralise Markdown table/formatting characters in untrusted text."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def to_markdown(doc: dict) -> str:
    """Render the report as Markdown."""
    out = [f"# {APP_NAME} report", "",
           f"- **Host:** {_md_escape(doc.get('host', ''))}  ",
           f"- **OS:** {_md_escape(doc.get('os', ''))}  ",
           f"- **Elevated:** {'yes' if doc.get('elevated') else 'no'}  ",
           f"- **Mode:** {_md_escape(doc.get('mode', ''))}  ",
           f"- **Profile:** {_md_escape(doc.get('profile', ''))}  ",
           f"- **Generated:** {doc['generated']} by {APP_NAME} {doc['version']}", "", "## Diagnosis", ""]
    for f in doc["verdict"]:
        out.append(f"- **[{f['severity'].upper()}] {_md_escape(f['title'])}** - {_md_escape(f['explanation'])}")
        for step in f["next_steps"][:3]:
            out.append(f"  - {_md_escape(step)}")
    results = [CheckResult.from_dict(r) for r in doc["results"]]
    for key, title in SECTIONS:
        group = [r for r in results if r.section == key]
        if not group:
            continue
        out += ["", f"## {title}", "", "| Status | Check | Result |", "|---|---|---|"]
        for r in group:
            out.append(f"| {r.status.value} | {_md_escape(r.title)} | {_md_escape(r.summary)} |")
    out.append("")
    return "\n".join(out)


_CSS = """
:root{--bg:#f7f7f8;--card:#fff;--fg:#1d1d1f;--muted:#6b6b73;--line:#e3e3e8;
--pass:#1f8a4c;--warn:#b26b00;--fail:#c62828;--info:#1565c0;--skip:#8a8a8f;--err:#8e24aa}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#ececf0;--muted:#9a9aa3;
--line:#2c2c31;--pass:#4cc38a;--warn:#f0a83a;--fail:#ff6b6b;--info:#64a8ff;--skip:#77777e;--err:#d58cf0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 8px}.meta{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:8px 0}
.finding .t{font-weight:600}.sev-critical{border-left:4px solid var(--fail)}
.sev-warning{border-left:4px solid var(--warn)}.sev-info{border-left:4px solid var(--info)}
ul{margin:6px 0 0 18px;padding:0}details{border-top:1px solid var(--line);padding:8px 0}
details:first-of-type{border-top:0}summary{cursor:pointer;display:flex;gap:10px;align-items:baseline;list-style:none}
summary::-webkit-details-marker{display:none}.badge{font:600 11px/1 ui-monospace,Consolas,monospace;
padding:3px 6px;border-radius:4px;color:#fff;min-width:44px;text-align:center;flex:none}
.PASS{background:var(--pass)}.WARN{background:var(--warn)}.FAIL{background:var(--fail)}
.INFO{background:var(--info)}.SKIP{background:var(--skip)}.ERROR{background:var(--err)}
.title{font-weight:600;flex:none;min-width:190px}.sum{color:var(--muted);overflow-wrap:anywhere}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;
font:12px/1.4 ui-monospace,Consolas,monospace;max-height:420px}
.advice{margin:6px 0 0 0}@media (max-width:640px){summary{flex-wrap:wrap}.title{min-width:0}}
"""


def to_html(doc: dict) -> str:
    """Render the report as a single self-contained HTML page (light/dark aware)."""
    e = html.escape
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f"<meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>{e(APP_NAME)} report - {e(str(doc.get('host', '')))}</title><style>{_CSS}</style></head><body><main>",
             f"<h1>{e(APP_NAME)} network report</h1>",
             f"<div class=meta>{e(str(doc.get('host', '')))} &middot; {e(str(doc.get('os', '')))} &middot; "
             f"{'elevated' if doc.get('elevated') else 'standard user'} &middot; mode: {e(str(doc.get('mode', '')))} "
             f"&middot; profile: {e(str(doc.get('profile', '')))}<br>generated {e(doc['generated'])} by "
             f"{e(APP_NAME)} {e(doc['version'])}</div>",
             "<h2>Diagnosis</h2>"]
    for f in doc["verdict"]:
        steps = "".join(f"<li>{e(s)}</li>" for s in f["next_steps"][:4])
        parts.append(f"<div class='card finding sev-{e(f['severity'])}'><div class=t>{e(f['title'])}</div>"
                     f"<div>{e(f['explanation'])}</div>{'<ul>' + steps + '</ul>' if steps else ''}</div>")
    results = [CheckResult.from_dict(r) for r in doc["results"]]
    for key, title in SECTIONS:
        group = [r for r in results if r.section == key]
        if not group:
            continue
        parts.append(f"<h2>{e(title)}</h2><div class=card>")
        for r in group:
            detail_json = json.dumps(r.details, indent=2, default=str)
            advice = "".join(f"<li>{e(a)}</li>" for a in r.advice)
            parts.append(
                f"<details><summary><span class='badge {r.status.value}'>{r.status.value}</span>"
                f"<span class=title>{e(r.title)}</span><span class=sum>{e(r.summary)}</span></summary>"
                + (f"<ul class=advice>{advice}</ul>" if advice else "")
                + f"<pre>{e(detail_json)}</pre></details>")
        parts.append("</div>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write_report(path: str | Path, doc: dict) -> Path:
    """Write a report; the format follows the file extension (.json, .md, .html/.htm)."""
    path = Path(path)
    ext = path.suffix.lower()
    if ext == ".json":
        text = to_json(doc)
    elif ext in (".md", ".markdown"):
        text = to_markdown(doc)
    elif ext in (".html", ".htm"):
        text = to_html(doc)
    else:
        raise ValueError("report file must end in .html, .md or .json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_bundle(path: str | Path, doc: dict, raw_outputs: dict[str, str], extra_files: list[Path]) -> Path:
    """
    Zip report.html/.md/.json, raw command outputs (raw/*.txt) and extra files
    (e.g. captures) into one archive for escalation.
    """
    path = Path(path)
    if path.suffix.lower() != ".zip":
        path = path.with_suffix(".zip")
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.html", to_html(doc))
        zf.writestr("report.md", to_markdown(doc))
        zf.writestr("report.json", to_json(doc))
        for label, text in raw_outputs.items():
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)[:80]
            zf.writestr(f"raw/{safe}.txt", text)
        for f in extra_files:
            if f.is_file() and f.stat().st_size < 200_000_000:
                zf.write(f, f"files/{f.name}")
    return path


def exit_code(results: list[CheckResult]) -> int:
    """Process exit code: 2 if anything FAILed, 1 for warnings/errors, else 0."""
    statuses = {r.status for r in results}
    if Status.FAIL in statuses:
        return 2
    if statuses & {Status.WARN, Status.ERROR}:
        return 1
    return 0
