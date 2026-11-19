"""
Turning check results into something a person reads:

  verdict.py   rule-based diagnosis: combines results into a short list of
               plain-English findings ("DNS server down", "wrong VLAN"...)
  console.py   coloured terminal output of results + verdict
  export.py    JSON, Markdown and self-contained HTML reports, and zip bundles
  redact.py    scrubs public IPs, MACs, SSIDs, host/user names before sharing
  baseline.py  save a known-good run and diff later runs against it
"""
