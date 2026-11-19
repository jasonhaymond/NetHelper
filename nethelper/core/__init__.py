"""
Core framework for NetHelper: the pieces every diagnostic check relies on.

- result.py      the standard "result" record every check returns
- registry.py    the catalogue of checks and their requirements (admin, OS)
- context.py     shared state handed to each check (options, profile, caches)
- runner.py      runs checks in parallel and enforces privilege/OS limits
- privileges.py  detects whether we're elevated and which tools exist
- cmd.py         the ONLY place that launches external programs (safely)
- validate.py    input validation for hostnames, IPs, ports, interface names
- config.py      loads per-site TOML profiles
- console.py     coloured terminal output
- paths.py       where logs, baselines and caches are stored
- logsetup.py    rotating log file configuration
"""
