"""
NetHelper - a cross-platform network troubleshooting toolkit.

This file marks the `nethelper` folder as a Python *package* (a folder of
modules that can be imported as one unit) and holds the single source of truth
for the application's version number. Everything else (the CLI banner, reports,
baselines, the security-report filename) reads the version from here.

NetHelper uses only Python's standard library, so it runs on any machine with
Python 3.11 or newer without installing anything else.
"""

# Semantic version: MAJOR.MINOR.PATCH. Bump this together with CHANGELOG.md and
# pyproject.toml in the same commit that ships the change.
__version__ = "1.0.1"

# Name shown in banners, reports and the HTTP User-Agent header.
APP_NAME = "NetHelper"
