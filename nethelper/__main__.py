"""
Entry point used when NetHelper is started with `python -m nethelper` or run
as a single-file zip app (`python nethelper.pyz`).

Python looks for a module named `__main__` inside a package when asked to "run"
the package. All this does is hand control to the real command-line handler in
cli.py and pass its exit code back to the operating system (0 = success,
non-zero = something failed), so scripts and schedulers can react to it.
"""

import sys

from nethelper.cli import main

if __name__ == "__main__":
    sys.exit(main())
