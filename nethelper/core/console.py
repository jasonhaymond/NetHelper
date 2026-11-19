"""
Terminal output helpers: colours, status badges, section headings, tables.

Colours use ANSI escape codes (special character sequences like ESC[32m that
terminals interpret as "switch to green"). They're turned off automatically
when output is redirected to a file, when NO_COLOR is set (a cross-tool
convention), or with --no-color. On Windows, "virtual terminal processing" is
switched on via the Win32 console API so the codes render instead of showing
as garbage.

All symbols are plain ASCII so output looks right in every Windows code page
and over basic SSH sessions.
"""

from __future__ import annotations

import os
import shutil
import sys

from nethelper.core.result import Status

_COLORS = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
    "cyan": "36", "grey": "90", "bold": "1", "dim": "2",
}

STATUS_STYLE = {
    Status.PASS: ("green", " OK "),
    Status.WARN: ("yellow", "WARN"),
    Status.FAIL: ("red", "FAIL"),
    Status.INFO: ("cyan", "INFO"),
    Status.SKIP: ("grey", "SKIP"),
    Status.ERROR: ("magenta", "ERR "),
}


class Console:
    """Writes formatted text to the terminal. One instance per run."""

    def __init__(self, color: bool | None = None, stream=None):
        self.stream = stream or sys.stdout
        if color is None:
            color = self.stream.isatty() and not os.environ.get("NO_COLOR")
        self.color = color
        if self.color and sys.platform == "win32":
            _enable_windows_ansi()
        self.width = min(shutil.get_terminal_size((100, 24)).columns, 120)

    def c(self, text: str, *styles: str) -> str:
        """Wrap text in colour codes (no-op when colour is off)."""
        if not self.color or not styles:
            return text
        codes = ";".join(_COLORS[s] for s in styles if s in _COLORS)
        return f"\033[{codes}m{text}\033[0m"

    def print(self, text: str = "") -> None:
        """Print one line, replacing characters the terminal can't encode."""
        try:
            print(text, file=self.stream, flush=True)
        except UnicodeEncodeError:
            enc = getattr(self.stream, "encoding", None) or "ascii"
            print(text.encode(enc, errors="replace").decode(enc), file=self.stream, flush=True)

    def badge(self, status: Status) -> str:
        """Return a fixed-width coloured status marker, e.g. "[ OK ]"."""
        color, label = STATUS_STYLE[status]
        return self.c(f"[{label}]", color, "bold")

    def heading(self, text: str) -> None:
        """Print a section heading with an underline rule."""
        self.print("")
        self.print(self.c(text, "bold", "cyan"))
        self.print(self.c("-" * min(len(text) + 4, self.width), "grey"))

    def kv(self, key: str, value: object, indent: int = 2, key_width: int = 22) -> None:
        """Print an aligned "key: value" line."""
        self.print(" " * indent + self.c(f"{key:<{key_width}}", "grey") + f" {value}")

    def table(self, headers: list[str], rows: list[list[object]], indent: int = 2,
              shrink_first: list[int] | None = None) -> None:
        """
        Print a simple left-aligned text table, truncating to terminal width.
        `shrink_first` lists column indexes to shorten before any others (least
        important first), so key columns like names stay readable.
        """
        if not rows:
            return
        cells = [[str(h) for h in headers]] + [["" if v is None else str(v) for v in r] for r in rows]
        widths = [max(len(row[i]) for row in cells) for i in range(len(headers))]
        budget = self.width - indent - 2 * (len(headers) - 1)
        # First shorten the low-priority columns (down to 6 chars), then the widest of the rest.
        for col in shrink_first or []:
            while sum(widths) > budget and widths[col] > 6:
                widths[col] -= 1
        while sum(widths) > budget and max(widths) > 8:
            widths[widths.index(max(widths))] -= 1
        for n, row in enumerate(cells):
            line = "  ".join(_fit(v, widths[i]) for i, v in enumerate(row))
            self.print(" " * indent + (self.c(line, "bold") if n == 0 else line))


def _fit(text: str, width: int) -> str:
    """Pad or truncate text to exactly `width` characters."""
    return text.ljust(width) if len(text) <= width else text[: max(width - 1, 0)] + "~"


def _enable_windows_ansi() -> None:
    """
    Turn on ANSI colour support in the Windows console by setting the
    ENABLE_VIRTUAL_TERMINAL_PROCESSING flag (0x0004) on the output handle.
    Harmless if it fails (colours just won't render).
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # -11 = STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except (AttributeError, OSError):
        pass
