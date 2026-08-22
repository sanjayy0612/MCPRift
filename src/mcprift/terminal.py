"""Small, opt-in ANSI styling for human-readable terminal output."""

from __future__ import annotations

import os
from typing import TextIO

_RESET = "\x1b[0m"
_GREEN = "\x1b[1;38;5;48m"
_YELLOW = "\x1b[1;38;5;220m"


def color_enabled(stream: TextIO) -> bool:
    """Use accents only in an interactive terminal that has not opted out."""
    is_terminal = bool(getattr(stream, "isatty", lambda: False)())
    return is_terminal and "NO_COLOR" not in os.environ


def green(text: str, *, enabled: bool) -> str:
    return _wrap(text, _GREEN, enabled)


def yellow(text: str, *, enabled: bool) -> str:
    return _wrap(text, _YELLOW, enabled)


def verdict(text: str, status: str, *, enabled: bool) -> str:
    """Render passing outcomes green and attention-required outcomes yellow."""
    if status == "pass":
        return green(text, enabled=enabled)
    return yellow(text, enabled=enabled)


def _wrap(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text
