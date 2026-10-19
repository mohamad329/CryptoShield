"""Startup banner for CryptoShield (original ASCII art, no third-party assets)."""

from __future__ import annotations

import os
from typing import Callable

# Lightweight ANSI color codes, used the same way the rest of the project's
# CLI output is colored. 0 codes are a no-op when color is disabled.
BOLD, DIM = "1", "2"
GREEN, CYAN, YELLOW = "32", "36", "33"

TITLE_ART = r"""
   _____                 _          _____ _     _      _     _
  / ____|               | |        / ____| |   (_)    | |   | |
 | |     _ __ _   _ _ __ | |_ ___  | (___ | |__  _  ___| | __| |
 | |    | '__| | | | '_ \| __/ _ \  \___ \| '_ \| |/ _ \ |/ _` |
 | |____| |  | |_| | |_) | || (_) | ____) | | | | |  __/ | (_| |
  \_____|_|   \__, | .__/ \__\___/ |_____/|_| |_|_|\___|_|\__,_|
               __/ | |
              |___/|_|
""".strip("\n")

LOCK_ART = r"""
                ___________
               /           \
              /   -------   \
             |   /       \   |
             |  |  AES256 |  |
             |   \_______/   |
              \_____________/
                   |     |
                   |_____|
""".strip("\n")

TAGLINE = "Educational AES-256 / XOR Cryptography & Obfuscation Toolkit"
SUBLINE = "confidentiality  *  integrity  *  reverse-engineering resistance"


def supports_color(stream) -> bool:
    """True if `stream` is an interactive terminal that should get ANSI
    colors (and the user hasn't opted out via the NO_COLOR convention)."""
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def make_colorizer(enabled: bool) -> Callable[[str, str], str]:
    """Build a `c(text, ansi_code)` function. When disabled, it returns
    `text` unchanged, so callers never need an `if enabled:` branch."""
    def colorize(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if enabled else text
    return colorize


def render_banner(version: str, c: Callable[[str, str], str]) -> str:
    """Render the full startup banner. `c(text, ansi_code)` applies color;
    pass a no-op lambda to get plain text (e.g. when writing to a file or
    when colors are disabled for a non-tty output)."""
    lines = []
    lines.extend(c(line, GREEN) for line in TITLE_ART.splitlines())
    lines.append("")
    lines.extend(c(line, CYAN) for line in LOCK_ART.splitlines())
    lines.append("")
    lines.append(c(f"CryptoShield v{version}".center(66), BOLD))
    lines.append(c(TAGLINE.center(66), YELLOW))
    lines.append(c(SUBLINE.center(66), DIM))
    lines.append("")
    return "\n".join(lines)
