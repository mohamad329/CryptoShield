"""
obfuscator.py -- String obfuscation utilities (NOT encryption).

OBFUSCATION VS. ENCRYPTION -- READ THIS FIRST
------------------------------------------------
This module deliberately contains no secret-key math. Hex and Base64 are
*encodings*, not ciphers: anyone can reverse them instantly with a single
line of code or an online decoder, with no key required at all. "Junk
data" insertion is a packing trick that makes a static string harder for
a human to spot while skimming disassembled code or a hex dump -- it adds
zero mathematical protection against an attacker who actually runs the
program or writes a short deobfuscation script.

In real reverse-engineering defense, obfuscation like this only raises the
*time cost* of manual analysis; it is layered ON TOP OF real encryption
(see aes.py), never used as a substitute for it. This module's purpose is
to let a student clearly see where "hiding" ends and "securing" begins.
"""

from __future__ import annotations

import base64
import os
from typing import List


# ---------------------------------------------------------------------- hex
def to_hex(data: bytes) -> str:
    """Render bytes as a lowercase hex string, e.g. b'AB' -> '4142'."""
    return data.hex()


def from_hex(text: str) -> bytes:
    return bytes.fromhex(text)


# ------------------------------------------------------------------ base64
def to_base64(data: bytes) -> str:
    """Base64 re-encodes arbitrary bytes using only 64 printable characters
    (A-Z, a-z, 0-9, '+', '/'), which is why it is the standard way to embed
    binary data (like ciphertext) inside text formats such as JSON, HTML or
    source code string literals."""
    return base64.b64encode(data).decode("ascii")


def from_base64(text: str) -> bytes:
    return base64.b64decode(text)


# -------------------------------------------------------------- junk data
# A junk "token" is wrapped in markers so it can always be located and
# stripped again deterministically, however random its own content is.
_JUNK_PREFIX = "{{J:"
_JUNK_SUFFIX = "}}"
_JUNK_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _random_token(min_len: int, max_len: int) -> str:
    length = min_len + (os.urandom(1)[0] % (max_len - min_len + 1))
    idx = os.urandom(length)
    return "".join(_JUNK_ALPHABET[b % len(_JUNK_ALPHABET)] for b in idx)


def insert_junk(text: str, density: float = 0.15, min_len: int = 3, max_len: int = 10) -> str:
    """Scatter meaningless marked tokens through `text`.

    This is purely a *visual* defense: a reverse engineer skimming a string
    table full of mixed real and junk tokens has to spend extra time
    checking each one, rather than instantly spotting the one meaningful
    secret. `density` is approximately one junk token inserted per
    `1/density` characters of real text.

    The tokens are wrapped in `{{J: ... }}` markers specifically so
    `strip_junk` can remove them with total precision; true malicious
    obfuscators use far subtler, unmarked noise, but a reversible, visible
    marker is what makes this safe to demonstrate and safe to undo in a
    classroom setting.
    """
    if not 0 <= density <= 1:
        raise ValueError("density must be between 0 and 1")
    if not text:
        return text

    out: List[str] = []
    gap = max(1, round(1 / density)) if density > 0 else len(text) + 1
    for i, ch in enumerate(text):
        out.append(ch)
        if density > 0 and (i + 1) % gap == 0:
            out.append(f"{_JUNK_PREFIX}{_random_token(min_len, max_len)}{_JUNK_SUFFIX}")
    return "".join(out)


def strip_junk(text: str) -> str:
    """Exact inverse of insert_junk: remove every {{J: ... }} token."""
    out, i = [], 0
    while i < len(text):
        start = text.find(_JUNK_PREFIX, i)
        if start == -1:
            out.append(text[i:])
            break
        out.append(text[i:start])
        end = text.find(_JUNK_SUFFIX, start)
        if end == -1:  # malformed tail; keep the rest verbatim
            out.append(text[start:])
            break
        i = end + len(_JUNK_SUFFIX)
    return "".join(out)


# --------------------------------------------------------- combined pipeline
def obfuscate_string(plaintext: str, encoding: str = "base64",
                     junk_density: float = 0.15) -> str:
    """Convenience pipeline: encode as hex/base64, then scatter junk tokens
    through the result. Returns a single string ready to, say, be dropped
    into a source file as a disguised literal."""
    data = plaintext.encode("utf-8")
    encoded = to_base64(data) if encoding == "base64" else to_hex(data)
    return insert_junk(encoded, density=junk_density)


def deobfuscate_string(obfuscated: str, encoding: str = "base64") -> str:
    """Exact inverse of obfuscate_string."""
    cleaned = strip_junk(obfuscated)
    data = from_base64(cleaned) if encoding == "base64" else from_hex(cleaned)
    return data.decode("utf-8")
