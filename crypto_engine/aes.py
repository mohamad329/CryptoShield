"""
aes.py -- A from-scratch, pure-Python implementation of AES-256 (FIPS-197).

WHY A FROM-SCRATCH IMPLEMENTATION?
-----------------------------------
In production you should ALWAYS use a vetted, hardware-accelerated library
(e.g. `cryptography`, OpenSSL) because a hand-written cipher is slow and,
more importantly, almost never "constant-time" (its runtime can leak key
bits through timing side-channels). This module exists purely so a student
can read every mathematical step of AES-256 in one file, with no C
extensions hiding the logic. Treat it as a textbook, not a dependency.

THE ALGORITHM IN ONE PARAGRAPH
-------------------------------
AES encrypts one 16-byte block at a time. It arranges the 16 bytes into a
4x4 grid called the "state", then repeatedly scrambles that grid with four
reversible operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) for a
fixed number of rounds. AES-256 uses a 256-bit (32-byte) key and runs 14
rounds -- more rounds than AES-128 (10) or AES-192 (12) because a longer
key needs more mixing to spread its influence over every output bit.
"""

from __future__ import annotations

import os
from typing import List

BLOCK_SIZE = 16          # AES always works on 16-byte (128-bit) blocks,
                         # regardless of key length.
KEY_SIZE_256 = 32        # AES-256 => a 32-byte (256-bit) key.
ROUNDS_256 = 14          # Number of "scrambling rounds" for a 256-bit key.
WORDS_PER_KEY_256 = 8    # Nk: key length measured in 4-byte words (32/4).
WORDS_PER_BLOCK = 4      # Nb: block length in 4-byte words (always 4 for AES).


# ---------------------------------------------------------------------------
# 1) THE S-BOX (SubBytes lookup table)
# ---------------------------------------------------------------------------
# The S-box is a fixed 256-entry substitution table. Its job is to be a
# "confusion" layer: a non-linear function with no simple algebraic
# relationship to its input, so an attacker cannot describe the cipher with
# easy equations. It is built mathematically from the multiplicative inverse
# in GF(2^8) followed by an affine transformation -- but every AES
# implementation just hard-codes the resulting 256 values, as we do here.
S_BOX: List[int] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
# The inverse S-box simply reverses the lookup: INV_S_BOX[S_BOX[x]] == x.
# We derive it programmatically instead of hard-coding a second 256-entry
# table, which also doubles as a cheap self-check of S_BOX above.
INV_S_BOX: List[int] = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

# RCON holds the "round constants" used while expanding the key. Round i's
# constant is simply 2^(i-1) evaluated inside GF(2^8) (see _xtime below) --
# it exists only to break the symmetry between rounds, so two rounds never
# get expanded the same way even if parts of the key repeat.
RCON: List[int] = [0x01]
for _ in range(1, 14):
    prev = RCON[-1]
    RCON.append(((prev << 1) ^ 0x11B) & 0xFF if prev & 0x80 else (prev << 1) & 0xFF)


def _xtime(byte: int) -> int:
    """Multiply a byte by 2 inside GF(2^8), the finite field AES does all
    its arithmetic in. Regular integer math would overflow past 255 with
    no way back; GF(2^8) multiplication instead "wraps around" using the
    fixed reduction polynomial 0x11B (x^8 + x^4 + x^3 + x + 1), which is
    what keeps every result a single byte."""
    shifted = (byte << 1) & 0xFF
    return shifted ^ 0x1B if byte & 0x80 else shifted


def _gf_multiply(a: int, b: int) -> int:
    """Multiply two bytes inside GF(2^8) using the standard
    'Russian peasant' double-and-add algorithm, reusing _xtime for the
    doubling step. This is what MixColumns needs to combine bytes."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


# ---------------------------------------------------------------------------
# 2) KEY EXPANSION (turns one 256-bit key into 15 round keys)
# ---------------------------------------------------------------------------
def _key_expansion(key: bytes) -> List[List[int]]:
    """Expand a 32-byte key into (ROUNDS_256 + 1) * 4 = 60 "words" (4 bytes
    each). AES does not reuse the same 32-byte key in every round: instead
    it derives a fresh 16-byte round key for each of the 15 stages
    (1 initial AddRoundKey + 14 rounds) from this schedule, so compromising
    one round's key does not trivially reveal the others."""
    if len(key) != KEY_SIZE_256:
        raise ValueError(f"AES-256 requires a {KEY_SIZE_256}-byte key, got {len(key)}")

    # Start with the key itself, split into 4-byte words.
    words: List[List[int]] = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    total_words = WORDS_PER_BLOCK * (ROUNDS_256 + 1)

    for i in range(WORDS_PER_KEY_256, total_words):
        temp = list(words[i - 1])
        if i % WORDS_PER_KEY_256 == 0:
            # RotWord: cyclic left-shift, e.g. [a,b,c,d] -> [b,c,d,a].
            temp = temp[1:] + temp[:1]
            # SubWord: run each byte through the S-box.
            temp = [S_BOX[b] for b in temp]
            # XOR in this round's constant (only in the first byte).
            temp[0] ^= RCON[i // WORDS_PER_KEY_256 - 1]
        elif i % WORDS_PER_KEY_256 == 4:
            # AES-256 only: an extra SubWord every 4 words keeps the longer
            # key schedule just as non-linear as the shorter AES variants.
            temp = [S_BOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - WORDS_PER_KEY_256], temp)])

    # Group every 4 words into one 16-byte round key.
    return [sum(words[4 * r:4 * r + 4], []) for r in range(ROUNDS_256 + 1)]


# ---------------------------------------------------------------------------
# 3) THE FOUR ROUND OPERATIONS (each one is its own exact inverse elsewhere)
# ---------------------------------------------------------------------------
def _add_round_key(state: List[int], round_key: List[int]) -> None:
    """XOR the state with this round's key. XOR is used because it is its
    own inverse (A ^ B ^ B == A), so decryption just XORs the same key in
    again -- no separate 'un-XOR' operation is needed."""
    for i in range(16):
        state[i] ^= round_key[i]


def _sub_bytes(state: List[int], box: List[int]) -> None:
    """Replace every byte with its S-box lookup -- the 'confusion' step."""
    for i in range(16):
        state[i] = box[state[i]]


def _shift_rows(state: List[int]) -> None:
    """Cyclically shift each row of the 4x4 state left, by 0/1/2/3 positions
    for rows 0/1/2/3. AES stores the state column-major, so row r's bytes
    live at indices r, r+4, r+8, r+12. This is the 'diffusion' step that
    spreads a byte's influence across different columns."""
    rows = [[state[r + 4 * c] for c in range(4)] for r in range(4)]
    for r in range(1, 4):
        rows[r] = rows[r][r:] + rows[r][:r]
    for c in range(4):
        for r in range(4):
            state[r + 4 * c] = rows[r][c]


def _inv_shift_rows(state: List[int]) -> None:
    """Exact inverse of _shift_rows: shift each row right instead of left."""
    rows = [[state[r + 4 * c] for c in range(4)] for r in range(4)]
    for r in range(1, 4):
        rows[r] = rows[r][-r:] + rows[r][:-r]
    for c in range(4):
        for r in range(4):
            state[r + 4 * c] = rows[r][c]


def _mix_single_column(col: List[int]) -> List[int]:
    """Multiply one 4-byte column by the fixed matrix
        [2 3 1 1]
        [1 2 3 1]
        [1 1 2 3]
        [3 1 1 2]
    inside GF(2^8). This is the other half of 'diffusion': it blends the
    four bytes of a column together so that changing one input byte
    changes every byte of the output column."""
    a, b, c, d = col
    return [
        _gf_multiply(a, 2) ^ _gf_multiply(b, 3) ^ c ^ d,
        a ^ _gf_multiply(b, 2) ^ _gf_multiply(c, 3) ^ d,
        a ^ b ^ _gf_multiply(c, 2) ^ _gf_multiply(d, 3),
        _gf_multiply(a, 3) ^ b ^ c ^ _gf_multiply(d, 2),
    ]


def _mix_columns(state: List[int]) -> None:
    for c in range(4):
        state[4 * c:4 * c + 4] = _mix_single_column(state[4 * c:4 * c + 4])


def _inv_mix_single_column(col: List[int]) -> List[int]:
    """Multiply by the matrix inverse of the one in _mix_single_column
    (every entry here is the GF(2^8) inverse relationship of the forward
    matrix), which exactly undoes MixColumns."""
    a, b, c, d = col
    return [
        _gf_multiply(a, 14) ^ _gf_multiply(b, 11) ^ _gf_multiply(c, 13) ^ _gf_multiply(d, 9),
        _gf_multiply(a, 9) ^ _gf_multiply(b, 14) ^ _gf_multiply(c, 11) ^ _gf_multiply(d, 13),
        _gf_multiply(a, 13) ^ _gf_multiply(b, 9) ^ _gf_multiply(c, 14) ^ _gf_multiply(d, 11),
        _gf_multiply(a, 11) ^ _gf_multiply(b, 13) ^ _gf_multiply(c, 9) ^ _gf_multiply(d, 14),
    ]


def _inv_mix_columns(state: List[int]) -> None:
    for c in range(4):
        state[4 * c:4 * c + 4] = _inv_mix_single_column(state[4 * c:4 * c + 4])


# ---------------------------------------------------------------------------
# 4) SINGLE-BLOCK ENCRYPT / DECRYPT (the core AES-256 algorithm)
# ---------------------------------------------------------------------------
def encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Encrypt exactly one 16-byte block. The structure is:
        AddRoundKey(0)
        for round 1..13: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
        round 14 (final): SubBytes -> ShiftRows -> AddRoundKey  (no MixColumns)
    The final round skips MixColumns purely so that encryption and
    decryption are built from a symmetric set of steps -- it does not
    weaken the cipher."""
    state = list(block)
    _add_round_key(state, round_keys[0])

    for rnd in range(1, ROUNDS_256):
        _sub_bytes(state, S_BOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])

    _sub_bytes(state, S_BOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[ROUNDS_256])
    return bytes(state)


def decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Decrypt one block by applying every step's inverse in reverse order
    -- this is what makes AES a *symmetric* cipher: the same key material
    that locked the block is reused, just walked backwards."""
    state = list(block)
    _add_round_key(state, round_keys[ROUNDS_256])
    _inv_shift_rows(state)
    _sub_bytes(state, INV_S_BOX)

    for rnd in range(ROUNDS_256 - 1, 0, -1):
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _sub_bytes(state, INV_S_BOX)

    _add_round_key(state, round_keys[0])
    return bytes(state)


# ---------------------------------------------------------------------------
# 5) PKCS#7 PADDING (AES only processes full 16-byte blocks)
# ---------------------------------------------------------------------------
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad `data` to a multiple of `block_size`. PKCS#7 pads with N bytes,
    each of value N, where N is however many bytes are needed (1..block_size).
    Padding every N with the value N is what lets unpad() know exactly how
    much to strip, even if the plaintext's real length was already a clean
    multiple of the block size (then a full extra block of padding is added)."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Padded data length must be a non-zero multiple of the block size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding -- wrong key, corrupted data, or tampering")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# 6) CBC MODE (chains blocks together so identical plaintext blocks don't
#    produce identical ciphertext blocks)
# ---------------------------------------------------------------------------
def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class AES256:
    """AES-256 in CBC (Cipher Block Chaining) mode.

    CBC XORs each plaintext block with the *previous ciphertext block*
    before encrypting it (the first block is XORed with a random IV
    instead, since there is no previous ciphertext yet). This single trick
    is what defeats the weakness of "ECB mode", where two identical
    plaintext blocks always produce identical ciphertext blocks -- a
    pattern that can literally be visible to the eye (the classic
    "ECB penguin" image is the textbook demonstration of this flaw).
    """

    def __init__(self, key: bytes):
        self.key = key
        self._round_keys = _key_expansion(key)

    @classmethod
    def generate_key(cls) -> bytes:
        """A cryptographically secure random 256-bit key, using the OS's
        CSPRNG (os.urandom) -- never Python's default `random` module,
        which is predictable and unsuitable for secrets."""
        return os.urandom(KEY_SIZE_256)

    def encrypt(self, plaintext: bytes, iv: bytes | None = None) -> bytes:
        """Returns `iv + ciphertext`. The IV is not secret -- it only needs
        to be unique per encryption -- so shipping it alongside the
        ciphertext is the normal, safe thing to do."""
        iv = iv or os.urandom(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

        padded = pkcs7_pad(plaintext)
        previous = iv
        out = bytearray(iv)
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i + BLOCK_SIZE]
            chained_in = _xor_bytes(block, previous)
            cipher_block = encrypt_block(chained_in, self._round_keys)
            out += cipher_block
            previous = cipher_block
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < BLOCK_SIZE or (len(data) - BLOCK_SIZE) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length is invalid for AES-CBC")
        iv, body = data[:BLOCK_SIZE], data[BLOCK_SIZE:]

        previous = iv
        out = bytearray()
        for i in range(0, len(body), BLOCK_SIZE):
            cipher_block = body[i:i + BLOCK_SIZE]
            decrypted = decrypt_block(cipher_block, self._round_keys)
            out += _xor_bytes(decrypted, previous)
            previous = cipher_block
        return pkcs7_unpad(bytes(out))
