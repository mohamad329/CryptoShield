"""
authenticated.py -- Encrypt-then-MAC: fixing AES-CBC's missing integrity check.

Main_Demo.py (step 2) shows that plain AES-256-CBC only rejects a tampered
ciphertext when the corruption happens to land in the final block's
padding -- an attacker who flips a bit elsewhere gets silently corrupted
(but undetected) plaintext back. This module closes that gap using the
standard, well-studied construction called "Encrypt-then-MAC":

    1. Encrypt the plaintext with AES-256-CBC as usual.
    2. Compute an HMAC-SHA256 over the resulting ciphertext (IV included),
       keyed with a SEPARATE key from the encryption key.
    3. Ship `ciphertext || tag`. Before decrypting anything, recompute the
       HMAC over the received ciphertext and compare it to the received
       tag using a constant-time comparison (`hmac.compare_digest`) --
       this is what stops an attacker's forged or altered ciphertext from
       ever reaching the decryption step at all.

WHY TWO SEPARATE KEYS?
------------------------
Reusing one key for both encryption and authentication can let the two
uses interact in ways that weaken either guarantee, depending on the
modes involved. Deriving two independent keys from one master secret
(or simply generating two random keys, as this demo does) avoids the
question entirely and is the conventional, safe default.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from hashlib import sha256

from .aes import AES256

MAC_KEY_SIZE = 32
TAG_SIZE = 32  # HMAC-SHA256 always produces a 32-byte tag


@dataclass(frozen=True)
class AuthenticatedKeyPair:
    """Two independent keys: one for secrecy, one for integrity."""
    enc_key: bytes
    mac_key: bytes

    @classmethod
    def generate(cls) -> "AuthenticatedKeyPair":
        return cls(enc_key=AES256.generate_key(), mac_key=os.urandom(MAC_KEY_SIZE))


def encrypt_and_authenticate(plaintext: bytes, keys: AuthenticatedKeyPair) -> bytes:
    """Return `ciphertext || tag`, ready to transmit or store as one blob."""
    ciphertext = AES256(keys.enc_key).encrypt(plaintext)
    tag = hmac.new(keys.mac_key, ciphertext, sha256).digest()
    return ciphertext + tag


def verify_and_decrypt(blob: bytes, keys: AuthenticatedKeyPair) -> bytes:
    """Verify the MAC BEFORE touching AES at all ('verify-then-decrypt').
    Raises ValueError if the tag does not match -- i.e. the data was
    corrupted or an attacker without `mac_key` tampered with it."""
    if len(blob) < TAG_SIZE:
        raise ValueError("Data too short to contain a valid authentication tag")
    ciphertext, received_tag = blob[:-TAG_SIZE], blob[-TAG_SIZE:]

    expected_tag = hmac.new(keys.mac_key, ciphertext, sha256).digest()
    # hmac.compare_digest runs in constant time regardless of where the
    # first mismatching byte occurs, which prevents a *timing* side-channel
    # attack from leaking the correct tag one byte at a time.
    if not hmac.compare_digest(expected_tag, received_tag):
        raise ValueError("Authentication failed: ciphertext was tampered with or corrupted")

    return AES256(keys.enc_key).decrypt(ciphertext)
