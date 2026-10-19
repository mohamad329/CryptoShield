"""
file_crypto.py -- Encrypt/decrypt whole files using the AES256 engine.

A file is just a sequence of bytes, so encrypting one is mechanically
identical to encrypting an in-memory byte string -- this module only adds
the file-handling boilerplate (reading, writing, a recognizable output
extension) around aes.AES256.
"""

from __future__ import annotations

import os

from .aes import AES256

ENCRYPTED_SUFFIX = ".enc"


def encrypt_file(src_path: str, key: bytes, dst_path: str | None = None) -> str:
    dst_path = dst_path or src_path + ENCRYPTED_SUFFIX
    with open(src_path, "rb") as fh:
        plaintext = fh.read()
    ciphertext = AES256(key).encrypt(plaintext)
    with open(dst_path, "wb") as fh:
        fh.write(ciphertext)
    return dst_path


def decrypt_file(src_path: str, key: bytes, dst_path: str | None = None) -> str:
    if dst_path is None:
        dst_path = src_path[:-len(ENCRYPTED_SUFFIX)] if src_path.endswith(ENCRYPTED_SUFFIX) \
            else src_path + ".dec"
    with open(src_path, "rb") as fh:
        ciphertext = fh.read()
    plaintext = AES256(key).decrypt(ciphertext)
    with open(dst_path, "wb") as fh:
        fh.write(plaintext)
    return dst_path


def save_key(key: bytes, path: str) -> None:
    """Save a key to disk. For this educational project a plain file is
    fine; in production a key belongs in a hardware module or a secrets
    manager, never a plaintext file next to the data it protects."""
    with open(path, "wb") as fh:
        fh.write(key)
    try:
        os.chmod(path, 0o600)  # best-effort: owner read/write only (POSIX)
    except OSError:
        pass


def load_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()
