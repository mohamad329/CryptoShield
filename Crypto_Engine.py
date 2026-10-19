#!/usr/bin/env python3
"""
Crypto_Engine.py -- Command-line front-end for the CryptoShield engine.

This is the single entry point a user runs directly:
    python Crypto_Engine.py <command> [options]

The actual algorithms live in the `crypto_engine/` package (aes.py,
xor_cipher.py, obfuscator.py, file_crypto.py) -- this file only parses
arguments and wires them together, so the cryptographic logic stays in one
well-commented place regardless of how the CLI evolves.
"""

from __future__ import annotations

import argparse
import base64
import sys

from crypto_engine import __version__
from crypto_engine.aes import AES256
from crypto_engine.authenticated import (AuthenticatedKeyPair,
                                         encrypt_and_authenticate,
                                         verify_and_decrypt)
from crypto_engine.banner import make_colorizer, render_banner, supports_color
from crypto_engine.file_crypto import decrypt_file, encrypt_file, load_key, save_key
from crypto_engine.obfuscator import deobfuscate_string, obfuscate_string
from crypto_engine.xor_cipher import break_single_byte_xor, xor_encrypt

KEY_PREVIEW_LEN = 12


def _key_from_hex_or_file(args) -> bytes:
    if args.key_file:
        return load_key(args.key_file)
    if args.key_hex:
        key = bytes.fromhex(args.key_hex)
        if len(key) != 32:
            raise ValueError("--key-hex must decode to exactly 32 bytes (256 bits)")
        return key
    raise ValueError("Provide a key with --key-hex or --key-file")


# --------------------------------------------------------------------- AES
def cmd_genkey(args) -> int:
    key = AES256.generate_key()
    if args.out:
        save_key(key, args.out)
        print(f"[+] New AES-256 key written to {args.out} (permissions set to owner-only where supported)")
    print(f"[+] Key (hex): {key.hex()}")
    return 0


def cmd_encrypt_text(args) -> int:
    key = _key_from_hex_or_file(args)
    ciphertext = AES256(key).encrypt(args.text.encode("utf-8"))
    print(base64.b64encode(ciphertext).decode("ascii"))
    return 0


def cmd_decrypt_text(args) -> int:
    key = _key_from_hex_or_file(args)
    try:
        ciphertext = base64.b64decode(args.base64)
        plaintext = AES256(key).decrypt(ciphertext)
    except (ValueError, Exception) as exc:  # noqa: BLE001 - surface any crypto error to the user
        print(f"[!] Decryption failed: {exc}", file=sys.stderr)
        return 1
    print(plaintext.decode("utf-8", errors="replace"))
    return 0


def cmd_encrypt_file(args) -> int:
    key = _key_from_hex_or_file(args)
    out = encrypt_file(args.path, key, args.out)
    print(f"[+] Encrypted -> {out}")
    return 0


def cmd_decrypt_file(args) -> int:
    key = _key_from_hex_or_file(args)
    try:
        out = decrypt_file(args.path, key, args.out)
    except ValueError as exc:
        print(f"[!] Decryption failed: {exc}", file=sys.stderr)
        return 1
    print(f"[+] Decrypted -> {out}")
    return 0


# ------------------------------------------------------------- authenticated
def cmd_auth_genkeys(args) -> int:
    keys = AuthenticatedKeyPair.generate()
    if args.out_prefix:
        save_key(keys.enc_key, f"{args.out_prefix}.enc.key")
        save_key(keys.mac_key, f"{args.out_prefix}.mac.key")
        print(f"[+] Keys written to {args.out_prefix}.enc.key / {args.out_prefix}.mac.key")
    print(f"[+] enc-key (hex): {keys.enc_key.hex()}")
    print(f"[+] mac-key (hex): {keys.mac_key.hex()}")
    return 0


def cmd_auth_encrypt(args) -> int:
    keys = AuthenticatedKeyPair(bytes.fromhex(args.enc_key_hex), bytes.fromhex(args.mac_key_hex))
    blob = encrypt_and_authenticate(args.text.encode("utf-8"), keys)
    print(base64.b64encode(blob).decode("ascii"))
    return 0


def cmd_auth_decrypt(args) -> int:
    keys = AuthenticatedKeyPair(bytes.fromhex(args.enc_key_hex), bytes.fromhex(args.mac_key_hex))
    try:
        plaintext = verify_and_decrypt(base64.b64decode(args.base64), keys)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print(plaintext.decode("utf-8", errors="replace"))
    return 0


# --------------------------------------------------------------------- XOR
def cmd_xor(args) -> int:
    data = args.text.encode("utf-8")
    result = xor_encrypt(data, args.key.encode("utf-8"))
    print(base64.b64encode(result).decode("ascii"))
    return 0


def cmd_xor_break(args) -> int:
    ciphertext = base64.b64decode(args.base64)
    key, plaintext, score = break_single_byte_xor(ciphertext)
    print(f"[+] Best single-byte key: 0x{key:02x} ({chr(key) if 32 <= key < 127 else '?'!r})")
    print(f"[+] Recovered text: {plaintext.decode('utf-8', errors='replace')}")
    print(f"[+] Confidence score: {score:.1f} (higher = more English-like)")
    return 0


# ------------------------------------------------------------- obfuscation
def cmd_obfuscate(args) -> int:
    print(obfuscate_string(args.text, encoding=args.encoding, junk_density=args.density))
    return 0


def cmd_deobfuscate(args) -> int:
    print(deobfuscate_string(args.text, encoding=args.encoding))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Crypto_Engine.py",
        description="CryptoShield - educational AES-256/XOR encryption and string "
                    "obfuscation toolkit. For academic / defensive-security study only.",
    )
    p.add_argument("--no-banner", action="store_true", help="do not print the startup banner")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = p.add_subparsers(dest="command", required=True)

    def add_key_args(sp):
        g = sp.add_mutually_exclusive_group(required=True)
        g.add_argument("--key-hex", help="32-byte AES-256 key as a 64-char hex string")
        g.add_argument("--key-file", help="path to a raw binary key file")

    g = sub.add_parser("genkey", help="generate a new random AES-256 key")
    g.add_argument("--out", help="save the key to this file")
    g.set_defaults(func=cmd_genkey)

    e = sub.add_parser("encrypt-text", help="AES-256-CBC encrypt a string -> base64")
    e.add_argument("text")
    add_key_args(e)
    e.set_defaults(func=cmd_encrypt_text)

    d = sub.add_parser("decrypt-text", help="AES-256-CBC decrypt a base64 string")
    d.add_argument("base64")
    add_key_args(d)
    d.set_defaults(func=cmd_decrypt_text)

    ef = sub.add_parser("encrypt-file", help="AES-256-CBC encrypt a file")
    ef.add_argument("path")
    ef.add_argument("--out", help="output path (default: <path>.enc)")
    add_key_args(ef)
    ef.set_defaults(func=cmd_encrypt_file)

    df = sub.add_parser("decrypt-file", help="AES-256-CBC decrypt a file")
    df.add_argument("path")
    df.add_argument("--out", help="output path (default strips the .enc suffix)")
    add_key_args(df)
    df.set_defaults(func=cmd_decrypt_file)

    ag = sub.add_parser("auth-genkeys", help="generate an AES encryption key + separate HMAC key")
    ag.add_argument("--out-prefix", help="save both keys as <prefix>.enc.key / <prefix>.mac.key")
    ag.set_defaults(func=cmd_auth_genkeys)

    ae = sub.add_parser("auth-encrypt", help="AES-256-CBC + HMAC-SHA256 encrypt a string (Encrypt-then-MAC)")
    ae.add_argument("text")
    ae.add_argument("--enc-key-hex", required=True)
    ae.add_argument("--mac-key-hex", required=True)
    ae.set_defaults(func=cmd_auth_encrypt)

    ad = sub.add_parser("auth-decrypt", help="verify + decrypt an Encrypt-then-MAC blob")
    ad.add_argument("base64")
    ad.add_argument("--enc-key-hex", required=True)
    ad.add_argument("--mac-key-hex", required=True)
    ad.set_defaults(func=cmd_auth_decrypt)

    x = sub.add_parser("xor", help="repeating-key XOR encrypt/decrypt a string -> base64")
    x.add_argument("text")
    x.add_argument("--key", required=True, help="XOR key (any length)")
    x.set_defaults(func=cmd_xor)

    xb = sub.add_parser("xor-break", help="brute-force a single-byte XOR ciphertext (base64 in)")
    xb.add_argument("base64")
    xb.set_defaults(func=cmd_xor_break)

    o = sub.add_parser("obfuscate", help="hex/base64-encode a string and scatter junk tokens through it")
    o.add_argument("text")
    o.add_argument("--encoding", choices=["hex", "base64"], default="base64")
    o.add_argument("--density", type=float, default=0.15, help="junk token density 0-1 (default 0.15)")
    o.set_defaults(func=cmd_obfuscate)

    do = sub.add_parser("deobfuscate", help="reverse `obfuscate`")
    do.add_argument("text")
    do.add_argument("--encoding", choices=["hex", "base64"], default="base64")
    do.set_defaults(func=cmd_deobfuscate)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner:
        c = make_colorizer(supports_color(sys.stderr) and not args.no_color)
        print(render_banner(__version__, c), file=sys.stderr)

    try:
        return args.func(args)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
