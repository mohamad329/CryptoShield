#!/usr/bin/env python3
"""
Main_Demo.py -- Proof-of-Concept runner for CryptoShield.

This script is the "show, don't tell" companion to the engine modules. It
walks through five demonstrations, printing each intermediate value so a
reader can see the data change shape at every step:

  1. AES-256-CBC round trip      (confidentiality -- data is unreadable
                                   without the key)
  2. Tamper detection             (integrity -- a single flipped bit makes
                                   decryption fail loudly instead of
                                   silently returning corrupted data)
  3. XOR cipher + how to break it (why "any encryption" is not "secure
                                   encryption")
  4. String obfuscation           (hex/base64 + junk data, and why this is
                                   not a substitute for step 1)
  5. File encryption               (the same AES engine applied to a file
                                   on disk)

Run it directly:  python Main_Demo.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap

from crypto_engine import __version__
from crypto_engine.aes import AES256
from crypto_engine.authenticated import (AuthenticatedKeyPair,
                                         encrypt_and_authenticate,
                                         verify_and_decrypt)
from crypto_engine.banner import make_colorizer, render_banner, supports_color
from crypto_engine.file_crypto import decrypt_file, encrypt_file
from crypto_engine.obfuscator import (deobfuscate_string, insert_junk,
                                      obfuscate_string, strip_junk, to_base64, to_hex)
from crypto_engine.xor_cipher import break_single_byte_xor, xor_encrypt


def header(title: str) -> None:
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def preview(label: str, value: bytes | str, width: int = 60) -> None:
    text = value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
    wrapped = textwrap.fill(text, width=width, subsequent_indent=" " * (len(label) + 2))
    print(f"{label}: {wrapped}")


# --------------------------------------------------------------------- 1&2
def demo_aes_cbc() -> None:
    header("1) AES-256-CBC: confidentiality in memory")

    secret_message = b"Operation Nightingale launches at 04:00. Rally point: Hangar 9."
    key = AES256.generate_key()
    engine = AES256(key)

    print("Plaintext (what we want to protect):")
    print(f"  {secret_message.decode()}\n")
    preview("Random 256-bit key ", key)

    ciphertext = engine.encrypt(secret_message)
    preview("Ciphertext (IV + encrypted blocks)", ciphertext)
    print(f"  -> {len(secret_message)} bytes of plaintext became "
          f"{len(ciphertext)} bytes of ciphertext (16-byte IV + padded blocks).")
    print("  -> Without `key`, this ciphertext is computationally indistinguishable")
    print("     from random noise: that is the formal security goal of AES-CBC.")

    recovered = engine.decrypt(ciphertext)
    print(f"\nDecrypted with the correct key -> matches original: {recovered == secret_message}")
    print(f"Recovered text: {recovered.decode()}")

    header("2) Integrity check: what CBC does and does NOT catch on its own")
    block_size = 16
    last_block_start = block_size * (len(ciphertext) // block_size - 1)

    print("Case A -- flip one bit in an EARLY ciphertext block, then decrypt:")
    tampered_early = bytearray(ciphertext)
    tampered_early[20] ^= 0xFF  # inside the first ciphertext block (not the last)
    result_a = engine.decrypt(bytes(tampered_early))
    print(f"  -> No exception was raised. Recovered bytes: {result_a!r}")
    print("  -> This is CBC's well-known 'malleability': flipping a ciphertext bit")
    print("     scrambles its own block and flips the SAME bit position one block")
    print("     later, but never touches the final block's padding -- so a plain")
    print("     padding check cannot see this corruption at all.")

    print("\nCase B -- flip one bit in the LAST ciphertext block, then decrypt:")
    tampered_last = bytearray(ciphertext)
    tampered_last[last_block_start] ^= 0xFF
    try:
        engine.decrypt(bytes(tampered_last))
        print("  -> Decrypted without error (possible ~1/256 of the time by chance).")
    except ValueError as exc:
        print(f"  -> Rejected: {exc}")
    print("  -> Here the flip broke the PKCS#7 padding bytes themselves, so THIS")
    print("     particular tamper happened to be caught -- but Case A proves that")
    print("     is luck of where the attacker struck, not a real integrity guarantee.")
    print("\nLESSON: PKCS#7 padding checks are not a substitute for authentication.")
    print("Production systems should use an authenticated mode (AES-GCM) or attach")
    print("a separate MAC (e.g. HMAC-SHA256) over the ciphertext -- see README.")


def demo_authenticated_fix() -> None:
    header("2b) Fixing it: Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256)")

    message = b"Transfer $500 to account #1189."
    keys = AuthenticatedKeyPair.generate()
    blob = encrypt_and_authenticate(message, keys)
    print(f"Plaintext: {message.decode()}")
    preview("ciphertext||tag", blob)

    print("\nRepeating Case A's early-block bit flip against this authenticated blob...")
    tampered = bytearray(blob)
    tampered[20] ^= 0xFF
    try:
        verify_and_decrypt(bytes(tampered), keys)
        print("  -> Decrypted without error (this should not happen).")
    except ValueError as exc:
        print(f"  -> Rejected before AES ever ran: {exc}")
        print("  -> The exact tamper that slipped past plain CBC in Case A is now")
        print("     caught 100% of the time, anywhere in the ciphertext.")


# ------------------------------------------------------------------------- 3
def demo_xor_weakness() -> None:
    header("3) XOR cipher: why key length and reuse matter")

    message = b"the quick brown fox jumps over the lazy dog and keeps on running"
    weak_key = b"k"  # a single repeated byte -- the worst realistic case

    ciphertext = xor_encrypt(message, weak_key)
    preview("XOR ciphertext (single-byte key)", ciphertext)

    recovered_key, recovered_plain, score = break_single_byte_xor(ciphertext)
    print(f"\nBrute-forcing all 256 possible single-byte keys by letter-frequency score...")
    print(f"  -> Recovered key : {recovered_key!r} (0x{recovered_key:02x})")
    print(f"  -> Recovered text: {recovered_plain.decode()}")
    print(f"  -> Matches the real plaintext: {recovered_plain == message}")
    print("  -> This took under a second with no knowledge of the key at all --")
    print("     the mathematical gap between this and AES-256's 2^256 keyspace")
    print("     is the entire point of this demonstration.")


# ------------------------------------------------------------------------- 4
def demo_obfuscation() -> None:
    header("4) String obfuscation: hiding a literal from a quick skim")

    secret_literal = "sk_live_51Hc9f3K2example_api_key_do_not_hardcode"
    print(f"Original string literal: {secret_literal}")

    hexed = to_hex(secret_literal.encode())
    based = to_base64(secret_literal.encode())
    print(f"Hex-encoded   : {hexed}")
    print(f"Base64-encoded: {based}")

    obfuscated = obfuscate_string(secret_literal, encoding="base64", junk_density=0.2)
    print(f"\nBase64 + junk tokens scattered through it:\n  {obfuscated}")

    restored = deobfuscate_string(obfuscated, encoding="base64")
    print(f"\nStripping junk and decoding recovers the original: {restored == secret_literal}")
    print("\nNOTE: anyone can reverse hex/base64 instantly, with no key at all --")
    print("      obfuscation only slows down a human skimming the code, it provides")
    print("      NO cryptographic protection. Compare the key-based security of")
    print("      step 1 (AES) against this step: that contrast is the lesson.")


# ------------------------------------------------------------------------- 5
def demo_file_encryption() -> None:
    header("5) File encryption: the same engine applied to a file on disk")

    with tempfile.TemporaryDirectory() as tmp:
        plain_path = os.path.join(tmp, "lab_report.txt")
        with open(plain_path, "w", encoding="utf-8") as fh:
            fh.write("CONFIDENTIAL LAB NOTES\nSample batch #42 passed all QC checks.\n")

        key = AES256.generate_key()
        enc_path = encrypt_file(plain_path, key)
        dec_path = decrypt_file(enc_path, key, dst_path=os.path.join(tmp, "lab_report.decrypted.txt"))

        with open(plain_path, "rb") as fh:
            original = fh.read()
        with open(enc_path, "rb") as fh:
            encrypted = fh.read()
        with open(dec_path, "rb") as fh:
            decrypted = fh.read()

        print(f"Original file : {plain_path} ({len(original)} bytes)")
        print(f"Encrypted file: {enc_path} ({len(encrypted)} bytes)")
        preview("First 32 bytes of encrypted file", encrypted[:32])
        print(f"Decrypted file: {dec_path} ({len(decrypted)} bytes)")
        print(f"Round-trip matches original: {decrypted == original}")
        print("\n(Temporary files are created in an OS temp directory and removed")
        print(" automatically when this demo finishes -- nothing is left on disk.)")


def main() -> None:
    c = make_colorizer(supports_color(sys.stdout))
    print(render_banner(__version__, c))
    print("For academic / defensive-security study only. See README.md.")
    demo_aes_cbc()
    demo_authenticated_fix()
    demo_xor_weakness()
    demo_obfuscation()
    demo_file_encryption()
    header("Done")
    print("All five demonstrations completed. Explore crypto_engine/ to read")
    print("the heavily-commented source behind each one.\n")


if __name__ == "__main__":
    main()
