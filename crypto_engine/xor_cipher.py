"""
xor_cipher.py -- A repeating-key XOR cipher, included for comparison with AES.

WHY INCLUDE A "WEAK" CIPHER IN A SECURITY PROJECT?
----------------------------------------------------
Seeing a strong and a weak cipher side by side is the fastest way to learn
*why* AES's extra complexity (S-boxes, multiple rounds, GF(2^8) math) is
necessary. XOR is include here purely to demonstrate -- and let a student
empirically break -- the two classic failures below. It must never be used
to protect real data.

THE MATH
--------
XOR encryption repeats a key over and over and XORs it byte-by-byte with
the plaintext: ciphertext[i] = plaintext[i] ^ key[i % len(key)]. Because
XOR is its own inverse, decryption is the exact same operation run again.

WHY IT IS INSECURE
-------------------
1. Key reuse leaks structure: XORing two ciphertexts that were produced
   with the same key cancels the key out entirely --
   (P1^K) ^ (P2^K) = P1^P2 -- which is why real protocols never reuse a
   one-time-style key.
2. Frequency analysis: if the key is shorter than the message (the normal
   case), the cipher is just a repeating Vigenere cipher over bytes. Group
   the ciphertext by key-byte position and the classic letter-frequency
   distribution of the plaintext (e.g. English text, or the 0x00 padding
   of a binary file) reappears in each group, which is enough to recover
   the key one byte at a time without ever guessing it directly.
"""

from __future__ import annotations


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt (or decrypt -- it's the same operation) `data` by repeating
    `key` across its length and XORing byte-by-byte."""
    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# XOR decryption is identical to encryption: (P ^ K) ^ K == P.
xor_decrypt = xor_encrypt


def break_single_byte_xor(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Educational attack: brute-force every possible single-byte key (only
    256 possibilities) and score each candidate plaintext by how closely
    its byte distribution matches typical English text. Returns
    (best_key, best_plaintext, confidence_score).

    This function exists to let a student PROVE to themselves that a
    single-byte (or short-key) XOR cipher offers close to zero real
    security -- it is the project's "red team" demonstration, not a
    general-purpose cryptanalysis tool."""
    # Rough relative frequency of each letter in English prose (Mayzner
    # index, simplified) used only to score how "English-like" a candidate
    # decryption looks.
    freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
        'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4,
        'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0,
        'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.1, 'z': 0.07, ' ': 13.0,
    }
    best_key, best_score, best_plain = 0, -1.0, b""
    for key in range(256):
        candidate = xor_encrypt(ciphertext, bytes([key]))
        try:
            text = candidate.decode("ascii").lower()
        except UnicodeDecodeError:
            continue
        score = sum(freq.get(ch, -2.0) for ch in text)
        if score > best_score:
            best_key, best_score, best_plain = key, score, candidate
    return best_key, best_plain, best_score
