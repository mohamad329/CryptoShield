# CryptoShield

**Educational Cryptography & Obfuscation Toolkit** — a from-scratch, dependency-free Python implementation of AES-256, built to make the *mathematics* of encryption, the *limits* of obfuscation, and the *difference between the two* fully transparent and inspectable.

> **Academic scope notice:** This project is built for learning defensive security concepts — data confidentiality, integrity, and the reverse-engineering resistance obfuscation provides. The AES-256 implementation here is written in pure Python for readability, is **not constant-time**, and must never replace a vetted library (`cryptography`, OpenSSL) in a real system. See [Limitations & Responsible Use](#limitations--responsible-use).

## Why this project exists

Most tutorials either wrap `pycryptodome` in three lines (hiding every interesting detail) or dump the AES spec as dense pseudocode. This project does neither: every mathematical step — the S-box substitution, the GF(2⁸) field arithmetic inside MixColumns, the key schedule — is written out in plain Python with a comment explaining *why* that step exists, not just *what* it does. It also deliberately sits a cipher (AES), a broken cipher (XOR), and non-cryptographic encoding (hex/Base64 + junk data) next to each other, so the security gap between them is something you can run and see, not just read about.

## Directory structure

```
CryptoShield/
├── Crypto_Engine.py          # CLI front-end (the tool you run)
├── Main_Demo.py               # Proof-of-Concept walkthrough (the tool you read)
├── crypto_engine/             # The engine itself — one concept per file
│   ├── __init__.py
│   ├── aes.py                  # AES-256 from scratch (FIPS-197) + CBC mode
│   ├── xor_cipher.py           # Repeating-key XOR + a cryptanalysis demo
│   ├── obfuscator.py           # Hex/Base64 encoding + junk-data insertion
│   ├── authenticated.py        # Encrypt-then-MAC (fixes CBC's integrity gap)
│   └── file_crypto.py          # AES applied to whole files on disk
├── tests/                      # 22 unit tests (NIST test vector included)
│   ├── test_aes.py
│   └── test_other.py
├── .github/workflows/ci.yml    # Runs the test suite on Linux/Windows/macOS
├── pyproject.toml
├── LICENSE
├── CHANGELOG.md
└── README.md
```

## Components

### 1. Encryption engine (`crypto_engine/aes.py`, `xor_cipher.py`)

- **AES-256**, implemented directly from the FIPS-197 specification: the S-box, the 14-round key schedule (`Nk=8`), SubBytes/ShiftRows/MixColumns/AddRoundKey, and their exact inverses for decryption. Validated against the **official NIST test vector** (see `tests/test_aes.py`) so you can trust the arithmetic is correct, not just "looks plausible."
- **CBC (Cipher Block Chaining) mode** with a random IV per message and PKCS#7 padding, so identical plaintext blocks never produce identical ciphertext (the classic failure of ECB mode).
- **XOR cipher**, included deliberately as the "what NOT to do" baseline. `break_single_byte_xor()` is a working frequency-analysis attack that recovers a single-byte key in well under a second — a concrete demonstration of why key length and cipher design matter mathematically, not just by reputation.

### 2. String obfuscation (`crypto_engine/obfuscator.py`)

- Encodes strings as **Hex** or **Base64**.
- Scatters reversible, marker-wrapped **junk tokens** through the encoded text (`insert_junk` / `strip_junk`) to make a secret literal harder to spot while skimming a disassembly or hex dump.
- The module's docstring is explicit that this is **not encryption**: anyone can reverse hex/Base64 instantly with no key at all. It only raises the *time cost* of manual reverse engineering, layered **on top of** real encryption — never as a substitute for it.

### 3. Integrity: Encrypt-then-MAC (`crypto_engine/authenticated.py`)

`Main_Demo.py` doesn't just claim CBC has integrity limits — it proves it, then fixes it:

- **Case A** flips a bit in an early ciphertext block and shows AES-CBC decrypts it *without error*, silently returning corrupted plaintext (CBC's well-known "malleability").
- **Case B** flips a bit in the final block and shows the same tamper happens to break PKCS#7 padding — catching it by luck of position, not by design.
- `authenticated.py` then wraps AES-256-CBC with **HMAC-SHA256** in the standard Encrypt-then-MAC construction (two independent keys, constant-time tag comparison via `hmac.compare_digest`), and the demo repeats Case A against it to show the exact same tamper is now rejected before AES ever runs.

### 4. Demo runner (`Main_Demo.py`)

A five-part, fully narrated proof of concept:

1. AES-256-CBC round trip (confidentiality)
2. What plain CBC does and doesn't catch, then the Encrypt-then-MAC fix (integrity)
3. XOR cipher + live key recovery (why "any encryption" ≠ "secure encryption")
4. String obfuscation walkthrough (hex/Base64 + junk data, and its real limits)
5. Whole-file encryption/decryption using the same AES engine

Every step prints the intermediate bytes so you can see the data change shape, not just a final "OK".

### 5. CLI tool (`Crypto_Engine.py`)

A single entry point for interactive use:

```bash
# Generate a random AES-256 key
python Crypto_Engine.py genkey --out secret.key

# Encrypt / decrypt a string (base64 in/out)
python Crypto_Engine.py encrypt-text "hello world" --key-file secret.key
python Crypto_Engine.py decrypt-text "<base64-ciphertext>" --key-file secret.key

# Encrypt / decrypt a file
python Crypto_Engine.py encrypt-file report.txt --key-file secret.key
python Crypto_Engine.py decrypt-file report.txt.enc --key-file secret.key

# Encrypt-then-MAC (recommended over plain encrypt-text for anything that matters)
python Crypto_Engine.py auth-genkeys --out-prefix secret
python Crypto_Engine.py auth-encrypt "transfer confirmed" \
    --enc-key-hex <hex> --mac-key-hex <hex>
python Crypto_Engine.py auth-decrypt "<base64-blob>" \
    --enc-key-hex <hex> --mac-key-hex <hex>

# XOR cipher and its break
python Crypto_Engine.py xor "attack at dawn" --key k
python Crypto_Engine.py xor-break "<base64-ciphertext>"

# String obfuscation
python Crypto_Engine.py obfuscate "sk_live_51Hc9f3K2example" --encoding base64 --density 0.2
python Crypto_Engine.py deobfuscate "<obfuscated-string>" --encoding base64
```

Run `python Crypto_Engine.py --help` or `python Crypto_Engine.py <command> --help` for full option lists.
Pass `--no-banner` (and/or `--no-color`) **before** the subcommand to suppress the startup banner, e.g. `python Crypto_Engine.py --no-banner genkey`.

## Installation

Zero third-party dependencies — only the Python 3.9+ standard library.

```bash
git clone https://github.com/mohamad329/Mo-Crypto.git
cd Mo-Crypto
python Main_Demo.py          # run the walkthrough immediately, no install needed
```

To install the test tooling:

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Example output (abridged)

```
1) AES-256-CBC: confidentiality in memory
Plaintext (what we want to protect):
  Operation Nightingale launches at 04:00. Rally point: Hangar 9.
Ciphertext (IV + encrypted blocks): 9533bc0e28a2bd89...
Decrypted with the correct key -> matches original: True

2) Integrity check: what CBC does and does NOT catch on its own
Case A -- flip one bit in an EARLY ciphertext block, then decrypt:
  -> No exception was raised. Recovered bytes: b'H\x8f\xc3...'
Case B -- flip one bit in the LAST ciphertext block, then decrypt:
  -> Rejected: Invalid padding -- wrong key, corrupted data, or tampering

3) XOR cipher: why key length and reuse matter
  -> Recovered key : 107 (0x6b)
  -> Matches the real plaintext: True
```

## Limitations & responsible use

- **Not constant-time.** The pure-Python AES here branches and indexes based on secret data, so its execution time can in principle leak information through timing side-channels. This is acceptable for a teaching tool run locally; it is not acceptable for a networked service handling real secrets.
- **Educational, not audited.** This code has not undergone the kind of formal cryptographic review that libraries like OpenSSL have. Use `cryptography` or `pycryptodome` for anything beyond learning.
- **No key management system.** `save_key`/`load_key` write raw key bytes to disk with best-effort file permissions — fine for a lab exercise, unacceptable for production (use a KMS or hardware security module instead).
- **Obfuscation is not security.** As the project itself demonstrates, hex/Base64/junk-data techniques only cost a reverse engineer time, never cryptographic effort. Treat `obfuscator.py` purely as a case study, not a defense.
- **Scope.** Intended for authorized academic exercises, CTF-style practice, and personal study of applied cryptography. Do not use it to protect data you cannot afford to lose, or to conceal information from parties who have a legitimate right to it.

## Roadmap

- [ ] AES-GCM (authenticated encryption in a single primitive, replacing the separate HMAC step)
- [ ] Constant-time S-box lookup variant, with benchmarks against the current table-lookup version
- [ ] RSA key exchange module for a hybrid encryption demo
- [ ] Web-based interactive visualizer of the AES round structure

## License

MIT — see [LICENSE](LICENSE).
