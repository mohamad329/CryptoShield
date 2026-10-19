# Changelog

## 1.1.0
- Startup ASCII banner in Main_Demo.py and Crypto_Engine.py (disable with `--no-banner`, placed before the subcommand; also respects `--no-color` / `NO_COLOR`)

## 1.0.0
- AES-256 implemented from scratch (FIPS-197), verified against the official
  NIST test vector; CBC mode with PKCS#7 padding
- Repeating-key XOR cipher, plus a single-byte-key cryptanalysis demo
- String obfuscation: hex/base64 encoding + reversible junk-data insertion
- File-level encryption/decryption helpers
- Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256) authenticated encryption,
  fixing the integrity gap demonstrated in Main_Demo.py
- `Crypto_Engine.py` CLI front-end; `Main_Demo.py` five-part PoC walkthrough
- 22 unit tests, GitHub Actions CI on Linux/Windows/macOS
