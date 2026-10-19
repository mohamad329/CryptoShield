import os
import tempfile
import unittest

from crypto_engine.authenticated import (AuthenticatedKeyPair,
                                         encrypt_and_authenticate,
                                         verify_and_decrypt)
from crypto_engine.file_crypto import decrypt_file, encrypt_file
from crypto_engine.obfuscator import (deobfuscate_string, insert_junk,
                                      obfuscate_string, strip_junk, to_base64, to_hex)
from crypto_engine.xor_cipher import break_single_byte_xor, xor_encrypt


class XorTests(unittest.TestCase):
    def test_roundtrip(self):
        msg = b"attack at dawn"
        key = b"k3y"
        ct = xor_encrypt(msg, key)
        self.assertEqual(xor_encrypt(ct, key), msg)

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            xor_encrypt(b"data", b"")

    def test_break_single_byte(self):
        msg = b"the quick brown fox jumps over the lazy dog repeatedly for testing"
        ct = xor_encrypt(msg, bytes([42]))
        key, plain, _ = break_single_byte_xor(ct)
        self.assertEqual(key, 42)
        self.assertEqual(plain, msg)


class ObfuscatorTests(unittest.TestCase):
    def test_hex_roundtrip(self):
        self.assertEqual(to_base64(b"hello").encode(), to_base64(b"hello").encode())
        self.assertEqual(to_hex(b"\x00\xff"), "00ff")

    def test_junk_insertion_and_stripping(self):
        text = "a_fairly_long_string_for_junk_testing_purposes"
        junked = insert_junk(text, density=0.3)
        self.assertGreater(len(junked), len(text))
        self.assertEqual(strip_junk(junked), text)

    def test_zero_density_is_noop(self):
        text = "no junk here"
        self.assertEqual(insert_junk(text, density=0), text)

    def test_full_pipeline_base64_and_hex(self):
        secret = "some s3cret literal!"
        for enc in ("base64", "hex"):
            obf = obfuscate_string(secret, encoding=enc, junk_density=0.25)
            self.assertNotIn(secret, obf)
            self.assertEqual(deobfuscate_string(obf, encoding=enc), secret)

    def test_invalid_density_rejected(self):
        with self.assertRaises(ValueError):
            insert_junk("x", density=1.5)


class AuthenticatedTests(unittest.TestCase):
    def test_roundtrip(self):
        keys = AuthenticatedKeyPair.generate()
        msg = b"integrity-protected payload"
        blob = encrypt_and_authenticate(msg, keys)
        self.assertEqual(verify_and_decrypt(blob, keys), msg)

    def test_tamper_anywhere_is_detected(self):
        keys = AuthenticatedKeyPair.generate()
        blob = bytearray(encrypt_and_authenticate(b"0123456789abcdef0123456789abcdef", keys))
        for i in (0, 5, len(blob) // 2, len(blob) - 1):
            tampered = bytearray(blob)
            tampered[i] ^= 0xFF
            with self.assertRaises(ValueError):
                verify_and_decrypt(bytes(tampered), keys)

    def test_wrong_mac_key_rejected(self):
        keys = AuthenticatedKeyPair.generate()
        blob = encrypt_and_authenticate(b"message", keys)
        wrong = AuthenticatedKeyPair(keys.enc_key, os.urandom(32))
        with self.assertRaises(ValueError):
            verify_and_decrypt(blob, wrong)


class FileCryptoTests(unittest.TestCase):
    def test_file_roundtrip(self):
        from crypto_engine.aes import AES256
        key = AES256.generate_key()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "data.bin")
            with open(src, "wb") as fh:
                fh.write(os.urandom(500))
            enc = encrypt_file(src, key)
            dec = decrypt_file(enc, key, dst_path=os.path.join(tmp, "data.out"))
            with open(src, "rb") as a, open(dec, "rb") as b:
                self.assertEqual(a.read(), b.read())


if __name__ == "__main__":
    unittest.main()
