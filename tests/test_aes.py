import unittest

from crypto_engine.aes import (AES256, BLOCK_SIZE, decrypt_block, encrypt_block,
                               _key_expansion, pkcs7_pad, pkcs7_unpad)


class NistVectorTests(unittest.TestCase):
    """FIPS-197 Appendix C.3: the official AES-256 test vector."""

    def test_official_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        round_keys = _key_expansion(key)
        self.assertEqual(encrypt_block(plaintext, round_keys), expected)
        self.assertEqual(decrypt_block(expected, round_keys), plaintext)


class PaddingTests(unittest.TestCase):
    def test_pad_unpad_roundtrip(self):
        for length in range(0, 40):
            data = bytes(range(length % 256)) * ((length // 256) + 1)
            data = data[:length]
            padded = pkcs7_pad(data)
            self.assertEqual(len(padded) % BLOCK_SIZE, 0)
            self.assertEqual(pkcs7_unpad(padded), data)

    def test_full_extra_block_when_already_aligned(self):
        data = b"A" * 16
        padded = pkcs7_pad(data)
        self.assertEqual(len(padded), 32)  # a full block of padding is added

    def test_rejects_bad_padding(self):
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"A" * 15 + b"\x05")  # pad byte says 5, but bytes don't match
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"A" * 10)  # not a multiple of block size


class CbcModeTests(unittest.TestCase):
    def test_roundtrip_various_lengths(self):
        key = AES256.generate_key()
        engine = AES256(key)
        for length in (0, 1, 15, 16, 17, 63, 64, 65, 1000):
            msg = bytes((i * 7) % 256 for i in range(length))
            ct = engine.encrypt(msg)
            self.assertEqual(engine.decrypt(ct), msg)

    def test_same_plaintext_different_ciphertext(self):
        """A fresh random IV each call must make identical plaintexts produce
        different ciphertexts -- this is the whole point of using an IV."""
        key = AES256.generate_key()
        engine = AES256(key)
        msg = b"identical message"
        self.assertNotEqual(engine.encrypt(msg), engine.encrypt(msg))

    def test_wrong_key_fails_or_garbles(self):
        key_a, key_b = AES256.generate_key(), AES256.generate_key()
        ct = AES256(key_a).encrypt(b"top secret message of correct block length!!!!")
        with self.assertRaises(ValueError):
            AES256(key_b).decrypt(ct)

    def test_rejects_short_or_misaligned_ciphertext(self):
        engine = AES256(AES256.generate_key())
        with self.assertRaises(ValueError):
            engine.decrypt(b"short")
        with self.assertRaises(ValueError):
            engine.decrypt(b"A" * 20)  # not IV-aligned

    def test_key_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            AES256(b"too-short-key")

    def test_generated_keys_are_unique(self):
        keys = {AES256.generate_key() for _ in range(20)}
        self.assertEqual(len(keys), 20)


if __name__ == "__main__":
    unittest.main()
