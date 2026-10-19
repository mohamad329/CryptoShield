import unittest

from crypto_engine.banner import render_banner


class BannerTests(unittest.TestCase):
    def test_contains_name_and_version(self):
        out = render_banner("9.9.9", lambda text, code: text)
        self.assertIn("CryptoShield v9.9.9", out)
        self.assertGreater(len(out.splitlines()), 15)

    def test_plain_when_color_disabled(self):
        out = render_banner("1.0.0", lambda text, code: text)
        self.assertNotIn("\033[", out)


if __name__ == "__main__":
    unittest.main()
