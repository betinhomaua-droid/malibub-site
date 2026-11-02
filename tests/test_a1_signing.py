import unittest
from a1_signing import sign_pdf_pades, SignatureConfigurationError


class A1SigningTests(unittest.TestCase):
    def test_rejects_non_pdf(self):
        with self.assertRaises(ValueError):
            sign_pdf_pades(b"not a PDF", b"cert", "password")

    def test_rejects_missing_certificate(self):
        with self.assertRaises(SignatureConfigurationError):
            sign_pdf_pades(b"%PDF-1.7", b"", "password")

    def test_rejects_missing_password(self):
        with self.assertRaises(SignatureConfigurationError):
            sign_pdf_pades(b"%PDF-1.7", b"cert", "")


if __name__ == "__main__":
    unittest.main()
