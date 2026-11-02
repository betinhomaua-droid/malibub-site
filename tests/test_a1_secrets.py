import tempfile
import base64
import unittest
from pathlib import Path
from a1_signing import SignatureConfigurationError
from a1_secrets import load_a1_credentials


class A1SecretTests(unittest.TestCase):
    def test_missing_configuration_fails_closed(self):
        with self.assertRaises(SignatureConfigurationError):
            load_a1_credentials(certificate_path="", password="")

    def test_reads_private_file_without_printing_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.pfx"
            path.write_bytes(b"test-pfx-fixture")
            self.assertEqual(
                load_a1_credentials(certificate_path=str(path), password="test-pass"),
                (b"test-pfx-fixture", "test-pass"),
            )

    def test_reads_base64_secret_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "malibub_a1.pfx.b64"
            path.write_bytes(base64.b64encode(b"test-pfx-fixture"))
            self.assertEqual(
                load_a1_credentials(certificate_path=str(path), password="test-pass"),
                (b"test-pfx-fixture", "test-pass"),
            )

    def test_rejects_invalid_base64_secret_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "malibub_a1.pfx.b64"
            path.write_text("not valid !")
            with self.assertRaises(SignatureConfigurationError):
                load_a1_credentials(certificate_path=str(path), password="test-pass")

    def test_relative_path_is_rejected(self):
        with self.assertRaises(SignatureConfigurationError):
            load_a1_credentials(certificate_path="test.pfx", password="test-pass")

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "real.pfx"
            path.write_bytes(b"test")
            alias = Path(folder) / "alias.pfx"
            alias.symlink_to(path)
            with self.assertRaises(SignatureConfigurationError):
                load_a1_credentials(certificate_path=str(alias), password="test-pass")


if __name__ == "__main__":
    unittest.main()
