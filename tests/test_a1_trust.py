import tempfile
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from a1_signing import SignatureConfigurationError
from a1_trust import load_icp_brasil_validation_context


class TrustLoaderTests(unittest.TestCase):
    def test_missing_directory_fails_closed(self):
        with patch.dict("os.environ", {"MALIBUB_ICP_BRASIL_TRUST_DIR": ""}):
            with self.assertRaises(SignatureConfigurationError):
                load_icp_brasil_validation_context()

    def test_empty_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SignatureConfigurationError):
                load_icp_brasil_validation_context(anchors_dir=tmp)

    def test_invalid_anchor_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "root.pem").write_text("not a certificate")
            with self.assertRaises(SignatureConfigurationError):
                load_icp_brasil_validation_context(anchors_dir=tmp)

    def test_missing_approved_fingerprints_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "root.der").write_bytes(b"invalid")
            with patch.dict("os.environ", {"MALIBUB_ICP_BRASIL_ROOT_SHA256": ""}):
                with self.assertRaises(SignatureConfigurationError):
                    load_icp_brasil_validation_context(anchors_dir=tmp)

    def test_unapproved_root_fingerprint_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "root.der").write_bytes(b"not an approved root")
            with patch.dict("os.environ", {"MALIBUB_ICP_BRASIL_ROOT_SHA256": "a" * 64}):
                with self.assertRaises(SignatureConfigurationError):
                    load_icp_brasil_validation_context(anchors_dir=tmp)

    def test_unrelated_files_do_not_count_as_anchors(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "notes.txt").write_text("no trust roots")
            with self.assertRaises(SignatureConfigurationError):
                load_icp_brasil_validation_context(anchors_dir=tmp)


if __name__ == "__main__":
    unittest.main()
