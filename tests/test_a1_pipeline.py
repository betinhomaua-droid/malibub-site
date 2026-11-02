import os
import unittest
from unittest.mock import patch
from a1_pipeline import prepare_signed_report
from a1_signing import SignatureConfigurationError, SignatureValidationError


class PipelineTests(unittest.TestCase):
    def test_disabled_flag_blocks_before_secret_access(self):
        with patch.dict(os.environ, {"MALIBUB_A1_SIGNING_ENABLED": "false"}):
            with self.assertRaises(SignatureConfigurationError):
                prepare_signed_report(pdf_bytes=b"%PDF-1.7", exam_id=1,
                                      storage_client=object(), bucket="private",
                                      validation_context=object(), authorized=True,
                                      credentials_loader=lambda: self.fail("secret accessed"))

    def test_unauthorized_role_blocks_before_secret_access(self):
        with patch.dict(os.environ, {"MALIBUB_A1_SIGNING_ENABLED": "true"}):
            with self.assertRaises(PermissionError):
                prepare_signed_report(pdf_bytes=b"%PDF-1.7", exam_id=1,
                                      storage_client=object(), bucket="private",
                                      validation_context=object(), authorized=False,
                                      credentials_loader=lambda: self.fail("secret accessed"))

    def test_missing_trust_blocks_before_secret_access(self):
        with patch.dict(os.environ, {"MALIBUB_A1_SIGNING_ENABLED": "true"}):
            with self.assertRaises(SignatureConfigurationError):
                prepare_signed_report(pdf_bytes=b"%PDF-1.7", exam_id=1,
                                      storage_client=object(), bucket="private",
                                      validation_context=None, authorized=True,
                                      credentials_loader=lambda: self.fail("secret accessed"))

    def test_invalid_signature_never_reaches_storage(self):
        with patch.dict(os.environ, {"MALIBUB_A1_SIGNING_ENABLED": "true"}):
            with patch("a1_pipeline.sign_pdf_pades", return_value=b"%PDF-1.7 signed"):
                with patch("a1_pipeline.verify_embedded_signature", return_value=False):
                    with patch("a1_pipeline.persist_signed_pdf") as persist:
                        with self.assertRaises(SignatureValidationError):
                            prepare_signed_report(pdf_bytes=b"%PDF-1.7", exam_id=1,
                                                  storage_client=object(), bucket="private",
                                                  validation_context=object(), authorized=True,
                                                  credentials_loader=lambda: (b"test", "test"))
                        persist.assert_not_called()

    def test_untrusted_certificate_never_reaches_storage(self):
        with patch.dict(os.environ, {"MALIBUB_A1_SIGNING_ENABLED": "true"}):
            with patch("a1_pipeline.sign_pdf_pades", return_value=b"%PDF-1.7 signed"):
                with patch("a1_pipeline.verify_embedded_signature", return_value=True):
                    with patch("a1_pipeline.validate_signer_trust", return_value=False):
                        with patch("a1_pipeline.persist_signed_pdf") as persist:
                            with self.assertRaises(SignatureValidationError):
                                prepare_signed_report(pdf_bytes=b"%PDF-1.7", exam_id=1,
                                                      storage_client=object(), bucket="private",
                                                      validation_context=object(), authorized=True,
                                                      credentials_loader=lambda: (b"test", "test"))
                            persist.assert_not_called()


if __name__ == "__main__":
    unittest.main()
