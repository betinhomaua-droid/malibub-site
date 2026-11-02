"""Additional negative tests for immutable A1 delivery (no real patient data)."""
import hashlib
import io
import unittest

from a1_delivery import read_signed_report
from a1_signing import SignatureValidationError


class StorageClient:
    def __init__(self, data=None, error=None):
        self.data = data
        self.error = error

    def get_object(self, **kwargs):
        if self.error:
            raise self.error
        return {"Body": io.BytesIO(self.data)}


class DeliveryFailureTests(unittest.TestCase):
    def setUp(self):
        self.pdf = b"%PDF-1.7\nimmutable test artifact"
        self.digest = hashlib.sha256(self.pdf).hexdigest()
        self.key = "signed-reports/21/immutable.pdf"

    def fetch(self, client, **changes):
        args = dict(key=self.key, sha256=self.digest, exam_id=21)
        args.update(changes)
        return read_signed_report(client, "private", **args)

    def test_storage_unavailable_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(error=OSError("unavailable")))

    def test_missing_document_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(error=KeyError("missing")))

    def test_empty_document_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(b""))

    def test_non_pdf_blocks_even_when_digest_matches(self):
        data = b"not a pdf"
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(data), sha256=hashlib.sha256(data).hexdigest())

    def test_truncated_document_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf[:-1]))

    def test_boolean_exam_identifier_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf), exam_id=True)

    def test_cross_exam_key_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf), key="signed-reports/22/immutable.pdf")

    def test_nested_storage_key_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf), key="signed-reports/21/other/immutable.pdf")

    def test_recorded_size_mismatch_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf), expected_size=len(self.pdf) + 1)

    def test_invalid_recorded_size_blocks(self):
        for value in (0, -1, True, "123"):
            with self.subTest(value=value):
                with self.assertRaises(SignatureValidationError):
                    self.fetch(StorageClient(self.pdf), expected_size=value)

    def test_invalid_digest_format_blocks(self):
        with self.assertRaises(SignatureValidationError):
            self.fetch(StorageClient(self.pdf), sha256="z" * 64)

    def test_recorded_size_matches(self):
        self.assertEqual(self.fetch(StorageClient(self.pdf), expected_size=len(self.pdf)), self.pdf)

    def test_original_bytes_are_returned_unchanged(self):
        self.assertEqual(self.fetch(StorageClient(self.pdf)), self.pdf)


if __name__ == "__main__":
    unittest.main()
