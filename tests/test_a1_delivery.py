import hashlib
import io
import unittest
from a1_delivery import read_signed_report
from a1_signing import SignatureValidationError


class FakeClient:
    def __init__(self, data):
        self.data = data

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.data)}


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.pdf = b"%PDF-1.7 test signed artifact"
        self.digest = hashlib.sha256(self.pdf).hexdigest()
        self.key = "signed-reports/7/version.pdf"

    def test_delivers_exact_original_bytes(self):
        self.assertEqual(read_signed_report(FakeClient(self.pdf), "private",
                                            key=self.key, sha256=self.digest, exam_id=7), self.pdf)

    def test_rejects_other_exam_key(self):
        with self.assertRaises(SignatureValidationError):
            read_signed_report(FakeClient(self.pdf), "private", key=self.key,
                               sha256=self.digest, exam_id=8)

    def test_rejects_mutated_pdf(self):
        with self.assertRaises(SignatureValidationError):
            read_signed_report(FakeClient(self.pdf + b"modified"), "private",
                               key=self.key, sha256=self.digest, exam_id=7)

    def test_rejects_path_traversal(self):
        with self.assertRaises(SignatureValidationError):
            read_signed_report(FakeClient(self.pdf), "private",
                               key="signed-reports/7/../other.pdf", sha256=self.digest, exam_id=7)


if __name__ == "__main__":
    unittest.main()
