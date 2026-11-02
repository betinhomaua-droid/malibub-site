import hashlib
import io
import unittest
from types import SimpleNamespace
from a1_delivery import read_signed_report, read_signed_version
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



class VersionDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.original = b"%PDF-1.7 original"
        self.revised = b"%PDF-1.7 revised"
        self.rows = [
            SimpleNamespace(exam_id=7, version=1, storage_key="signed-reports/7/first.pdf",
                            sha256=hashlib.sha256(self.original).hexdigest(), size=len(self.original)),
            SimpleNamespace(exam_id=7, version=2, storage_key="signed-reports/7/second.pdf",
                            sha256=hashlib.sha256(self.revised).hexdigest(), size=len(self.revised)),
        ]

    def read(self, exam_id, version=None):
        rows = self.rows
        class Query:
            filters = {}
            latest = False
            def filter_by(self, **kwargs):
                self.filters.update(kwargs)
                return self
            def order_by(self, *args):
                self.latest = True
                return self
            def first(self):
                matching = [r for r in rows if all(getattr(r, k) == v for k, v in self.filters.items())]
                if self.latest and matching:
                    return max(matching, key=lambda r: r.version)
                return matching[0] if matching else None
        class Session:
            def query(self, model):
                return Query()
        class Client:
            def get_object(self, Bucket, Key):
                payload = self_original if Key.endswith("first.pdf") else self_revised
                return {"Body": io.BytesIO(payload)}
        self_original, self_revised = self.original, self.revised
        model = SimpleNamespace(version=SimpleNamespace(desc=lambda: None))
        return read_signed_version(Client(), "private", model=model,
                                   db_session=Session(), exam_id=exam_id, version=version)

    def test_latest_returns_revised_pdf(self):
        self.assertEqual(self.read(7), self.revised)

    def test_original_remains_accessible_by_version(self):
        self.assertEqual(self.read(7, 1), self.original)

    def test_unknown_version_is_rejected(self):
        with self.assertRaises(SignatureValidationError):
            self.read(7, 3)

    def test_other_exam_is_rejected(self):
        with self.assertRaises(SignatureValidationError):
            self.read(8, 1)

if __name__ == "__main__":
    unittest.main()
