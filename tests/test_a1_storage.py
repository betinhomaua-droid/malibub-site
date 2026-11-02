import io
import unittest
from a1_storage import persist_signed_pdf
from a1_signing import SignatureValidationError


class FakeStorage:
    def __init__(self, corrupt=False, fail=False):
        self.objects = {}
        self.corrupt = corrupt
        self.fail = fail

    def put_object(self, Bucket, Key, Body, **kwargs):
        if self.fail:
            raise OSError("storage down")
        if kwargs.get("IfNoneMatch") != "*":
            raise AssertionError("Signed PDF must use conditional create-only upload")
        if (Bucket, Key) in self.objects:
            raise FileExistsError("precondition failed")
        self.objects[(Bucket, Key)] = Body.read()

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)

    def get_object(self, Bucket, Key):
        data = self.objects[(Bucket, Key)]
        return {"Body": io.BytesIO(data + b"tampered" if self.corrupt else data)}


class SignedStorageTests(unittest.TestCase):
    def test_write_and_readback(self):
        store = FakeStorage()
        pdf = b"%PDF-1.7 test document"
        info = persist_signed_pdf(store, "private-bucket", 3, pdf)
        self.assertEqual(info["size"], len(pdf))
        self.assertEqual(store.objects[("private-bucket", info["key"])], pdf)

    def test_new_key_for_each_version(self):
        store = FakeStorage()
        a = persist_signed_pdf(store, "private-bucket", 3, b"%PDF-1.7 a")
        b = persist_signed_pdf(store, "private-bucket", 3, b"%PDF-1.7 b")
        self.assertNotEqual(a["key"], b["key"])

    def test_signed_upload_requires_create_only_precondition(self):
        store = FakeStorage()
        persist_signed_pdf(store, "private-bucket", 3, b"%PDF-1.7 protected")
        self.assertEqual(len(store.objects), 1)

    def test_invalid_boolean_exam_id_rejected(self):
        with self.assertRaises(ValueError):
            persist_signed_pdf(FakeStorage(), "private-bucket", True, b"%PDF-1.7")

    def test_storage_failure_blocks_release(self):
        with self.assertRaises(SignatureValidationError):
            persist_signed_pdf(FakeStorage(fail=True), "private-bucket", 3, b"%PDF-1.7")

    def test_corrupted_readback_blocks_release(self):
        store = FakeStorage(corrupt=True)
        with self.assertRaises(SignatureValidationError):
            persist_signed_pdf(store, "private-bucket", 3, b"%PDF-1.7")
        self.assertEqual(store.objects, {})


if __name__ == "__main__":
    unittest.main()
