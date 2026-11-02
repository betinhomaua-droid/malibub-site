import unittest
from types import SimpleNamespace
from io import BytesIO
from pypdf import PdfWriter


def sample_pdf():
    out = BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=595, height=842)
    writer.write(out)
    return out.getvalue()
from a1_orchestration import sign_and_release


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.exam = SimpleNamespace(id=7, status="A conferir")

    def pipeline(self, **kwargs):
        self.events.append("sign")
        self.assertEqual(kwargs["pdf_bytes"], sample_pdf())
        self.assertTrue(kwargs["authorized"])
        return {"key": "signed-reports/7/test.pdf", "sha256": "a"*64, "size": 100}

    def transaction(self, **kwargs):
        self.events.append("commit")
        self.assertEqual(kwargs["artifact"]["size"], 100)
        return "released"

    def run_flow(self, **changes):
        args = dict(pdf_builder=lambda: self._build(), model=object(),
                    db_session=object(), exam=self.exam, signer_name="Radiologista",
                    storage_client=object(), bucket="private", validation_context=object(),
                    authorized=True, signing_pipeline=self.pipeline, transaction=self.transaction)
        args.update(changes)
        return sign_and_release(**args)

    def _build(self):
        self.events.append("pdf")
        return sample_pdf()

    def test_signing_precedes_release(self):
        self.assertEqual(self.run_flow(), "released")
        self.assertEqual(self.events, ["pdf", "sign", "commit"])

    def test_unauthorized_never_builds(self):
        with self.assertRaises(PermissionError):
            self.run_flow(authorized=False)
        self.assertEqual(self.events, [])

    def test_released_exam_never_builds(self):
        self.exam.status = "Liberado"
        with self.assertRaises(ValueError):
            self.run_flow()
        self.assertEqual(self.events, [])

    def test_missing_signer_never_builds(self):
        with self.assertRaises(ValueError):
            self.run_flow(signer_name="  ")
        self.assertEqual(self.events, [])

    def test_missing_trust_context_never_builds(self):
        with self.assertRaises(ValueError):
            self.run_flow(validation_context=None)
        self.assertEqual(self.events, [])

    def test_missing_storage_never_builds(self):
        with self.assertRaises(ValueError):
            self.run_flow(storage_client=None)
        self.assertEqual(self.events, [])

    def test_builder_failure_never_signs_or_commits(self):
        def broken():
            self.events.append("pdf")
            raise RuntimeError("PDF failure")
        with self.assertRaises(RuntimeError):
            self.run_flow(pdf_builder=broken)
        self.assertEqual(self.events, ["pdf"])

    def test_invalid_pdf_output_never_signs_or_commits(self):
        for invalid in (None, "", "not bytes", b"", b"not a pdf", bytearray(b"%PDF-test")):
            with self.subTest(invalid=repr(invalid)):
                self.events.clear()
                with self.assertRaises(Exception):
                    self.run_flow(pdf_builder=lambda invalid=invalid: invalid)
                self.assertEqual(self.events, [])

    def test_transaction_failure_occurs_only_after_signed_artifact(self):
        def broken_transaction(**kwargs):
            self.events.append("commit")
            raise RuntimeError("database commit failure")
        with self.assertRaisesRegex(RuntimeError, "database commit failure"):
            self.run_flow(transaction=broken_transaction)
        self.assertEqual(self.events, ["pdf", "sign", "commit"])

    def test_malformed_pdf_with_valid_header_never_signs(self):
        with self.assertRaises(Exception):
            self.run_flow(pdf_builder=lambda: b"%PDF-1.7\\ntruncated")
        self.assertEqual(self.events, [])

    def test_encrypted_pdf_never_signs(self):
        out = BytesIO()
        writer = PdfWriter()
        writer.add_blank_page(width=595, height=842)
        writer.encrypt("password")
        writer.write(out)
        with self.assertRaises(Exception):
            self.run_flow(pdf_builder=lambda: out.getvalue())
        self.assertEqual(self.events, [])

    def test_pipeline_receives_exact_generated_pdf(self):
        pdf = sample_pdf()
        def pipeline(**kwargs):
            self.events.append("sign")
            self.assertIs(kwargs["pdf_bytes"], pdf)
            self.assertEqual(kwargs["exam_id"], self.exam.id)
            return {"key": "signed-reports/7/test.pdf", "sha256": "a"*64, "size": 100}
        self.assertEqual(self.run_flow(pdf_builder=lambda: (self.events.append("pdf"), pdf)[1],
                                       signing_pipeline=pipeline), "released")
        self.assertEqual(self.events, ["pdf", "sign", "commit"])

    def test_signing_failure_never_commits(self):
        def broken(**kwargs):
            self.events.append("sign")
            raise RuntimeError("certificate failure")
        with self.assertRaises(RuntimeError):
            self.run_flow(signing_pipeline=broken)
        self.assertEqual(self.events, ["pdf", "sign"])


if __name__ == "__main__":
    unittest.main()
