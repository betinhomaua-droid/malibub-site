"""Regression guard: A1-required approval must never fall through to legacy release.

These static tests intentionally do not load app.py, its database, or any patient data.
They protect the current fail-closed boundary until the signing transaction is wired.
"""
from pathlib import Path
import unittest


class A1ApprovalGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")

    def test_a1_guard_precedes_legacy_release(self):
        start = self.source.index('def report(eid):')
        end = self.source.index(' imgs=', start)
        block = self.source[start:end]
        guard = block.index('if os.getenv("MALIBUB_A1_SIGNING_ENABLED", "").lower()=="true":')
        release = block.index('e.status="Liberado"')
        self.assertLess(guard, release)
        self.assertIn('return redirect(url_for("report",eid=e.id))', block[guard:release])

    def test_preview_never_changes_release_status_or_flushes(self):
        start = self.source.index("def preview_report_pdf(eid):")
        end = self.source.index("\ndef br_date(", start)
        block = self.source[start:end]
        self.assertIn("SignedReport.query.filter_by(exam_id=e.id)", block)
        self.assertIn("build_legacy_report_pdf_bytes(e)", block)
        self.assertNotIn('e.status="Liberado"', block)
        self.assertNotIn("db.session.flush()", block)
        self.assertNotIn("db.session.commit()", block)
        self.assertNotIn("result_pdf(eid)", block)

    def test_signed_exam_cannot_fall_back_to_unsigned_release(self):
        start = self.source.index("def report(eid):")
        end = self.source.index(" imgs=", start)
        block = self.source[start:end]
        signed_guard = block.index("SignedReport.query.filter_by(exam_id=e.id).first()")
        release = block.index('e.status="Liberado"')
        self.assertLess(signed_guard, release)
        self.assertIn('return redirect(url_for("report",eid=e.id))', block[signed_guard:release])

    def test_signed_delivery_precedes_legacy_pdf_generation(self):
        start = self.source.index('def result_pdf(eid):')
        block = self.source[start:]
        self.assertLess(block.index('signed_version=SignedReport.query'),
                        block.index('return render_legacy_report_pdf_response(e)'))
        self.assertLess(block.index('if os.getenv("MALIBUB_A1_SIGNING_ENABLED","").lower()=="true":'),
                        block.index('return render_legacy_report_pdf_response(e)'))


if __name__ == "__main__":
    unittest.main()
