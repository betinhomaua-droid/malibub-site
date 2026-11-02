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

    def test_signed_delivery_precedes_legacy_pdf_generation(self):
        start = self.source.index('def result_pdf(eid):')
        block = self.source[start:]
        self.assertLess(block.index('signed_version=SignedReport.query'),
                        block.index('from reportlab.lib.pagesizes import A4'))
        self.assertLess(block.index('if os.getenv("MALIBUB_A1_SIGNING_ENABLED","").lower()=="true":'),
                        block.index('from reportlab.lib.pagesizes import A4'))


if __name__ == "__main__":
    unittest.main()
