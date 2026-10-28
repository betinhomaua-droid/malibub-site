import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1].joinpath("app.py").read_text(encoding="utf-8")


class ClinicalEditorStaticTests(unittest.TestCase):
    def test_clinical_notes_schema_and_migrations(self):
        self.assertIn('clinical_notes=db.Column(db.Text,default="")', SOURCE)
        self.assertIn("ALTER TABLE exam ADD COLUMN IF NOT EXISTS clinical_notes TEXT", SOURCE)
        self.assertIn("ALTER TABLE exam ADD COLUMN clinical_notes TEXT", SOURCE)

    def test_clinical_notes_saved_in_both_submission_paths(self):
        self.assertIn('data.get("clinical_notes","")', SOURCE)
        self.assertIn('request.form.get("clinical_notes","")', SOURCE)

    def test_pdf_indication_and_internal_notes_separated(self):
        pdf_code = SOURCE.split('def result_pdf(eid):', 1)[1]
        self.assertIn('e.observation', pdf_code)
        self.assertNotIn('e.clinical_notes', pdf_code)

    def test_font_size_options_and_reload(self):
        for pt in (8, 10, 12, 14, 18):
            self.assertRegex(SOURCE, rf'<option value="{pt}"(?: selected)?>{pt} pt</option>')
        self.assertIn("rich.querySelectorAll('span[data-size]')", SOURCE)


if __name__ == "__main__":
    unittest.main()
