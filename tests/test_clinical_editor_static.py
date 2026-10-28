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

    def test_continuation_pdf_has_progress_guard(self):
        self.assertIn("continuation_start_index=index", SOURCE)
        self.assertIn("if index<len(rendered) and index==continuation_start_index:", SOURCE)
        self.assertNotIn("if index<len(rendered) and y==height-47*mm:", SOURCE)

    def test_custom_pdf_uses_clinic_configured_margins(self):
        self.assertIn("top_margin_mm=max(20,min(120,int(clinic.report_top_mm or 72)))", SOURCE)
        self.assertIn("bottom_margin_mm=max(15,min(100,int(clinic.report_bottom_mm or 42)))", SOURCE)
        self.assertIn("y=height-top_margin_mm*mm", SOURCE)
        self.assertIn("min_y=bottom_margin_mm*mm", SOURCE)

    def test_continuation_indication_wraps_without_truncation(self):
        self.assertIn('indication_para.wrap(width-44*mm,200*mm)', SOURCE)
        self.assertIn('indication_para.drawOn(cv,22*mm,indication_top-indication_height)', SOURCE)
        self.assertNotIn("(e.observation or '')[:95]", SOURCE)

    def test_tmj_respects_active_pdf_template(self):
        self.assertIn('if is_tmj_model and not has_pdf_model:', SOURCE)
        self.assertIn('if model_path and model_path.exists() and model_path.suffix.lower()==".pdf":', SOURCE)

    def test_font_size_options_and_reload(self):
        for pt in (8, 10, 12, 14, 18):
            self.assertRegex(SOURCE, rf'<option value="{pt}"(?: selected)?>{pt} pt</option>')
        self.assertIn("rich.querySelectorAll('span[data-size]')", SOURCE)


if __name__ == "__main__":
    unittest.main()
