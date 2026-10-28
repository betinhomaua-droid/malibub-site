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

    def test_revision_reuses_existing_financial_charge(self):
        self.assertIn('if e.status=="Revisão solicitada" and existing_revenue:', SOURCE)
        self.assertIn('amount=existing_revenue.amount', SOURCE)
        self.assertIn('if not existing_revenue:', SOURCE)

    def test_clinic_revision_request_workflow(self):
        self.assertIn('@app.route("/exam/<int:eid>/revisao",methods=["GET","POST"])', SOURCE)
        self.assertIn('Exam.query.filter_by(id=eid,clinic_id=session["uid"]).first_or_404()', SOURCE)
        self.assertIn('e.status="Revisão solicitada"', SOURCE)
        self.assertIn('revision_reason=db.Column(db.Text)', SOURCE)
        self.assertIn('if not is_radiologist and e.status=="Liberado"', SOURCE)
        self.assertIn('Revisão solicitada pela clínica', SOURCE)
        self.assertIn('e.revision_reason=None; e.revision_requested_at=None;', SOURCE)
        self.assertIn('if not existing_revenue:', SOURCE)

    def test_long_formatted_paragraph_splits_across_pages(self):
        self.assertIn("pieces=para.split(available_width,available_height)", SOURCE)
        self.assertIn("pending=pieces[1:]+pending[1:]", SOURCE)
        self.assertIn("if not pending and y>=90*mm:", SOURCE)

    def test_continuation_pdf_has_progress_guard(self):
        self.assertIn("page_progress=False", SOURCE)
        self.assertIn("if pending and not page_progress:", SOURCE)
        self.assertNotIn("if index<len(rendered) and y==height-47*mm:", SOURCE)

    def test_model_settings_warn_about_overlapping_content(self):
        self.assertIn("ao trocar de modelo, revise os valores para evitar sobreposição", SOURCE)
        self.assertIn("margens são da clínica", SOURCE)

    def test_invalid_margin_submission_is_rejected(self):
        self.assertIn('if not 20<=top_input<=120 or not 15<=bottom_input<=100:', SOURCE)
        self.assertIn('flash("Margens inválidas.', SOURCE)
        self.assertIn('except (ValueError,TypeError):', SOURCE)

    def test_signature_reserves_footer_clearance(self):
        self.assertIn("if not pending and y>=90*mm:", SOURCE)
        self.assertIn('draw_report_signature(cv,width,baseline=y-12*mm)', SOURCE)

    def test_legacy_model_margins_are_initialized_once(self):
        self.assertIn("if item.top_mm is None: item.top_mm=u.report_top_mm or 72", SOURCE)
        self.assertIn("if item.bottom_mm is None: item.bottom_mm=u.report_bottom_mm or 42", SOURCE)
        self.assertIn("u.report_top_mm=item.top_mm", SOURCE)
        self.assertIn("u.report_bottom_mm=item.bottom_mm", SOURCE)

    def test_model_specific_margins_with_legacy_fallback(self):
        self.assertIn("top_mm=db.Column(db.Integer,nullable=True)", SOURCE)
        self.assertIn("bottom_mm=db.Column(db.Integer,nullable=True)", SOURCE)
        self.assertIn("ALTER TABLE report_model ADD COLUMN IF NOT EXISTS top_mm INTEGER", SOURCE)
        self.assertIn("ALTER TABLE report_model ADD COLUMN IF NOT EXISTS bottom_mm INTEGER", SOURCE)
        self.assertIn("active_template=ReportModel.query.filter_by(clinic_id=clinic.id,stored=clinic.report_model).first()", SOURCE)
        self.assertIn("active_model.top_mm=u.report_top_mm", SOURCE)
        self.assertIn("active_model.bottom_mm=u.report_bottom_mm", SOURCE)

    def test_custom_pdf_uses_clinic_configured_margins(self):
        self.assertIn("top_margin_mm=max(20,min(120,int(configured_top or 72)))", SOURCE)
        self.assertIn("bottom_margin_mm=max(15,min(100,int(configured_bottom or 42)))", SOURCE)
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
