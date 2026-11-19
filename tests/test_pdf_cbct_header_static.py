import ast
from pathlib import Path
import unittest

class PdfCbctHeaderTests(unittest.TestCase):
 def test_header_and_report_opening(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('Paragraph("TOMOGRAFIA VOLUMÉTRICA POR FEIXE CÔNICO"',source)
  self.assertIn('Paragraph("Observa-se no volume adquirido:"',source)
  self.assertIn('header_cell("Sexo",e.sex',source)
  self.assertIn('header_cell("Idade",age_text)',source)
  self.assertIn('header_cell("Data do exame",br_date(e.exam_date))',source)
  self.assertIn('header_cell("Dentista solicitante",e.dentist)',source)
  self.assertNotIn('Paragraph(escape(clinic.name or ""),ParagraphStyle("clinicbrand"',source)

if __name__=="__main__":
 unittest.main()
