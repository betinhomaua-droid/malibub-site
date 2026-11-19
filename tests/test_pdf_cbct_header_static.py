import ast
from pathlib import Path
import unittest

class PdfCbctHeaderTests(unittest.TestCase):
 def test_header_and_report_opening(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('Paragraph("TOMOGRAFIA VOLUMÉTRICA POR FEIXE CÔNICO"',source)
  self.assertIn('Paragraph("Observa-se no volume adquirido:"',source)
  self.assertIn('header_label("Sexo"),header_value(e.sex',source)
  self.assertIn('header_label("Idade"),header_value(age_text)',source)
  self.assertIn('header_label("Data do exame"),header_value(br_date(e.exam_date))',source)
  self.assertIn('header_label("Dentista solicitante"),header_value(e.dentist)',source)
  self.assertIn('("BACKGROUND",(0,0),(0,-1),colors.HexColor("#DCEFFA"))',source)
  self.assertIn('("BACKGROUND",(1,0),(1,-1),colors.white)',source)
  self.assertIn('("GRID",(0,0),(-1,-1),.45,colors.HexColor("#A5C8DE"))',source)
  self.assertNotIn('Paragraph(escape(clinic.name or ""),ParagraphStyle("clinicbrand"',source)

if __name__=="__main__":
 unittest.main()
