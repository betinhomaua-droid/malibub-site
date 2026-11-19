import ast
import unittest
from pathlib import Path

class ApprovedLayoutTests(unittest.TestCase):
 def test_footer_and_title(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('cv.drawCentredString(width/2,18*mm,"MALIBUB Imaginologia  |  www.malibub.com.br")',source)
  self.assertIn('from reportlab.platypus import HRFlowable',source)
  self.assertIn('HRFlowable(width="100%",thickness=0.7,color=gold',source)
  self.assertIn('TOMOGRAFIA VOLUMÉTRICA POR FEIXE CÔNICO',source)

if __name__=="__main__":
 unittest.main()
