import ast
from pathlib import Path
import unittest

class FixedParagraphsTest(unittest.TestCase):
 def test_fixed_report_text(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('technique_text="Obtidas imagens por Tomografia',source)
  self.assertIn('disclaimer_text="A mensuração (em milímetros)',source)
  self.assertIn('Paragraph(escape(technique_text),compact_body)',source)
  self.assertIn('Paragraph("Observa-se no volume adquirido:",observation_style)',source)
  self.assertIn('Paragraph(escape(disclaimer_text),body)',source)
  self.assertIn('if cleaned in (technique_key,disclaimer_key):',source)

if __name__=="__main__": unittest.main()
