import ast
from pathlib import Path
import unittest
class TestCbctSpacing(unittest.TestCase):
 def test_spacing_and_bold(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('observation_style=ParagraphStyle("cbct_observation",parent=compact_body,fontName="Helvetica-Bold"',source)
  self.assertIn('Paragraph("Observa-se no volume adquirido:",observation_style)',source)
  self.assertIn('Paragraph(escape(technique_text),compact_body),Spacer(1,2*mm)',source)
  self.assertIn('spaceBefore=0,spaceAfter=0',source)
  self.assertIn('Paragraph("CONSIDERAÇÕES FINAIS"',source)
  self.assertIn('Demais estruturas e elementos não mencionados encontram-se dentro dos padrões de normalidade.',source)
  self.assertIn('Para maiores detalhes indica-se correr o volume.',source)
  self.assertIn('Este laudo não deve ser interpretado de modo conclusivo',source)
if __name__=="__main__": unittest.main()
