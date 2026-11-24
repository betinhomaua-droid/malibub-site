import ast
import unittest
from pathlib import Path

class FinanceReportPreviewTests(unittest.TestCase):
 def test_preview_and_download(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('name="preview" value="1" formtarget="_blank">Visualizar relatório',source)
  self.assertIn('name="preview" value="0">Baixar relatório PDF',source)
  self.assertIn('as_attachment=request.args.get("preview")!="1"',source)
  self.assertIn('if session.get("role")!="Radiologista": return redirect("/")',source)

if __name__=="__main__":
 unittest.main()
