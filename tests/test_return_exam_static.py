import ast
from pathlib import Path
import unittest

class ReturnWorkflowTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.source=Path("app.py").read_text(encoding="utf-8")
  cls.tree=ast.parse(cls.source)
 def method(self,name):
  return ast.get_source_segment(self.source,next(n for n in self.tree.body if isinstance(n,ast.FunctionDef) and n.name==name))
 def test_return_permissions_and_reason(self):
  s=self.method("return_exam_to_clinic")
  for value in ('session.get("role")!="Radiologista"','return_reason','10<=len(reason)<=2000','ExamReturn(','Devolvido para correção'):
   self.assertIn(value,s)
 def test_clinic_can_correct_same_exam(self):
  s=self.method("correct_returned_exam")
  for value in ('session.get("role")!="Clinica"','clinic_id=session["uid"]','validate_zip_upload(file)','entrada_anterior','requisicao_anterior','Aguardando laudo','corrected_at=datetime.utcnow()'):
   self.assertIn(value,s)
 def test_ui_and_release_guard(self):
  self.assertIn('{return_form}</section>',self.source)
  self.assertIn('Corrigir e reenviar',self.method("dashboard"))
  self.assertIn('if e.status in {"Liberado","Devolvido para correção"}:',self.method("report"))

if __name__=="__main__":
 unittest.main()
