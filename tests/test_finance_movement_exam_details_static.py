import ast
import unittest
from pathlib import Path

class FinanceMovementExamDetailsTest(unittest.TestCase):
 def test_columns_and_safe_exam_linkage(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('re.fullmatch(r"Laudo (\\d+)",x.description or "")',source)
  self.assertIn('linked_exams={e.protocol:e for e in Exam.query.filter(Exam.protocol.in_(linked_protocols)).all()}',source)
  self.assertIn('Protocolo / lançamento</th><th>Paciente</th><th>Exame</th><th>Prioridade</th><th>Status</th><th>Criado em</th><th>Valor</th><th>Ação',source)
  self.assertIn('patient=html_escape(e.patient or "—")',source)
  self.assertIn('if e.status=="Liberado" else',source)
  self.assertIn('patient="—"; exam_type="—"; priority="—"',source)

if __name__=="__main__":
 unittest.main()
