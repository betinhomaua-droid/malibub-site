import ast
import unittest
from pathlib import Path

class FinanceMovementExamDetailsTest(unittest.TestCase):
 def test_columns_and_safe_exam_linkage(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('re.fullmatch(r"Laudo (\\d+)",x.description or "")',source)
  self.assertIn('linked_exams={e.protocol:e for e in Exam.query.filter(Exam.protocol.in_(linked_protocols)).all()}',source)
  self.assertIn('Protocolo / lançamento</div><div>Paciente</div><div>Exame</div><div>Prioridade</div><div>Status</div><div>Criado em</div><div>Valor</div><div>Ação',source)
  self.assertIn('finance-movement-row',source)
  self.assertIn('protocol=str(html_escape(e.protocol or ""))',source)
  self.assertIn('status=str(html_escape(e.status or "—"))',source)
  self.assertIn('patient=str(html_escape(e.patient or "—"))',source)
  self.assertIn('if e.status=="Liberado" else',source)
  self.assertIn('patient="—"; exam_type="—"; priority="—"',source)

if __name__=="__main__":
 unittest.main()
