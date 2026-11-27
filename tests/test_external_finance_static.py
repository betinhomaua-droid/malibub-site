import ast
import unittest
from pathlib import Path

class ExternalFinanceTests(unittest.TestCase):
 def test_external_finance_flow(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  for required in (
   "class ExternalExam(db.Model):",
   'finance_id=db.Column(db.Integer,db.ForeignKey("finance.id"),unique=True,nullable=False)',
   '@app.route("/finance/exames-externos",methods=["GET","POST"])',
   "db.session.add(ExternalExam(",
   "external_by_finance=",
   "externals=ExternalExam.query.filter(",
   'external_total=sum(',
   'data.append([x.service_date.strftime("%d/%m/%Y")',
   "Exames externos devem ser excluídos pela área Exames externos.",
  ):
   self.assertIn(required,source)

if __name__=="__main__":
 unittest.main()
