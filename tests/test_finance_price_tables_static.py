import ast
from pathlib import Path
import unittest

class FinancePriceTablesTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.source=Path("app.py").read_text(encoding="utf-8")
  cls.tree=ast.parse(cls.source)
 def method(self,name):
  return ast.get_source_segment(self.source,next(n for n in self.tree.body if isinstance(n,ast.FunctionDef) and n.name==name))
 def test_price_presets_model(self):
  self.assertIn("class PricePreset(db.Model):",self.source)
  self.assertIn('uq_price_preset_exam',self.source)
 def test_finance_price_table_ui(self):
  s=self.method("finance_price_tables")
  for value in ('STANDARD_PRICES_2026','PricePreset.query','Tabelas personalizadas','session.get("role")!="Radiologista"'):
   self.assertIn(value,s)
 def test_application_to_clinic(self):
  s=self.method("finance_apply_preset")
  for value in ('clinic.role!="Clinica"','ClinicPrice.query','existing.amount=p.amount','db.session.commit()'):
   self.assertIn(value,s)
 def test_finance_navigation(self):
  self.assertIn('href="/finance/tabelas"',self.method("finance"))

if __name__=="__main__":
 unittest.main()
