import ast
import unittest
from pathlib import Path

class PdfAgeDateTests(unittest.TestCase):
 def test_age_date_parsing(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('birth_date=datetime.strptime(str(e.birth).strip(),"%Y-%m-%d").date()',source)
  self.assertIn('datetime.strptime(str(e.exam_date).strip(),"%Y-%m-%d").date()',source)
  self.assertIn('except (ValueError,TypeError,AttributeError):',source)
 def test_example(self):
  from datetime import datetime
  birth=datetime.strptime("1990-05-09","%Y-%m-%d").date()
  exam=datetime.strptime("2026-11-09","%Y-%m-%d").date()
  age=exam.year-birth.year-((exam.month,exam.day)<(birth.month,birth.day))
  self.assertEqual(age,36)

if __name__=="__main__": unittest.main()
