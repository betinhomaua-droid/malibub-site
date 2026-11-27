import ast
import unittest
from pathlib import Path

class ClinicImagingSoftwareTests(unittest.TestCase):
 def test_registration_and_exam_selection(self):
  source=Path("app.py").read_text(encoding="utf-8")
  ast.parse(source)
  self.assertIn('IMAGING_SOFTWARE=("Imaging Studio","I Dixel","Ondemand","Romexis")',source)
  self.assertIn('request.form.getlist("imaging_software")',source)
  self.assertIn('software_select=',source)
  self.assertIn('validate_exam_software(software,clinic)',source)
  self.assertIn('e=Exam(imaging_software=software,protocol=',source)
  self.assertIn('"exam_type","imaging_software","priority"',source)
  self.assertIn('ADD COLUMN IF NOT EXISTS imaging_software',source)
  self.assertIn('ADD COLUMN imaging_software VARCHAR',source)

if __name__=="__main__":
 unittest.main()
