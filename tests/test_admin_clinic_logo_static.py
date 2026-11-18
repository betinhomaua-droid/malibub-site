import ast
from pathlib import Path
import unittest


class AdminClinicLogoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("app.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_admin_logo_route_permissions_and_formats(self):
        fn = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "admin_clinic_logo")
        source = ast.get_source_segment(self.source, fn)
        self.assertIn('session.get("role")!="Radiologista"', source)
        self.assertIn('u.role!="Clinica"', source)
        self.assertIn('{".jpg",".jpeg",".png"}', source)
        self.assertIn("malware_scan(logo,name)", source)
        self.assertIn("store_upload(logo,stored,logo.mimetype)", source)

    def test_admin_edit_has_preview_and_upload_form(self):
        fn = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "admin_user_edit")
        source = ast.get_source_segment(self.source, fn)
        self.assertIn("Logomarca da clínica", source)
        self.assertIn("'/clinic-logo/'", source)
        self.assertIn("enctype='multipart/form-data'", source)
        self.assertIn("name='logo'", source)
        self.assertIn("Salvar logomarca", source)


if __name__ == "__main__":
    unittest.main()
