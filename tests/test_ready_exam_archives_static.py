import ast
from pathlib import Path
import unittest


class ReadyExamArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("app.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_server_accepts_archives(self):
        route = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "upload_ready_exam")
        text = ast.get_source_segment(self.source, route)
        for extension in (".jpg", ".jpeg", ".pdf", ".zip", ".rar"):
            self.assertIn(repr(extension), text)

    def test_form_offers_archives(self):
        self.assertIn('accept=\\".jpg,.jpeg,.pdf,.zip,.rar,', self.source)

    def test_archive_does_not_use_pdf_preview(self):
        self.assertIn("if f.name.lower().endswith('.pdf') else", self.source)
        self.assertIn("Pré-visualização indisponível para ZIP/RAR", self.source)


if __name__ == "__main__":
    unittest.main()
