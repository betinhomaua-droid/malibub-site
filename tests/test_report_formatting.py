import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1].joinpath("app.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
NAMES = {"clean_report_html", "rich_report_blocks"}
FUNCTIONS = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in NAMES]
namespace = {}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), "report_helpers", "exec"), namespace)
blocks = namespace["rich_report_blocks"]


class ReportFormattingTests(unittest.TestCase):
    def test_html_paragraphs_remain_separate(self):
        result = blocks("<p>Primeira frase.</p><p>Segunda frase.</p>", "Primeira frase.\\nSegunda frase.")
        self.assertEqual([x[0] for x in result], ["Primeira frase.", "Segunda frase."])

    def test_plain_text_fallback_keeps_lines(self):
        result = blocks("", "Primeira frase.\\nSegunda frase.")
        self.assertEqual([x[0] for x in result], ["Primeira frase.", "Segunda frase."])

    def test_single_html_block_with_plain_newlines_recovers_paragraphs(self):
        result = blocks("<div>Primeira frase. Segunda frase.</div>", "Primeira frase.\\nSegunda frase.")
        self.assertEqual([x[0] for x in result], ["Primeira frase.", "Segunda frase."])

    def test_rich_text_is_not_discarded(self):
        result = blocks("<p><b>Achado:</b> normal.</p><p>Outra observação.</p>", "Achado: normal.\\nOutra observação.")
        self.assertIn("<b>Achado:</b>", result[0][0])
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
