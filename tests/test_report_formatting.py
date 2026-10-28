"""Testes de formatação do PDF sem banco de dados nem pacientes reais."""
import ast
from html.parser import HTMLParser
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1].joinpath("app.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCS = {node.name: node for node in TREE.body if isinstance(node, ast.FunctionDef)}
SCOPE = {}
exec(compile(ast.Module(body=[FUNCS["clean_report_html"], FUNCS["rich_report_blocks"]], type_ignores=[]), "<report-parser>", "exec"), SCOPE)

class BalancedMarkup(HTMLParser):
    def __init__(self):
        super().__init__(); self.stack = []
    def handle_starttag(self, tag, attrs):
        if tag in ("font", "b", "i", "u"): self.stack.append(tag)
    def handle_endtag(self, tag):
        if tag in ("font", "b", "i", "u"):
            assert self.stack and self.stack.pop() == tag, "Tags PDF desbalanceadas"

class ReportFormattingTests(unittest.TestCase):
    def blocks(self, html, plain=""):
        blocks = SCOPE["rich_report_blocks"](html, plain)
        for markup, _ in blocks:
            parser = BalancedMarkup()
            parser.feed(markup)
            self.assertFalse(parser.stack, "Tag aberta no final do bloco")
        return blocks

    def test_paragraphs_are_separate(self):
        blocks = self.blocks("<p>Primeiro parágrafo.</p><p>Segundo parágrafo.</p>")
        self.assertEqual([m for m, _ in blocks if m != "&nbsp;"], ["Primeiro parágrafo.", "Segundo parágrafo."])

    def test_explicit_line_breaks_are_separate(self):
        blocks = self.blocks("<div>Linha um<br>Linha dois</div>")
        self.assertIn("Linha um", [m for m, _ in blocks])
        self.assertIn("Linha dois", [m for m, _ in blocks])

    def test_blank_lines_survive(self):
        blocks = self.blocks("<div>Antes<br><br>Depois</div>")
        self.assertIn("&nbsp;", [m for m, _ in blocks])

    def test_font_spanning_paragraph_boundary(self):
        blocks = self.blocks("<font face='arial'><div>Primeiro</div><div>Segundo</div></font>")
        self.assertTrue(any("Primeiro" in m for m, _ in blocks))
        self.assertTrue(any("Segundo" in m for m, _ in blocks))

    def test_raw_newlines_do_not_merge_paragraphs(self):
        blocks = self.blocks("<div>Um" + chr(10) + chr(10) + "Dois</div>")
        texts = [m for m, _ in blocks]
        self.assertTrue(any("Um" in m for m in texts))
        self.assertTrue(any("Dois" in m for m in texts))
        self.assertIn("&nbsp;", texts)

    def test_plain_text_fallback(self):
        blocks = self.blocks("", "Um" + chr(10) + chr(10) + "Dois")
        self.assertEqual([m for m, _ in blocks], ["Um", "&nbsp;", "Dois"])

if __name__ == "__main__":
    unittest.main()
