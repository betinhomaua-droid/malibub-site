"""Offline PDF overlay geometry smoke test using fictitious data only."""
import io
import unittest

from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


class TemplateOverlayTests(unittest.TestCase):
    def test_template_preserved_and_overlay_within_configured_area(self):
        width, height = A4
        source = io.BytesIO()
        cv = canvas.Canvas(source, pagesize=A4)
        cv.drawString(22 * mm, height - 30 * mm, "TMJ - TESTE FICTICIO")
        cv.drawString(22 * mm, 25 * mm, "RODAPE FIXO")
        cv.save()
        source.seek(0)
        base = PdfReader(source)
        self.assertEqual(len(base.pages), 1)

        top_mm, bottom_mm = 102, 42
        overlay = io.BytesIO()
        cv = canvas.Canvas(overlay, pagesize=A4)
        y = height - top_mm * mm
        self.assertGreater(y, bottom_mm * mm)
        cv.drawString(22 * mm, y, "Descricao do exame - exemplo ficticio")
        cv.save()
        overlay.seek(0)
        page = base.pages[0]
        page.merge_page(PdfReader(overlay).pages[0])
        writer = PdfWriter()
        writer.add_page(page)
        result = io.BytesIO()
        writer.write(result)
        result.seek(0)
        output = PdfReader(result)
        self.assertEqual(len(output.pages), 1)
        text = output.pages[0].extract_text()
        self.assertIn("TMJ - TESTE FICTICIO", text)
        self.assertIn("RODAPE FIXO", text)
        self.assertIn("Descricao do exame - exemplo ficticio", text)


if __name__ == "__main__":
    unittest.main()
