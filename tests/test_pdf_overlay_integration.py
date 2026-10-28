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

    def test_long_report_spills_to_continuation_without_losing_lines(self):
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import getSampleStyleSheet

        width, height = A4
        lines = [f"Achado ficticio numero {n:03d}." for n in range(1, 101)]
        paragraphs = [Paragraph(line, getSampleStyleSheet()["BodyText"]) for line in lines]
        writer = PdfWriter()
        page_count = 0
        cursor = 0
        while cursor < len(paragraphs):
            buf = io.BytesIO()
            cv = canvas.Canvas(buf, pagesize=A4)
            y = height - (102 if page_count == 0 else 35) * mm
            floor = (42 if page_count == 0 else 66) * mm
            start = cursor
            while cursor < len(paragraphs):
                p = paragraphs[cursor]
                _, h = p.wrap(width - 44 * mm, height)
                if y - h - 2 * mm < floor:
                    break
                y -= h
                p.drawOn(cv, 22 * mm, y)
                y -= 2 * mm
                cursor += 1
            self.assertGreater(cursor, start, "A continuation page must fit at least one paragraph")
            cv.save()
            buf.seek(0)
            writer.add_page(PdfReader(buf).pages[0])
            page_count += 1
            self.assertLess(page_count, 20, "Unexpected PDF pagination loop")

        result = io.BytesIO()
        writer.write(result)
        result.seek(0)
        pdf = PdfReader(result)
        self.assertGreater(len(pdf.pages), 1)
        combined = "\\n".join(p.extract_text() for p in pdf.pages)
        for line in lines:
            self.assertEqual(combined.count(line), 1, line)

    def test_oversized_rich_paragraph_splits_and_preserves_text(self):
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import ParagraphStyle

        width, height = A4
        words = [f"Marcador{n:03d}" for n in range(1, 241)]
        rich = "<b>" + " ".join(words[:120]) + "</b> " + " ".join(words[120:])
        style = ParagraphStyle("large_report", fontName="Helvetica", fontSize=12, leading=17)
        pending = [Paragraph(rich, style)]
        writer = PdfWriter()
        page_count = 0
        while pending:
            page = io.BytesIO()
            cv = canvas.Canvas(page, pagesize=A4)
            y = height - 45 * mm
            floor = 95 * mm
            progress = False
            while pending:
                paragraph = pending[0]
                _, h = paragraph.wrap(width - 44 * mm, 700 * mm)
                available = y - floor - 2 * mm
                if h > available:
                    pieces = paragraph.split(width - 44 * mm, available)
                    if not pieces:
                        break
                    part = pieces[0]
                    _, part_height = part.wrap(width - 44 * mm, available)
                    y -= part_height
                    part.drawOn(cv, 22 * mm, y)
                    pending = pieces[1:] + pending[1:]
                else:
                    y -= h
                    paragraph.drawOn(cv, 22 * mm, y)
                    pending.pop(0)
                y -= 2 * mm
                progress = True
            self.assertTrue(progress, "Paragraph could not fit on a new page")
            cv.save()
            page.seek(0)
            writer.add_page(PdfReader(page).pages[0])
            page_count += 1
            self.assertLess(page_count, 20)

        output = io.BytesIO()
        writer.write(output)
        output.seek(0)
        pages = PdfReader(output).pages
        self.assertGreater(len(pages), 1)
        combined = " ".join(p.extract_text() for p in pages)
        for word in words:
            self.assertEqual(combined.count(word), 1, word)


if __name__ == "__main__":
    unittest.main()
