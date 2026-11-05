"""Assinatura criptográfica de PDFs; NÃO substitui validação de política ICP-Brasil.

Não registra chaves, senhas, certificados ou dados do paciente em logs.
A integração deve ocorrer DEPOIS da composição final do PDF.
"""
import io
import os
import base64
import binascii
import tempfile
from pathlib import Path


def _add_visible_signature_panel(pdf_bytes: bytes, signer_name: str) -> bytes:
    """Adds a visual indication before the cryptographic signature is applied.

    QR opens the official ITI verifier; it does NOT verify this specific PDF
    automatically. The original PDF must be uploaded to that service.
    """
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.graphics.barcode import qr
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics import renderPDF

    reader = PdfReader(io.BytesIO(pdf_bytes))
    if not reader.pages:
        raise ValueError("PDF sem paginas")
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    page = writer.pages[-1]
    box = page.mediabox
    width = float(box.width)
    height = float(box.height)
    # Position above the usual MALIBUB footer, to the left of the handwritten signature.
    w, h = min(205, width - 70), 55
    x, y = (width - w) / 2, 82
    overlay = io.BytesIO()
    c = canvas.Canvas(overlay, pagesize=(width, height))
    c.setStrokeColorRGB(0.48, 0.65, 0.73)
    c.setFillColorRGB(0.985, 0.993, 1.0)
    c.roundRect(x, y, w, h, 5, stroke=1, fill=1)
    c.setFillColorRGB(0.05, 0.27, 0.43)
    c.setFont("Helvetica-Bold", 7.2)
    c.drawString(x + 7, y + h - 13, "ASSINATURA DIGITAL ICP-BRASIL")
    c.setFont("Helvetica-Bold", 6.8)
    safe_name = signer_name.encode("latin-1", "replace").decode("latin-1")[:29]
    c.drawString(x + 7, y + h - 26, safe_name)
    c.setFont("Helvetica", 5.7)
    c.drawString(x + 7, y + h - 36, "Certificado A1 - assinatura PAdES")
    c.drawString(x + 7, y + 7, "Verifique o PDF original no portal ITI")
    code = qr.QrCodeWidget("https://validar.iti.gov.br/")
    bounds = code.getBounds()
    qrw, qrh = bounds[2] - bounds[0], bounds[3] - bounds[1]
    drawing = Drawing(39, 39, transform=[39 / qrw, 0, 0, 39 / qrh, 0, 0])
    drawing.add(code)
    renderPDF.draw(drawing, c, x + w - 45, y + 8)
    c.save()
    overlay.seek(0)
    page.merge_page(PdfReader(overlay).pages[0])
    result = io.BytesIO()
    writer.write(result)
    return result.getvalue()


class SigningConfigurationError(RuntimeError):
    pass


def sign_pdf_bytes(pdf_bytes: bytes) -> bytes:
    """Assina um PDF com PFX/P12 e falha sem produzir um PDF 'assinado' falso.

    Configuração: MALIBUB_A1_PFX_PATH e MALIBUB_A1_PFX_PASSWORD.
    O resultado precisa passar pela validação de política ICP-Brasil
    antes de ser considerado apto para uso.
    """
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigSeedSubFilter, MDPPerm
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.keys import load_certs_from_pemder
    from pyhanko_certvalidator import ValidationContext

    path = os.environ.get("MALIBUB_A1_PFX_PATH", "")
    password = os.environ.get("MALIBUB_A1_PFX_PASSWORD")
    if not path or not Path(path).is_file() or password is None:
        raise SigningConfigurationError("Certificado A1 não configurado no servidor")
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("Documento de entrada não é um PDF")
    # Arquivos .b64 do Render sao decodificados apenas em memoria.
    if Path(path).suffix.lower() == ".b64":
        try:
            encoded = Path(path).read_bytes()
            pkcs12_data = base64.b64decode(b"".join(encoded.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SigningConfigurationError("Arquivo A1 Base64 invalido") from exc
        if not pkcs12_data:
            raise SigningConfigurationError("Arquivo A1 vazio")
        # pyHanko exige caminho de arquivo; arquivo temporario restrito e removido.
        with tempfile.TemporaryDirectory(prefix="malibub-a1-") as tmp:
            private_path = Path(tmp) / "certificate.pfx"
            private_path.write_bytes(pkcs12_data)
            private_path.chmod(0o600)
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file=str(private_path), passphrase=password.encode("utf-8")
            )
    else:
        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=path, passphrase=password.encode("utf-8")
        )
    if signer is None:
        raise SigningConfigurationError("Não foi possível carregar o certificado A1")
    roots_path = os.environ.get("MALIBUB_ICP_TRUST_ROOTS_PATH")
    if not roots_path or not Path(roots_path).is_file():
        raise SigningConfigurationError("Raízes ICP-Brasil confiáveis não configuradas")
    context = ValidationContext(
        trust_roots=list(load_certs_from_pemder([roots_path])),
        allow_fetching=True,
        revocation_mode="require",
    )
    pdf_bytes = _add_visible_signature_panel(pdf_bytes, signer.signing_cert.subject.native.get("common_name", "Dra. Marina Bub"))
    output = io.BytesIO()
    signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(pdf_bytes)),
        signature_meta=signers.PdfSignatureMetadata(
            field_name="AssinaturaDigital",
            certify=True,
            docmdp_permissions=MDPPerm.NO_CHANGES,
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
            validation_context=context,
            embed_validation_info=True,
        ),
        signer=signer,
        output=output,
    )
    signed = output.getvalue()
    if not signed.startswith(b"%PDF-") or b"/ByteRange" not in signed:
        raise RuntimeError("Assinatura digital não foi incorporada ao PDF")
    reader = PdfFileReader(io.BytesIO(signed))
    signatures = reader.embedded_signatures
    if len(signatures) != 1:
        raise RuntimeError("Quantidade inesperada de assinaturas no PDF")
    status = validate_pdf_signature(signatures[0], signer_validation_context=context)
    if not (status.intact and status.valid and status.trusted):
        raise RuntimeError("Assinatura inválida ou cadeia não confiável")
    return signed
