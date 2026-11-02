"""Assinatura criptográfica de PDFs; NÃO substitui validação de política ICP-Brasil.

Não registra chaves, senhas, certificados ou dados do paciente em logs.
A integração deve ocorrer DEPOIS da composição final do PDF.
"""
import io
import os
from pathlib import Path


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
    from pyhanko.sign.fields import SigSeedSubFilter

    path = os.environ.get("MALIBUB_A1_PFX_PATH", "")
    password = os.environ.get("MALIBUB_A1_PFX_PASSWORD")
    if not path or not Path(path).is_file() or password is None:
        raise SigningConfigurationError("Certificado A1 não configurado no servidor")
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("Documento de entrada não é um PDF")
    signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=path, passphrase=password.encode("utf-8")
    )
    if signer is None:
        raise SigningConfigurationError("Não foi possível carregar o certificado A1")
    output = io.BytesIO()
    signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(pdf_bytes)),
        signature_meta=signers.PdfSignatureMetadata(
            field_name="AssinaturaDigital",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        ),
        signer=signer,
        output=output,
    )
    signed = output.getvalue()
    if not signed.startswith(b"%PDF-") or b"/ByteRange" not in signed:
        raise RuntimeError("Assinatura digital não foi incorporada ao PDF")
    return signed
