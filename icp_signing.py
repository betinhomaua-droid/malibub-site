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
    output = io.BytesIO()
    signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(pdf_bytes)),
        signature_meta=signers.PdfSignatureMetadata(
            field_name="AssinaturaDigital",
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
