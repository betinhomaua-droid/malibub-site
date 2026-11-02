"""PAdES signing foundation. No automatic certificate ingestion or production activation.

Secrets must be supplied by an authorized server-side secret provider. Never log
PKCS#12 bytes or passwords. Signed output must be stored immutably and served
verbatim; do not regenerate it on download.
"""
from io import BytesIO


class SignatureConfigurationError(RuntimeError):
    pass


class SignatureValidationError(RuntimeError):
    pass


def sign_pdf_pades(pdf_bytes: bytes, pfx_bytes: bytes, password: str) -> bytes:
    """Sign an already-finalized PDF with an A1 PKCS#12 using pyHanko.

    The caller is responsible for authorization, protected secret retrieval,
    audit logging (without secrets), durable storage, and release transaction.
    """
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("Documento de entrada não é PDF.")
    if not pfx_bytes or not password:
        raise SignatureConfigurationError("Certificado A1 ou senha indisponível.")
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    try:
        signer = signers.SimpleSigner.load_pkcs12(
            BytesIO(pfx_bytes), passphrase=password.encode("utf-8")
        )
        if signer is None:
            raise SignatureConfigurationError("Não foi possível carregar o certificado A1.")
        meta = signers.PdfSignatureMetadata(
            field_name="AssinaturaDigital",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )
        pdf_signer = signers.PdfSigner(
            signature_meta=meta,
            signer=signer,
            new_field_spec=SigFieldSpec(sig_field_name="AssinaturaDigital"),
        )
        out = BytesIO()
        pdf_signer.sign_pdf(IncrementalPdfFileWriter(BytesIO(pdf_bytes)), output=out)
        signed = out.getvalue()
        if not signed.startswith(b"%PDF-") or signed == pdf_bytes:
            raise SignatureValidationError("O PDF não recebeu assinatura.")
        return signed
    except (SignatureConfigurationError, SignatureValidationError):
        raise
    except Exception as exc:
        raise SignatureValidationError("Falha ao assinar o PDF; documento não liberado.") from exc


def verify_embedded_signature(pdf_bytes: bytes) -> bool:
    """Basic structural verification, not an ICP-Brasil trust/revocation verdict."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    try:
        reader = PdfFileReader(BytesIO(pdf_bytes))
        fields = list(reader.embedded_signatures)
        if len(fields) != 1:
            return False
        status = validate_pdf_signature(fields[0])
        return bool(status.intact and status.valid)
    except Exception:
        return False
