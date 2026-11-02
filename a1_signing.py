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
    from pyhanko.stamp import TextStampStyle
    try:
        from cryptography.hazmat.primitives.serialization import (
            pkcs12, Encoding, PrivateFormat, NoEncryption
        )
        from asn1crypto import x509 as asn1_x509, keys as asn1_keys
        from pyhanko_certvalidator.registry import SimpleCertificateStore
        private_key, cert, chain = pkcs12.load_key_and_certificates(
            pfx_bytes, password.encode("utf-8")
        )
        if private_key is None or cert is None:
            raise SignatureConfigurationError("O arquivo A1 não contém chave e certificado.")
        store = SimpleCertificateStore()
        for issuer_cert in chain or []:
            store.register(asn1_x509.Certificate.load(issuer_cert.public_bytes(Encoding.DER)))
        signer = signers.SimpleSigner(
            signing_cert=asn1_x509.Certificate.load(cert.public_bytes(Encoding.DER)),
            signing_key=asn1_keys.PrivateKeyInfo.load(private_key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )),
            cert_registry=store,
        )
        meta = signers.PdfSignatureMetadata(
            field_name="AssinaturaDigital",
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )
        pdf_signer = signers.PdfSigner(
            signature_meta=meta,
            signer=signer,
            new_field_spec=SigFieldSpec(
                sig_field_name="AssinaturaDigital",
                on_page=-1,
                box=(42, 32, 290, 100),
            ),
            stamp_style=TextStampStyle(
                stamp_text="Assinado digitalmente por %(signer)s\nData/hora: %(ts)s",
            ),
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
    """Basic structural verification only; not an ICP-Brasil trust verdict.

    Never use this boolean alone to authorize release of a clinical report.
    """
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


def validate_signer_trust(pdf_bytes: bytes, validation_context) -> bool:
    """Check signature integrity AND a caller-provided trusted validation context.

    The production caller must supply an explicitly configured ICP-Brasil trust
    context, including appropriate revocation checking. No default system trust
    or self-signed certificate is accepted implicitly by this function.
    """
    if validation_context is None:
        raise SignatureConfigurationError("Contexto de confiança ICP-Brasil obrigatório.")
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    try:
        signatures = list(PdfFileReader(BytesIO(pdf_bytes)).embedded_signatures)
        if len(signatures) != 1:
            return False
        status = validate_pdf_signature(signatures[0], signer_validation_context=validation_context)
        return bool(status.intact and status.valid and status.trusted)
    except Exception:
        return False
