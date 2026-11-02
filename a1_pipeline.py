"""Opt-in A1 pipeline; not wired to clinical release until audited.

Only the authorized report-approval route may call this function. The caller
must persist returned storage reference and digest in the database before
marking the report released. Never expose the PFX or password to clients.
"""
import os
import hashlib
from a1_signing import (
    SignatureConfigurationError, SignatureValidationError,
    sign_pdf_pades, verify_embedded_signature, validate_signer_trust,
)
from a1_secrets import load_a1_credentials
from a1_storage import persist_signed_pdf


def verify_pinned_signer_certificate(pfx, password):
    """Require an explicitly pinned signer certificate before any signature operation."""
    expected = os.getenv("MALIBUB_A1_SIGNER_CERT_SHA256", "").strip().lower().replace(":", "")
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise SignatureConfigurationError("Impressão digital do certificado signatário não configurada.")
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
        _, certificate, _ = pkcs12.load_key_and_certificates(pfx, password.encode("utf-8"))
        if certificate is None:
            raise ValueError("Certificado ausente.")
        actual = hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()
        if actual != expected:
            raise SignatureConfigurationError("Certificado A1 diferente do signatário autorizado.")
    except SignatureConfigurationError:
        raise
    except Exception:
        raise SignatureConfigurationError("Identidade do certificado A1 não pôde ser confirmada.") from None


def prepare_signed_report(*, pdf_bytes, exam_id, storage_client, bucket,
                          validation_context, authorized=False,
                          credentials_loader=load_a1_credentials):
    """Prepare an immutable signed artifact without changing exam status."""
    if os.getenv("MALIBUB_A1_SIGNING_ENABLED", "").lower() != "true":
        raise SignatureConfigurationError("Assinatura A1 desativada.")
    if authorized is not True:
        raise PermissionError("Radiologista não autorizada a assinar este laudo.")
    if not isinstance(exam_id, int) or isinstance(exam_id, bool) or exam_id <= 0:
        raise ValueError("Identificação do exame inválida.")
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes.startswith(b"%PDF-"):
        raise SignatureValidationError("Documento PDF de origem inválido.")
    if validation_context is None:
        raise SignatureConfigurationError("Confiança ICP-Brasil não configurada.")
    if storage_client is None or not bucket:
        raise SignatureConfigurationError("Armazenamento privado indisponível.")
    pfx, password = credentials_loader()
    verify_pinned_signer_certificate(pfx, password)
    signed_pdf = sign_pdf_pades(pdf_bytes, pfx, password)
    if not verify_embedded_signature(signed_pdf):
        raise SignatureValidationError("Integridade da assinatura não confirmada.")
    if not validate_signer_trust(signed_pdf, validation_context):
        raise SignatureValidationError("Certificado sem confiança validada.")
    return persist_signed_pdf(storage_client, bucket, exam_id, signed_pdf)
