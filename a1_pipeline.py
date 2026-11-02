"""Opt-in A1 pipeline; not wired to clinical release until audited.

Only the authorized report-approval route may call this function. The caller
must persist returned storage reference and digest in the database before
marking the report released. Never expose the PFX or password to clients.
"""
import os
from a1_signing import (
    SignatureConfigurationError, SignatureValidationError,
    sign_pdf_pades, verify_embedded_signature, validate_signer_trust,
)
from a1_secrets import load_a1_credentials
from a1_storage import persist_signed_pdf


def prepare_signed_report(*, pdf_bytes, exam_id, storage_client, bucket,
                          validation_context, authorized=False,
                          credentials_loader=load_a1_credentials):
    """Prepare an immutable signed artifact without changing exam status."""
    if os.getenv("MALIBUB_A1_SIGNING_ENABLED", "").lower() != "true":
        raise SignatureConfigurationError("Assinatura A1 desativada.")
    if not authorized:
        raise PermissionError("Radiologista não autorizada a assinar este laudo.")
    if validation_context is None:
        raise SignatureConfigurationError("Confiança ICP-Brasil não configurada.")
    if storage_client is None or not bucket:
        raise SignatureConfigurationError("Armazenamento privado indisponível.")
    pfx, password = credentials_loader()
    signed_pdf = sign_pdf_pades(pdf_bytes, pfx, password)
    if not verify_embedded_signature(signed_pdf):
        raise SignatureValidationError("Integridade da assinatura não confirmada.")
    if not validate_signer_trust(signed_pdf, validation_context):
        raise SignatureValidationError("Certificado sem confiança validada.")
    return persist_signed_pdf(storage_client, bucket, exam_id, signed_pdf)
