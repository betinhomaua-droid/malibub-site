"""Immutable signed PDF storage adapter for private S3-compatible object stores.

Does not integrate with clinical release; caller must authorize and transact.
"""
import hashlib
import io
import uuid
from a1_signing import SignatureValidationError


def persist_signed_pdf(client, bucket: str, exam_id: int, signed_pdf: bytes) -> dict:
    """Write a new, unpredictable immutable-version key and verify its bytes.

    Never overwrite an existing report key. The caller must retain the returned
    key and SHA-256 in a durable database transaction before clinical release.
    """
    if not bucket or not isinstance(exam_id, int) or isinstance(exam_id, bool) or exam_id <= 0:
        raise ValueError("Destino do laudo inválido.")
    if not isinstance(signed_pdf, bytes) or not signed_pdf.startswith(b"%PDF-"):
        raise SignatureValidationError("PDF assinado inválido.")
    digest = hashlib.sha256(signed_pdf).hexdigest()
    key = f"signed-reports/{exam_id}/{uuid.uuid4().hex}.pdf"
    try:
        client.put_object(
            Bucket=bucket, Key=key, Body=io.BytesIO(signed_pdf),
            ContentType="application/pdf",
            Metadata={"sha256": digest},
            IfNoneMatch="*",
        )
        result = client.get_object(Bucket=bucket, Key=key)
        stored = result["Body"].read()
        if stored != signed_pdf:
            raise SignatureValidationError("Falha na conferência do PDF armazenado.")
    except Exception as exc:
        raise SignatureValidationError("Não foi possível preservar o PDF assinado.") from None
    return {"key": key, "sha256": digest, "size": len(signed_pdf)}
