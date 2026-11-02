"""Read back an immutable signed PDF version by its recorded digest.

This helper must only be called after the route has authorized the requesting
clinic or radiologist for the specific exam. Never accept a key from the URL.
"""
import hashlib
from a1_signing import SignatureValidationError


def read_signed_report(client, bucket: str, *, key: str, sha256: str, exam_id: int) -> bytes:
    if not bucket or not isinstance(exam_id, int) or exam_id <= 0:
        raise SignatureValidationError("Identificação do laudo inválida.")
    if not isinstance(key, str) or not key.startswith(f"signed-reports/{exam_id}/"):
        raise SignatureValidationError("Referência do laudo assinado inválida.")
    if not key.endswith(".pdf") or ".." in key or "/" in key[len(f"signed-reports/{exam_id}/"):]:
        raise SignatureValidationError("Referência do laudo assinado inválida.")
    if not isinstance(sha256, str) or len(sha256) != 64:
        raise SignatureValidationError("Digest do laudo assinado inválido.")
    try:
        data = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:
        raise SignatureValidationError("PDF assinado indisponível.") from None
    if not data.startswith(b"%PDF-") or hashlib.sha256(data).hexdigest() != sha256:
        raise SignatureValidationError("Integridade do PDF assinado comprometida.")
    return data
