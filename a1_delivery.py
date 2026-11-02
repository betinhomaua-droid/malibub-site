"""Read back an immutable signed PDF version by its recorded digest.

This helper must only be called after the route has authorized the requesting
clinic or radiologist for the specific exam. Never accept a key from the URL.
"""
import hashlib
from a1_signing import SignatureValidationError


def read_signed_report(client, bucket: str, *, key: str, sha256: str, exam_id: int, expected_size: int | None = None) -> bytes:
    if not bucket or not isinstance(exam_id, int) or isinstance(exam_id, bool) or exam_id <= 0:
        raise SignatureValidationError("Identificação do laudo inválida.")
    if not isinstance(key, str) or not key.startswith(f"signed-reports/{exam_id}/"):
        raise SignatureValidationError("Referência do laudo assinado inválida.")
    if not key.endswith(".pdf") or ".." in key or "/" in key[len(f"signed-reports/{exam_id}/"):]:
        raise SignatureValidationError("Referência do laudo assinado inválida.")
    if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise SignatureValidationError("Digest do laudo assinado inválido.")
    if expected_size is not None and (not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0):
        raise SignatureValidationError("Tamanho registrado do laudo inválido.")
    try:
        data = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:
        raise SignatureValidationError("PDF assinado indisponível.") from None
    if (not data.startswith(b"%PDF-") or (expected_size is not None and len(data) != expected_size)
            or hashlib.sha256(data).hexdigest() != sha256):
        raise SignatureValidationError("Integridade do PDF assinado comprometida.")
    return data
