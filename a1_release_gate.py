"""Pure release decision for MALIBUB signed report rollout.

This is a gate for future integration into app.py. It does not change existing
clinical routes or authorize signers. In A1-required mode, a report may be
released only with a verified persisted artifact linked to its exam.
"""


class ReleaseBlocked(Exception):
    pass


def authorize_release(*, a1_required, exam_id, artifact=None):
    """Return release metadata or block; no implicit unsigned fallback.

    The caller must commit the artifact metadata and clinical status together.
    """
    if not isinstance(exam_id, int) or exam_id <= 0:
        raise ReleaseBlocked("Exame inválido.")
    if not a1_required:
        return {"mode": "legacy", "artifact": None}
    if not isinstance(artifact, dict):
        raise ReleaseBlocked("Assinatura digital obrigatória não concluída.")
    key = artifact.get("key")
    digest = artifact.get("sha256")
    size = artifact.get("size")
    if not isinstance(key, str) or not key.startswith(f"signed-reports/{exam_id}/"):
        raise ReleaseBlocked("Documento assinado não corresponde ao exame.")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ReleaseBlocked("Integridade do documento não comprovada.")
    if not isinstance(size, int) or size <= 0:
        raise ReleaseBlocked("Documento assinado vazio.")
    return {"mode": "signed", "artifact": dict(artifact)}
