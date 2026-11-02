"""Pure revision/version rules for digitally signed MALIBUB reports.

This module defines the state transitions without mutating clinical records.
The application must persist returned metadata atomically with its audit log.
"""
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SignedReportVersion:
    number: int
    storage_key: str
    sha256: str
    signed_at: datetime
    supersedes: int | None = None


def new_signed_version(*, previous, storage_key, sha256, signed_at=None):
    if not storage_key or not sha256 or len(sha256) != 64:
        raise ValueError("Referência de PDF assinado inválida.")
    if previous is not None and not isinstance(previous, SignedReportVersion):
        raise TypeError("Versão anterior inválida.")
    return SignedReportVersion(
        number=1 if previous is None else previous.number + 1,
        storage_key=storage_key,
        sha256=sha256,
        signed_at=signed_at or datetime.now(timezone.utc),
        supersedes=None if previous is None else previous.number,
    )


def resolve_revision(*, previous, decision, justification, replacement=None):
    """Return the current version and audit outcome; never mutate previous.

    decision: 'maintain' or 'replace'. A replacement must be newly signed
    and strictly increment the previous version number.
    """
    if not isinstance(previous, SignedReportVersion):
        raise ValueError("Não há laudo assinado anterior para revisar.")
    if not justification or not justification.strip():
        raise ValueError("Justificativa de revisão obrigatória.")
    if decision == "maintain":
        if replacement is not None:
            raise ValueError("Manutenção não aceita novo PDF.")
        return {"current": previous, "outcome": "mantido", "reason": justification.strip()}
    if decision == "replace":
        if not isinstance(replacement, SignedReportVersion):
            raise ValueError("Nova versão assinada obrigatória.")
        if replacement.number != previous.number + 1 or replacement.supersedes != previous.number:
            raise ValueError("Sequência de versões inválida.")
        if replacement.storage_key == previous.storage_key:
            raise ValueError("Não é permitido sobrescrever o PDF anterior.")
        if replacement.sha256 == previous.sha256:
            raise ValueError("Revisão sem alteração documental.")
        return {"current": replacement, "outcome": "substituido", "reason": justification.strip()}
    raise ValueError("Decisão de revisão inválida.")
